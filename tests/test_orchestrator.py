"""Tests for the orchestrator, plus the CLI entry point."""

from __future__ import annotations

import base64
import json
import socket
import time

import pytest

from hyperion import __main__ as cli
from hyperion import orchestrator, truth_gate
from hyperion.zero_sni import TrustAnchor
from hyperion.orchestrator import HyperionConfig, run

SECRET = truth_gate.Attestor.generate_secret()


def good_attestation_body(egress="93.184.216.34") -> bytes:
    return truth_gate.Attestor(SECRET).to_json(truth_gate.Attestor(SECRET).sign(egress))


def config(**overrides) -> HyperionConfig:
    base = dict(
        server_host="127.0.0.1",
        server_port=4433,
        probe_url="https://probe.invalid/gate",
        attestation_secret=SECRET,
        insecure_skip_verify=True,
    )
    base.update(overrides)
    return HyperionConfig(**base)


class TestConfigValidation:
    def test_an_empty_config_is_rejected_before_anything_runs(self):
        report = run(HyperionConfig())
        assert report.step("config").status == orchestrator.STATUS_FAIL
        assert len(report.steps) == 1, "no other step may run after a bad config"
        assert report.failed_steps == ("config",)

    def test_a_short_secret_is_rejected(self):
        report = run(HyperionConfig(server_host="h", probe_url="u", attestation_secret=b"x"))
        assert "attestation_secret must be at least 16 bytes" in report.step("config").evidence

    def test_no_anchor_and_no_insecure_flag_is_rejected(self):
        report = run(
            HyperionConfig(
                server_host="h", probe_url="u", attestation_secret=SECRET, insecure_skip_verify=False
            )
        )
        assert any("trust_anchors" in e for e in report.step("config").evidence)

    def test_a_valid_config_passes_validation(self):
        assert config().validate() == []


class TestSkippedStepsAreHonest:
    def test_dry_run_reports_skipped_not_ok(self):
        report = run(config(), skip_network=True)
        statuses = {s.name: s.status for s in report.steps}
        assert statuses["dns"] == orchestrator.STATUS_SKIPPED
        assert statuses["zero-sni"] == orchestrator.STATUS_SKIPPED
        assert statuses["truth-gate"] == orchestrator.STATUS_SKIPPED

    def test_a_dry_run_is_never_reported_as_verified(self):
        """This is the exact failure mode of the previous design."""
        report = run(config(), skip_network=True)
        assert not report.ok
        assert "NOT VERIFIED" in report.render()
        assert "SKIPPED" in report.render()

    def test_the_offline_steps_still_run_in_a_dry_run(self):
        report = run(config(), skip_network=True)
        assert report.step("config").ok
        assert report.step("shard").ok
        assert "reassembled == original: True" in report.step("shard").evidence


class TestFullChain:
    def _openers(self, dns_ip="93.184.216.34", gate_body=None, gate_status=200):
        from hyperion import dns

        def dns_opener(request, timeout):
            query = request.data
            qid = int.from_bytes(query[0:2], "big")
            header = (
                qid.to_bytes(2, "big")
                + (0x8180).to_bytes(2, "big")
                + b"\x00\x01\x00\x01\x00\x00\x00\x00"
            )
            answer = (
                b"\xc0\x0c\x00\x01\x00\x01"
                + (300).to_bytes(4, "big")
                + (4).to_bytes(2, "big")
                + socket.inet_aton(dns_ip)
            )
            return header + query[12:] + answer

        def gate_opener(request, timeout):
            return gate_status, (
                good_attestation_body() if gate_body is None else gate_body
            )

        return dns_opener, gate_opener

    def _connect_stub(self, tls_server, certs):
        from hyperion import zero_sni

        def connect_fn(host, port, anchors, timeout, alpn, insecure_skip_verify):
            return zero_sni.connect(
                "127.0.0.1", port=tls_server.port, anchors=[zero_sni.TrustAnchor(ca_pem=certs.ca_pem)]
            )

        return connect_fn

    def test_every_step_passes_against_a_real_tls_server(self, tls_server, certs):
        dns_opener, gate_opener = self._openers()
        report = run(
            config(insecure_skip_verify=False, trust_anchors=(TrustAnchor(ca_pem=certs.ca_pem),)),
            dns_opener=dns_opener,
            gate_opener=gate_opener,
            connect_fn=self._connect_stub(tls_server, certs),
        )
        assert report.ok, report.render()
        assert "ALL STEPS VERIFIED" in report.render()
        assert report.step("zero-sni").ok
        assert report.step("truth-gate").ok

    def test_a_forged_attestation_fails_the_run(self, tls_server, certs):
        dns_opener, gate_opener = self._openers(gate_body=b'{"egress_ip":"10.0.0.1"}')
        report = run(
            config(),
            dns_opener=dns_opener,
            gate_opener=gate_opener,
            connect_fn=self._connect_stub(tls_server, certs),
        )
        assert not report.ok
        assert report.step("truth-gate").status == orchestrator.STATUS_FAIL

    def test_a_poisoned_resolver_does_not_stop_the_run_but_is_reported(self, tls_server, certs):
        from hyperion import dns

        def dns_opener(request, timeout):
            query = request.data
            qid = int.from_bytes(query[0:2], "big")
            header = qid.to_bytes(2, "big") + (0x8180).to_bytes(2, "big") + b"\x00\x01\x00\x01\x00\x00\x00\x00"
            answer = b"\xc0\x0c\x00\x01\x00\x01" + (300).to_bytes(4, "big") + (4).to_bytes(2, "big") + socket.inet_aton("10.10.34.35")
            return header + query[12:] + answer

        _, gate_opener = self._openers()
        report = run(
            config(),
            dns_opener=dns_opener,
            gate_opener=gate_opener,
            connect_fn=self._connect_stub(tls_server, certs),
            resolvers=[dns.Resolver("isp", "10.10.34.35", "https://isp.invalid/dns-query")],
        )
        assert report.step("dns").status == orchestrator.STATUS_FAIL
        assert any("POISONED" in line for line in report.step("dns").evidence)

    def test_a_refused_handshake_fails_the_run_with_the_reason(self):
        dns_opener, gate_opener = self._openers()

        def refusing_connect(host, **kwargs):
            raise RuntimeError("peer pin does not match")

        report = run(config(), dns_opener=dns_opener, gate_opener=gate_opener, connect_fn=refusing_connect)
        assert report.step("zero-sni").status == orchestrator.STATUS_FAIL
        assert "peer pin does not match" in report.step("zero-sni").detail


class TestCli:
    def test_hello_command_prints_the_fragmentation_and_exits_zero(self, capsys):
        assert cli.main(["hello", "--sni", "blocked.example", "--strategy", "isolate-sni"]) == 0
        out = capsys.readouterr().out
        assert "byte-exact reassembly: True" in out
        assert "piece 0:" in out

    def test_amnezia_command_describes_a_real_config(self, tmp_path, capsys):
        conf = tmp_path / "wg.conf"
        conf.write_text(
            "[Interface]\nPrivateKey = x\nJc = 3\nJmin = 10\nJmax = 40\nS1 = 15\nH1 = 1234\n"
        )
        assert cli.main(["amnezia", str(conf)]) == 0
        out = capsys.readouterr().out
        assert "jc=3" in out and "h1=1234" in out
        assert "junk" in out

    def test_keygen_prints_a_32_byte_secret(self, capsys):
        assert cli.main(["keygen"]) == 0
        secret = base64.b64decode(capsys.readouterr().out.strip())
        assert len(secret) == 32

    def test_dry_run_command_exits_nonzero_because_it_is_unverified(self, capsys):
        code = cli.main(
            [
                "run",
                "--dry-run",
                "--host",
                "127.0.0.1",
                "--probe",
                "https://probe.invalid/gate",
                "--secret",
                base64.b64encode(SECRET).decode(),
                "--insecure",
            ]
        )
        assert code == 1, "an unverified run must not exit 0"
        assert "NOT VERIFIED" in capsys.readouterr().out

    def test_bad_config_exits_nonzero(self, capsys):
        assert cli.main(["run", "--dry-run"]) == 1

    def test_connect_to_a_closed_port_fails_cleanly(self, capsys):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        assert cli.main(["connect", "127.0.0.1", "--port", str(port), "--insecure"]) == 1
        assert "FAILED" in capsys.readouterr().out
