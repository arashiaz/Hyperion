"""Tests for the Truth Gate (signed egress attestation)."""

from __future__ import annotations

import json
import time

import pytest

from hyperion.truth_gate import Attestation, Attestor, Gate, GateError, format_timestamp

SECRET = b"0123456789abcdef0123456789abcdef"


def attestation_bytes(
    egress="93.184.216.34", timestamp=None, nonce="nonce-1", secret=SECRET, tamper=None
) -> bytes:
    signed = Attestor(secret).sign(
        egress, timestamp=time.time() if timestamp is None else timestamp, nonce=nonce
    )
    if tamper:
        signed = tamper(signed)
    return Attestor(secret).to_json(signed)


class TestHappyPath:
    def test_a_valid_attestation_passes_every_check(self):
        gate = Gate(secret=SECRET)
        verdict = gate.verify(attestation_bytes(), http_status=200, latency_ms=120.0)
        assert verdict.passed, verdict.failed
        assert [name for name, _, _ in verdict.checks] == [
            "http-status",
            "signature",
            "freshness",
            "egress",
        ]

    def test_the_report_shows_the_egress_ip(self):
        verdict = Gate(secret=SECRET).verify(attestation_bytes(), http_status=200)
        assert any("93.184.216.34" in note for _, _, note in verdict.checks)


class TestSignature:
    def test_a_forged_body_is_rejected(self):
        raw = attestation_bytes(tamper=lambda a: Attestation("8.8.8.8", a.timestamp, a.nonce, a.signature))
        verdict = Gate(secret=SECRET).verify(raw, http_status=200)
        assert not verdict.passed
        assert verdict.failed == ("signature",)

    def test_the_wrong_secret_is_rejected(self):
        raw = attestation_bytes(secret=b"ffffffffffffffffffffffffffffffff")
        verdict = Gate(secret=SECRET).verify(raw, http_status=200)
        assert not verdict.passed
        assert verdict.failed == ("signature",)

    def test_other_checks_are_not_evaluated_on_a_bad_signature(self):
        """A forger controls every field, so nothing downstream is trustworthy."""
        raw = attestation_bytes(tamper=lambda a: Attestation("10.0.0.1", a.timestamp, a.nonce, a.signature))
        verdict = Gate(secret=SECRET).verify(raw, http_status=200)
        names = [name for name, _, _ in verdict.checks]
        assert "egress" not in names

    def test_a_tampered_timestamp_breaks_the_signature(self):
        raw = attestation_bytes(
            tamper=lambda a: Attestation(
                a.egress_ip, format_timestamp(a.timestamp_seconds + 9999), a.nonce, a.signature
            )
        )
        verdict = Gate(secret=SECRET).verify(raw, http_status=200)
        assert not verdict.passed
        assert verdict.failed == ("signature",)

    def test_the_signed_timestamp_string_is_used_verbatim(self):
        """No float re-formatting on the verify side: the wire string is signed."""
        attestation = Attestor(SECRET).sign("93.184.216.34", timestamp=1800000000.0, nonce="n")
        assert attestation.timestamp == "1800000000.000"
        assert attestation.canonical_payload() == b"93.184.216.34|1800000000.000|n"


class TestFreshness:
    def test_an_old_attestation_is_rejected(self):
        raw = attestation_bytes(timestamp=time.time() - 3600)
        verdict = Gate(secret=SECRET).verify(raw, http_status=200)
        assert not verdict.passed
        assert "freshness" in verdict.failed

    def test_a_future_dated_attestation_is_rejected(self):
        raw = attestation_bytes(timestamp=time.time() + 3600)
        assert "freshness" in Gate(secret=SECRET).verify(raw, http_status=200).failed

    def test_a_replayed_nonce_is_rejected_the_second_time(self):
        gate = Gate(secret=SECRET)
        raw = attestation_bytes(nonce="fixed-nonce")
        assert gate.verify(raw, http_status=200).passed
        replay = gate.verify(raw, http_status=200)
        assert not replay.passed
        assert "freshness" in replay.failed
        assert any("replay" in note for _, _, note in replay.checks)

    def test_a_failed_check_does_not_consume_the_nonce(self):
        gate = Gate(secret=SECRET)
        raw = attestation_bytes(nonce="still-free", egress="10.0.0.1")
        assert not gate.verify(raw, http_status=200).passed, "non-routable egress must fail"
        good = attestation_bytes(nonce="still-free", egress="93.184.216.34")
        assert gate.verify(good, http_status=200).passed


class TestEgress:
    @pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.5", "127.0.0.1", "172.16.0.1"])
    def test_a_non_routable_egress_fails(self, ip):
        verdict = Gate(secret=SECRET).verify(attestation_bytes(egress=ip), http_status=200)
        assert "egress" in verdict.failed

    def test_an_egress_equal_to_our_own_address_fails(self):
        gate = Gate(secret=SECRET, local_addresses=("93.184.216.34",))
        assert "egress" in gate.verify(attestation_bytes(egress="93.184.216.34"), http_status=200).failed

    def test_a_garbage_egress_string_fails(self):
        verdict = Gate(secret=SECRET).verify(attestation_bytes(egress="not-an-ip"), http_status=200)
        assert "egress" in verdict.failed


class TestTransportSignals:
    def test_a_403_from_the_censor_fails(self):
        verdict = Gate(secret=SECRET).verify(attestation_bytes(), http_status=403)
        assert not verdict.passed
        assert "http-status" in verdict.failed

    def test_a_204_with_no_body_is_not_evidence(self):
        """The old design accepted a bare 204; this must now fail."""
        verdict = Gate(secret=SECRET).verify(b"", http_status=204)
        assert not verdict.passed

    def test_status_only_check_admits_it_is_weak(self):
        verdict = Gate(secret=SECRET).verify_status_only(204)
        assert verdict.passed
        assert "not evidence" in verdict.checks[0][2]

    def test_html_from_a_hijack_proxy_fails_to_parse(self):
        verdict = Gate(secret=SECRET).verify(b"<html>blocked</html>", http_status=200)
        assert not verdict.passed
        assert "attestation" in verdict.failed


class TestMalformed:
    def test_missing_field_is_an_error_not_a_pass(self):
        with pytest.raises(GateError):
            Gate(secret=SECRET).parse(b'{"egress_ip":"1.2.3.4"}')

    def test_short_secret_is_refused_at_construction(self):
        with pytest.raises(GateError, match="16 bytes"):
            Attestor(b"tooshort")

    def test_unsupported_algorithm_is_refused(self):
        doc = json.loads(attestation_bytes())
        doc["algorithm"] = "md5"
        with pytest.raises(GateError, match="unsupported algorithm"):
            Gate(secret=SECRET).parse(json.dumps(doc).encode())
