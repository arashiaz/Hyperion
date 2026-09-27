"""Tests for the reference transport, including a real no-SNI TLS handshake."""

from __future__ import annotations

import json
import socket

import pytest

from conftest import TlsTestServer
from hyperion import selector, transport, truth_gate, zero_sni
from hyperion.selector import Outcome, evaluate, select
from hyperion.transport import (
    TransportError,
    content_length,
    parse_status_line,
    split_head,
    timed_tcp,
    zero_sni_candidate,
)
from hyperion.zero_sni import TrustAnchor, ZeroSniError

SECRET = b"transport-test-secret-16bytes-min"
EGRESS = "93.184.216.34"
PATH = "/hyperion/attest"


def attestation_body(egress: str = EGRESS, when: float | None = None) -> bytes:
    attestor = truth_gate.Attestor(secret=SECRET)
    return attestor.to_json(attestor.sign(egress, timestamp=when))


def http_response(body: bytes, status: int = 200, reason: str = "OK") -> bytes:
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return head + body


class FakeSocket:
    """A recv-only stub. The parsing under test is the real thing."""

    def __init__(self, chunks, close_early: bool = False):
        self._chunks = list(chunks)
        self._close_early = close_early
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def recv(self, _n):
        if not self._chunks:
            return b""
        if self._close_early and len(self._chunks) == 1:
            self._chunks.clear()
            return b""
        return self._chunks.pop(0)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


class TestHeadParsing:
    def test_split_head_finds_the_blank_line(self):
        head, body = split_head(b"a\r\nb\r\n\r\nrest")
        assert head == b"a\r\nb"
        assert body == b"rest"

    def test_split_head_returns_none_until_it_arrives(self):
        assert split_head(b"HTTP/1.1 200 OK\r\n") is None

    @pytest.mark.parametrize(
        "line,status,reason",
        [
            (b"HTTP/1.1 200 OK", 200, "OK"),
            (b"HTTP/1.1 404 Not Found", 404, "Not Found"),
            (b"HTTP/1.0 503", 503, ""),
        ],
    )
    def test_status_lines(self, line, status, reason):
        assert parse_status_line(line) == (status, reason)

    @pytest.mark.parametrize(
        "line",
        [b"<html>blocked</html>", b"", b"HTTP/1.1 abc OK"],
    )
    def test_a_non_http_answer_raises_rather_than_guessing(self, line):
        """A status line that will not parse is a local terminator, not a failure."""
        with pytest.raises(TransportError):
            parse_status_line(line)

    def test_content_length_is_case_insensitive(self):
        head = b"HTTP/1.1 200 OK\r\ncontent-LENGTH: 42\r\nX-Other: 1"
        assert content_length(head) == 42

    def test_a_missing_or_broken_length_is_none(self):
        assert content_length(b"HTTP/1.1 200 OK") is None
        assert content_length(b"HTTP/1.1 200 OK\r\nContent-Length: abc") is None


class TestReadHttp:
    def test_a_declared_body_is_read_exactly(self):
        sock = FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", b"hello"])
        response = transport.read_http(sock, timeout=1.0)
        assert response.status == 200
        assert response.body == b"hello"

    def test_a_body_arriving_in_pieces_is_assembled(self):
        sock = FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nab", b"cd", b"ef"])
        assert transport.read_http(sock, timeout=1.0).body == b"abcdef"

    def test_no_declared_length_returns_what_arrived_with_the_head(self):
        """Reading to EOF is refused: it is how a probe waits out its timeout."""
        sock = FakeSocket([b"HTTP/1.1 204 No Content\r\n\r\n"])
        response = transport.read_http(sock, timeout=1.0)
        assert response.status == 204
        assert response.body == b""

    def test_a_truncated_body_raises(self):
        sock = FakeSocket([b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort"], close_early=True)
        with pytest.raises(TransportError, match="closed"):
            transport.read_http(sock, timeout=1.0)

    def test_a_connection_that_says_nothing_raises(self):
        with pytest.raises(TransportError, match="closed"):
            transport.read_http(FakeSocket([]), timeout=1.0)


# --------------------------------------------------------------------------
# end to end, against a real TLS server and a real signature
# --------------------------------------------------------------------------


@pytest.fixture
def attesting_server(certs):
    """A no-SNI TLS server that answers the attest path with a real signature."""

    def make(body: bytes, status: int = 200):
        return TlsTestServer(certs, response=http_response(body, status)).start()

    servers = []

    def factory(body: bytes, status: int = 200):
        server = make(body, status)
        servers.append(server)
        return server

    yield factory
    for server in servers:
        server.stop()


class TestEndToEnd:
    def test_an_honest_exit_is_works_and_attested(self, certs, attesting_server):
        server = attesting_server(attestation_body())
        candidate = zero_sni_candidate(
            "honest",
            "127.0.0.1",
            server.port,
            anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
        )
        result = evaluate(candidate, gate=truth_gate.Gate(secret=SECRET))
        assert result.outcome is Outcome.WORKS
        assert result.attested is True
        assert result.usable is True

    def test_no_sni_reaches_the_server(self, certs, attesting_server):
        server = attesting_server(attestation_body())
        candidate = zero_sni_candidate(
            "quiet",
            "127.0.0.1",
            server.port,
            anchors=[TrustAnchor(spki_sha256_hex=certs.spki_sha256)],
        )
        assert evaluate(candidate, gate=truth_gate.Gate(secret=SECRET)).usable
        assert server.sni_seen, "the server never saw a ClientHello"
        assert server.sni_seen[0] is None, "a name was announced"

    def test_a_forged_attestation_is_lying(self, certs, attesting_server):
        forged = json.loads(attestation_body())
        forged["egress_ip"] = "203.0.113.9"  # body changed, signature did not
        server = attesting_server(json.dumps(forged).encode())
        candidate = zero_sni_candidate(
            "forger",
            "127.0.0.1",
            server.port,
            anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
        )
        result = evaluate(candidate, gate=truth_gate.Gate(secret=SECRET))
        assert result.outcome is Outcome.LYING
        assert "signature" in result.detail

    def test_an_exit_signing_a_sinkhole_address_is_lying(self, certs, attesting_server):
        server = attesting_server(attestation_body("10.10.34.35"))
        candidate = zero_sni_candidate(
            "sinkholed",
            "127.0.0.1",
            server.port,
            anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
        )
        result = evaluate(candidate, gate=truth_gate.Gate(secret=SECRET))
        assert result.outcome is Outcome.LYING
        assert "egress" in result.detail

    def test_a_wrong_secret_is_lying(self, certs, attesting_server):
        server = attesting_server(attestation_body())
        candidate = zero_sni_candidate(
            "stranger",
            "127.0.0.1",
            server.port,
            anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
        )
        result = evaluate(candidate, gate=truth_gate.Gate(secret=b"a-different-secret-16b"))
        assert result.outcome is Outcome.LYING

    def test_an_http_error_is_refused(self, certs, attesting_server):
        server = attesting_server(b'{"error":"no proxy"}', status=503)
        candidate = zero_sni_candidate(
            "unavailable",
            "127.0.0.1",
            server.port,
            anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
        )
        result = evaluate(candidate, gate=truth_gate.Gate(secret=SECRET))
        assert result.outcome is Outcome.REFUSED
        assert "503" in result.detail
        assert result.retryable is True

    def test_a_closed_port_is_refused_not_filtered(self, certs):
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        candidate = zero_sni_candidate(
            "closed",
            "127.0.0.1",
            port,
            anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
        )
        result = evaluate(candidate, gate=truth_gate.Gate(secret=SECRET))
        assert result.outcome is Outcome.REFUSED

    def test_an_honest_exit_beats_a_lying_one(self, certs, attesting_server):
        good = attesting_server(attestation_body())
        bad = attesting_server(b"{}")
        gate = truth_gate.Gate(secret=SECRET)
        report = select(
            [
                zero_sni_candidate(
                    "liar", "127.0.0.1", bad.port,
                    anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
                ),
                zero_sni_candidate(
                    "honest", "127.0.0.1", good.port,
                    anchors=[TrustAnchor(ca_pem=certs.ca_pem)],
                ),
            ],
            width=2,
            gate=gate,
        )
        assert report.winner is not None
        assert report.winner.candidate == "honest"
        assert report.winner.attested is True


class TestCandidateGuards:
    def test_a_candidate_with_no_anchor_is_refused(self):
        with pytest.raises(ZeroSniError, match="trust anchor"):
            zero_sni_candidate("bare", "127.0.0.1", 443)

    def test_insecure_skip_verify_is_allowed_but_loud(self):
        candidate = zero_sni_candidate(
            "lab", "127.0.0.1", 443, insecure_skip_verify=True
        )
        assert candidate.attest is True


class TestTimedTcp:
    def test_a_live_port_completes(self, certs, attesting_server):
        server = attesting_server(attestation_body())
        ok, elapsed, detail = timed_tcp("127.0.0.1", server.port, timeout=2.0)
        assert ok is True
        assert elapsed >= 0.0
        assert "completed" in detail

    def test_a_closed_port_is_classified(self, certs):
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        ok, _elapsed, detail = timed_tcp("127.0.0.1", port, timeout=2.0)
        assert ok is False
        assert detail.startswith("refused")
