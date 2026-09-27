"""Tests for the Zero-SNI client, against a real local TLS server."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest

from hyperion import zero_sni
from hyperion.tls_record import ClientHello, TlsRecord, looks_like_tls, sni_in_bytes
from hyperion.zero_sni import TrustAnchor, ZeroSniError, connect, normalise_pin


class TestPins:
    @pytest.mark.parametrize(
        "form",
        [
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "0" * 64,
            "sha256:" + "0" * 64,
        ],
    )
    def test_accepted_forms_normalise_to_hex(self, form):
        assert len(normalise_pin(form)) == 64

    def test_base64_and_hex_of_the_same_pin_agree(self):
        import base64

        raw = bytes(range(32))
        assert normalise_pin(base64.b64encode(raw).decode()) == raw.hex()
        assert normalise_pin(raw.hex()) == raw.hex()

    def test_a_pin_of_the_wrong_length_is_refused(self):
        with pytest.raises(ZeroSniError):
            normalise_pin("AAAA")

    def test_an_empty_anchor_is_refused(self):
        with pytest.raises(ZeroSniError, match="refusing to build"):
            TrustAnchor()


class TestGuards:
    def test_connecting_with_no_anchor_is_refused(self):
        with pytest.raises(ZeroSniError, match="no trust anchor"):
            connect("127.0.0.1", port=1)

    def test_an_untrusted_peer_is_rejected(self, tls_server):
        """The test CA is not in the trust store, so this must fail closed."""
        with pytest.raises(ZeroSniError):
            connect("127.0.0.1", port=tls_server.port, anchors=[TrustAnchor(spki_sha256_hex="0" * 64)])


class TestRealHandshake:
    def test_ca_anchor_completes_the_handshake(self, tls_server, certs):
        sock, report = connect(
            "127.0.0.1", port=tls_server.port, anchors=[TrustAnchor(ca_pem=certs.ca_pem)]
        )
        with sock:
            assert report.trusted
            assert report.matched_anchor == "ca-chain"
            assert report.sni_sent is False
            assert report.version.startswith("TLSv1.")
            assert report.peer_subject_cn == "hyperion.test"

    def test_spki_pin_alone_completes_the_handshake(self, tls_server, certs):
        sock, report = connect(
            "127.0.0.1",
            port=tls_server.port,
            anchors=[TrustAnchor(spki_sha256_hex=certs.spki_sha256)],
        )
        with sock:
            assert report.trusted
            assert report.peer_pin == certs.spki_sha256
            assert report.matched_anchor.startswith("spki-pin")

    def test_data_flows_both_ways_after_the_handshake(self, tls_server, certs):
        sock, _ = connect(
            "127.0.0.1", port=tls_server.port, anchors=[TrustAnchor(ca_pem=certs.ca_pem)]
        )
        with sock:
            sock.sendall(b"ping")
            assert sock.recv(16) == b"OK\n"

    def test_the_server_never_received_an_sni(self, tls_server, certs):
        """Asserted from the server side: no SNI callback fired at all."""
        sock, _ = connect(
            "127.0.0.1", port=tls_server.port, anchors=[TrustAnchor(ca_pem=certs.ca_pem)]
        )
        with sock:
            sock.sendall(b"x")
            sock.recv(16)
        # OpenSSL invokes the SNI callback with None when no SNI was present,
        # so the only acceptable outcomes are "never called" or "called with None".
        assert tls_server.sni_seen, "the callback never fired; the test proves nothing"
        assert all(name is None for name in tls_server.sni_seen), (
            f"server received an SNI: {tls_server.sni_seen}"
        )

    def test_insecure_mode_is_loudly_labelled(self, tls_server):
        sock, report = connect("127.0.0.1", port=tls_server.port, insecure_skip_verify=True)
        with sock:
            assert "SKIPPED" in report.verification
            assert report.matched_anchor == "none"


class TestClientHelloOnTheWire:
    """Intercept the raw bytes so the absence of SNI is proved, not assumed."""

    def _capture_client_hello(self, port: int) -> bytes:
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            data = b""
            while len(data) < 200:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                data += chunk
                total = TlsRecord.peek_length(data)
                if total and len(data) >= total:
                    break
            return data
        finally:
            raw.close()

    @pytest.fixture
    def sniffer(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        captured: list[bytes] = []

        def serve():
            conn, _ = listener.accept()
            with conn:
                data = conn.recv(4096)
                captured.append(data)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        yield listener.getsockname()[1], captured
        listener.close()
        thread.join(timeout=2)

    def test_python_emits_no_server_name_extension(self, sniffer):
        port, captured = sniffer

        def attempt():
            context = zero_sni.build_ssl_context([TrustAnchor(spki_sha256_hex="0" * 64)])
            raw = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                context.wrap_socket(raw, server_hostname=None)
            except (ssl.SSLError, OSError):
                pass  # the sniffer never completes a handshake; that is expected

        attempt()
        assert captured, "the sniffer received nothing"
        hello_bytes = captured[0]
        assert looks_like_tls(hello_bytes), "the first bytes were not a TLS record"
        assert sni_in_bytes(hello_bytes) is None
        hello = ClientHello.parse(TlsRecord.parse(hello_bytes).payload)
        assert hello.sni is None

    def test_the_same_stack_with_a_hostname_does_emit_sni(self, sniffer):
        """Control experiment: proves the test above is not vacuous."""
        port, captured = sniffer
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.wrap_socket(raw, server_hostname="control.example")
        except (ssl.SSLError, OSError):
            pass
        assert captured
        assert sni_in_bytes(captured[0]) == "control.example"
