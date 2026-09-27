"""Shared fixtures: a throwaway CA + leaf certificate for the Zero-SNI tests."""

from __future__ import annotations

import base64
import datetime
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CertBundle:
    ca_pem: str
    leaf_pem: str
    leaf_key_pem: str
    leaf_der: bytes
    spki_sha256: str


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _spki_pin(key: rsa.RSAPrivateKey) -> str:
    import hashlib

    return hashlib.sha256(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()


@pytest.fixture(scope="session")
def certs() -> CertBundle:
    ca_key = _make_key()
    leaf_key = _make_key()
    now = datetime.datetime.now(datetime.timezone.utc)

    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Hyperion Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hyperion.test")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("hyperion.test"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return CertBundle(
        ca_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        leaf_pem=leaf_cert.public_bytes(serialization.Encoding.PEM).decode(),
        leaf_key_pem=leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        leaf_der=leaf_cert.public_bytes(serialization.Encoding.DER),
        spki_sha256=_spki_pin(leaf_key),
    )


class TlsTestServer:
    """A TLS server that serves the fixture certificate to a no-SNI client."""

    def __init__(self, bundle: CertBundle, response: bytes = b"") -> None:
        self.bundle = bundle
        self.response = response or b"OK\n"
        self.sni_seen: list[str | None] = []
        self.alpn_seen: list[str | None] = []
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._load_cert()
        self._context.set_alpn_protocols(["h2", "http/1.1"])

        def _servername_callback(sock: ssl.SSLSocket, name: str | None, ctx: ssl.SSLContext):
            self.sni_seen.append(name)
            return None

        self._context.sni_callback = _servername_callback
        self._httpd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._httpd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._httpd.bind(("127.0.0.1", 0))
        self._httpd.listen(4)
        self.port = self._httpd.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _load_cert(self) -> None:
        import tempfile
        from pathlib import Path

        self._tmpdir = Path(tempfile.mkdtemp(prefix="hyperion-test-"))
        cert_path = self._tmpdir / "leaf.pem"
        key_path = self._tmpdir / "leaf.key"
        cert_path.write_text(self.bundle.leaf_pem)
        key_path.write_text(self.bundle.leaf_key_pem)
        self._context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    def start(self) -> "TlsTestServer":
        self._thread.start()
        return self

    def _serve(self) -> None:
        while True:
            try:
                raw, _ = self._httpd.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        try:
            tls = self._context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        with tls:
            self.alpn_seen.append(tls.selected_alpn_protocol())
            try:
                tls.recv(1)
            except OSError:
                return
            try:
                tls.sendall(self.response)
            except OSError:
                return

    def stop(self) -> None:
        try:
            self._httpd.close()
        except OSError:
            pass


@pytest.fixture
def tls_server(certs: CertBundle):
    server = TlsTestServer(certs).start()
    yield server
    server.stop()


@pytest.fixture
def doh_wire_opener(certs: CertBundle):
    """An opener that answers DoH wire-format queries with a scripted A record."""

    def make(answer_ip: str = "93.184.216.34", rcode: int = 0, txid: int = 0x4859):
        from hyperion import dns

        def opener(request, timeout: float) -> bytes:
            query = request.data
            assert request.get_header("Accept") == dns.DNS_MESSAGE_MEDIA_TYPE
            assert query is not None
            qid = int.from_bytes(query[0:2], "big")
            header = (
                qid.to_bytes(2, "big")
                + (0x8180 | rcode).to_bytes(2, "big")
                + (1).to_bytes(2, "big")
                + (1 if rcode == 0 else 0).to_bytes(2, "big")
                + (0).to_bytes(2, "big")
                + (0).to_bytes(2, "big")
            )
            question = query[12:]
            answer = b""
            if rcode == 0:
                answer = (
                    b"\xc0\x0c"
                    + (1).to_bytes(2, "big")
                    + (1).to_bytes(2, "big")
                    + (300).to_bytes(4, "big")
                    + (4).to_bytes(2, "big")
                    + socket.inet_aton(answer_ip)
                )
            return header + question + answer

        return opener

    return make


@pytest.fixture
def json_opener():
    """An opener that answers the JSON DoH interface."""

    def make(payload: dict):
        import json as _json

        from hyperion import dns

        def opener(request, timeout: float) -> bytes:
            assert request.get_header("Accept") == dns.DNS_JSON_MEDIA_TYPE
            return _json.dumps(payload).encode()

        return opener

    return make
