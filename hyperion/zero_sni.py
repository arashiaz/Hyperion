"""Zero-SNI TLS client: connect to :443 without telling anyone who you want.

How the censorship is broken
----------------------------
An SNI filter only has the plaintext ``server_name`` extension to match on.  If
the ClientHello carries no such extension there is nothing to match, and the
connection is indistinguishable from any other TLS session opened against that
IP.  Dropping SNI has one consequence: the client can no longer rely on the
hostname to validate the certificate, so *identity must be proven another way*.
This module does that with two mechanisms, either of which is sufficient:

* **Pinned CA** -- a PEM trust anchor you control; the server's chain must
  verify against it.
* **SPKI pin** -- SHA-256 over the certificate's ``SubjectPublicKeyInfo``.  This
  survives certificate renewal (the key stays) and cannot be satisfied by a
  certificate that a middlebox obtains from any public CA, which is precisely
  the attack a national DPI box would mount.

Verification is *on by default and cannot be silently disabled*: constructing a
``TrustAnchor`` with neither a CA nor a pin raises.  The escape hatch is
``insecure_skip_verify=True``, which is loud, recorded in the returned report
and meant for lab benches only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Sequence

DEFAULT_TIMEOUT = 8.0
DEFAULT_TLS_MIN_VERSION = ssl.TLSVersion.TLSv1_2


class ZeroSniError(RuntimeError):
    """Raised when the peer cannot be trusted or the handshake is rejected."""


def normalise_pin(pin: str) -> str:
    """Accept ``sha256/AAAA...`` (base64), raw base64, or hex; return lowercase hex."""
    text = pin.strip()
    for prefix in ("sha256/", "sha256:"):
        if text.lower().startswith(prefix):
            text = text.split(prefix, 1)[1].strip()
    if len(text) == 64:
        try:
            return binascii.unhexlify(text).hex()
        except (ValueError, binascii.Error):
            pass
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=False)
    except (ValueError, binascii.Error) as exc:
        raise ZeroSniError(f"unparseable pin {pin!r}") from exc
    if len(raw) != 32:
        raise ZeroSniError(f"pin must decode to 32 bytes, got {len(raw)}")
    return raw.hex()


@dataclass(frozen=True)
class TrustAnchor:
    """Either a CA certificate (PEM) or an SPKI SHA-256 pin."""

    ca_pem: str | None = None
    spki_sha256_hex: str | None = None

    def __post_init__(self) -> None:
        if not self.ca_pem and not self.spki_sha256_hex:
            raise ZeroSniError(
                "a TrustAnchor needs ca_pem or spki_sha256_hex; refusing to build "
                "an anchor that trusts nothing"
            )
        if self.spki_sha256_hex:
            object.__setattr__(
                self, "spki_sha256_hex", normalise_pin(self.spki_sha256_hex)
            )

    @property
    def kind(self) -> str:
        return "spki-pin" if self.spki_sha256_hex else "ca"


def der_spki_sha256(der_cert: bytes) -> str:
    """SHA-256 over the SubjectPublicKeyInfo of a DER certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(der_cert)
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()


def der_subject_and_expiry(der_cert: bytes) -> tuple[str, str]:
    """Human-readable subject CN and notAfter, for reports and debugging."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_der_x509_certificate(der_cert)
    cn = ""
    for attribute in cert.subject:
        if attribute.oid == NameOID.COMMON_NAME:
            cn = str(attribute.value)
            break
    return cn, cert.not_valid_after_utc.isoformat(timespec="seconds")


@dataclass(frozen=True)
class HandshakeReport:
    """What the handshake actually proved."""

    peer_address: str
    peer_port: int
    version: str
    cipher: str
    alpn: str | None
    peer_pin: str
    peer_subject_cn: str
    peer_not_after: str
    matched_anchor: str
    sni_sent: bool
    verification: str
    elapsed_ms: float

    @property
    def trusted(self) -> bool:
        return self.verification == "verified"

    def one_line(self) -> str:
        return (
            f"{self.peer_address}:{self.peer_port} {self.version} {self.cipher} "
            f"pin={self.peer_pin[:12]}... {self.verification} "
            f"({'SNI sent' if self.sni_sent else 'no SNI'}) in {self.elapsed_ms:.0f}ms"
        )


def build_ssl_context(
    anchors: Sequence[TrustAnchor],
    alpn: Sequence[str] | None = None,
    insecure_skip_verify: bool = False,
    minimum_version: ssl.TLSVersion = DEFAULT_TLS_MIN_VERSION,
) -> ssl.SSLContext:
    """Build a context that validates the peer with no hostname to go on."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = minimum_version
    # There is no SNI, so there is no hostname to match against the certificate.
    context.check_hostname = False
    if insecure_skip_verify:
        context.verify_mode = ssl.CERT_NONE
    else:
        ca_pems = [anchor.ca_pem for anchor in anchors if anchor.ca_pem]
        if ca_pems:
            # OpenSSL validates the chain; pins are checked on top of it below.
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cadata="\n".join(ca_pems))
        elif any(anchor.spki_sha256_hex for anchor in anchors):
            # Pin-only mode: there is no chain to check, so accept whatever is
            # presented and enforce the pin ourselves in _match_anchor().
            context.verify_mode = ssl.CERT_NONE
        else:
            raise ZeroSniError("no usable trust anchors")
    if alpn:
        context.set_alpn_protocols(list(alpn))
    return context


def _match_anchor(anchors: Sequence[TrustAnchor], peer_pin: str, chain_verified: bool) -> str | None:
    for anchor in anchors:
        if anchor.spki_sha256_hex == peer_pin:
            return f"spki-pin {peer_pin[:12]}..."
    if chain_verified:
        return "ca-chain"
    return None


def connect(
    host: str,
    port: int = 443,
    anchors: Sequence[TrustAnchor] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    alpn: Sequence[str] | None = None,
    insecure_skip_verify: bool = False,
    source_address: tuple[str, int] | None = None,
) -> tuple[ssl.SSLSocket, HandshakeReport]:
    """Open a TLS connection to ``host:port`` without sending SNI.

    Returns the live socket and a report describing what was proven.  The caller
    owns the socket and must close it.
    """
    if not anchors and not insecure_skip_verify:
        raise ZeroSniError(
            "refusing to connect with no trust anchor; pass anchors=[...] or set "
            "insecure_skip_verify=True explicitly"
        )
    anchors = tuple(anchors or ())
    context = build_ssl_context(
        anchors, alpn=alpn, insecure_skip_verify=insecure_skip_verify
    )

    started = time.perf_counter()
    raw = socket.create_connection(
        (host, port), timeout=timeout, source_address=source_address
    )
    try:
        # server_hostname=None is the whole point: no SNI extension is emitted.
        tls_sock = context.wrap_socket(
            raw, server_hostname=None, do_handshake_on_connect=True
        )
    except Exception:
        raw.close()
        raise
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    try:
        der = tls_sock.getpeercert(binary_form=True)
        if not der:
            raise ZeroSniError("peer presented no certificate")

        peer_pin = der_spki_sha256(der)
        subject_cn, not_after = der_subject_and_expiry(der)
        # getpeercert() only returns a parsed dict when OpenSSL validated the
        # chain, which is how we learn whether a CA anchor did its job.
        chain_verified = bool(tls_sock.getpeercert())
        matched = _match_anchor(anchors, peer_pin, chain_verified)

        if insecure_skip_verify:
            verification = "SKIPPED (insecure)"
        elif matched is None:
            raise ZeroSniError(
                f"peer pin {peer_pin[:16]}... matches no configured anchor and the "
                "chain did not verify; this is what a MITM looks like"
            )
        else:
            verification = "verified"
    except Exception:
        tls_sock.close()
        raise

    cipher = tls_sock.cipher()
    report = HandshakeReport(
        peer_address=host,
        peer_port=port,
        version=tls_sock.version() or "unknown",
        cipher=cipher[0] if cipher else "unknown",
        alpn=tls_sock.selected_alpn_protocol(),
        peer_pin=peer_pin,
        peer_subject_cn=subject_cn,
        peer_not_after=not_after,
        matched_anchor=matched or ("none" if insecure_skip_verify else "unknown"),
        sni_sent=False,
        verification=verification,
        elapsed_ms=elapsed_ms,
    )
    return tls_sock, report


def http_connect_tunnel(
    tls_sock: ssl.SSLSocket,
    target_host: str,
    target_port: int = 443,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Ask a front server for a CONNECT tunnel; returns the status line."""
    request = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode("ascii")
    tls_sock.settimeout(timeout)
    tls_sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response and len(response) < 65536:
        chunk = tls_sock.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if " 200" not in status_line:
        raise ZeroSniError(f"front refused the tunnel: {status_line or 'empty response'}")
    return status_line


__all__ = [
    "DEFAULT_TIMEOUT",
    "HandshakeReport",
    "TrustAnchor",
    "ZeroSniError",
    "build_ssl_context",
    "connect",
    "der_spki_sha256",
    "der_subject_and_expiry",
    "http_connect_tunnel",
    "normalise_pin",
]
