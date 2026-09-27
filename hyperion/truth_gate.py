"""Truth Gate: prove the tunnel is real instead of hoping it is.

The problem with a plain 204
---------------------------
"Ask a probe URL and accept HTTP 204" does not prove anything.  A transparent
middlebox can answer ``204 No Content`` locally without a single byte ever
leaving the country, and the client will happily conclude that it is free.
Iranian operators have been observed doing exactly this class of local
termination, so a self-answered probe is *negative* evidence at best.

What does constitute evidence
-----------------------------
Three properties, all checked here:

1. **Authorship.** The probe reply must carry an HMAC-SHA256 over a secret only
   the real server holds.  A middlebox that terminates the connection locally
   cannot produce it, and it cannot replay an old one either (see 3).
2. **Egress.** The server reports the source IP it actually saw.  If that IP is
   not globally routable, or equals the address the client has on its own
   interface, the "exit" is the local network.
3. **Freshness.** A signed attestation carries a timestamp and a nonce.  The
   timestamp must be inside the window; the nonce must not have been seen
   before.  Without the nonce a captured attestation could be replayed forever.

``verify`` returns a :class:`GateVerdict` naming *which* of the three failed,
because "the tunnel is down" and "the tunnel is up but a censor is answering"
call for completely different responses from the orchestrator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import tls_record

ALGORITHM = "hmac-sha256"
DEFAULT_WINDOW_SECONDS = 30.0
DEFAULT_TIMEOUT = 8.0


class GateError(RuntimeError):
    """Raised for malformed input rather than a failed check."""


def format_timestamp(value: float) -> str:
    """Render a timestamp for the wire.

    Fixed at three decimals and, crucially, formatted *once* by the signer and
    then transmitted verbatim.  The verifier signs over the string it received
    rather than re-formatting a float, so no client ever has to agree with the
    server about floating-point rounding rules -- which is exactly the kind of
    thing that silently breaks a Kotlin client against a Python server.
    """
    return f"{value:.3f}"


@dataclass(frozen=True)
class Attestation:
    """A signed statement by the server about what it saw."""

    egress_ip: str
    timestamp: str
    nonce: str
    signature: str
    algorithm: str = ALGORITHM

    @property
    def timestamp_seconds(self) -> float:
        try:
            return float(self.timestamp)
        except ValueError as exc:
            raise GateError(f"timestamp {self.timestamp!r} is not a number") from exc

    def canonical_payload(self) -> bytes:
        """The exact bytes that are signed. Field order is part of the protocol."""
        return f"{self.egress_ip}|{self.timestamp}|{self.nonce}".encode("ascii")


@dataclass(frozen=True)
class GateVerdict:
    """Outcome of a truth-gate check."""

    passed: bool
    checks: tuple[tuple[str, bool, str], ...]
    http_status: int | None = None
    latency_ms: float = 0.0

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(name for name, ok, _ in self.checks if not ok)

    def one_line(self) -> str:
        state = "PASS" if self.passed else f"FAIL ({', '.join(self.failed)})"
        return f"truth-gate: {state} in {self.latency_ms:.0f}ms"

    def detail_lines(self) -> Iterable[str]:
        for name, ok, note in self.checks:
            yield f"  [{'x' if ok else ' '}] {name}: {note}"


@dataclass
class Attestor:
    """Server side: signs attestations, and can validate one it is given."""

    secret: bytes
    algorithm: str = ALGORITHM

    def __post_init__(self) -> None:
        if len(self.secret) < 16:
            raise GateError("attestation secret must be at least 16 bytes")

    @classmethod
    def generate_secret(cls) -> bytes:
        return secrets.token_bytes(32)

    def sign(self, egress_ip: str, timestamp: float | None = None, nonce: str | None = None) -> Attestation:
        return self._attest(egress_ip, time.time() if timestamp is None else timestamp, nonce)

    def _attest(self, egress_ip: str, timestamp: float, nonce: str | None) -> Attestation:
        attestation = Attestation(
            egress_ip=egress_ip,
            timestamp=format_timestamp(timestamp),
            nonce=nonce or secrets.token_urlsafe(16),
            signature="",
        )
        digest = hmac.new(self.secret, attestation.canonical_payload(), hashlib.sha256).digest()
        return Attestation(
            egress_ip=attestation.egress_ip,
            timestamp=attestation.timestamp,
            nonce=attestation.nonce,
            signature=base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
        )

    def to_json(self, attestation: Attestation) -> bytes:
        return json.dumps(
            {
                "egress_ip": attestation.egress_ip,
                "ts": attestation.timestamp,
                "nonce": attestation.nonce,
                "signature": attestation.signature,
                "algorithm": attestation.algorithm,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")


@dataclass
class Gate:
    """Client side: fetches an attestation and decides whether to believe it."""

    secret: bytes
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    local_addresses: tuple[str, ...] = ()
    _seen_nonces: set[str] = field(default_factory=set)

    # -- parsing -----------------------------------------------------------

    def parse(self, raw: bytes) -> Attestation:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise GateError(f"attestation is not JSON: {exc}") from exc
        try:
            attestation = Attestation(
                egress_ip=str(doc["egress_ip"]),
                timestamp=str(doc["ts"]),
                nonce=str(doc["nonce"]),
                signature=str(doc["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError(f"attestation missing a field: {exc}") from exc
        if doc.get("algorithm", ALGORITHM) != ALGORITHM:
            raise GateError(f"unsupported algorithm {doc.get('algorithm')!r}")
        return attestation

    # -- the checks --------------------------------------------------------

    def check_signature(self, attestation: Attestation) -> tuple[bool, str]:
        expected = hmac.new(
            self.secret, attestation.canonical_payload(), hashlib.sha256
        ).digest()
        provided = base64.urlsafe_b64encode(expected).decode("ascii").rstrip("=")
        # constant-time compare, and on the padded forms so length differences
        # do not leak through the short-circuit in compare_digest
        ok = hmac.compare_digest(provided, attestation.signature)
        return ok, "signature matches" if ok else "signature does not match (forged or replayed body)"

    def check_freshness(self, attestation: Attestation, now: float | None = None) -> tuple[bool, str]:
        now = time.time() if now is None else now
        age = now - attestation.timestamp_seconds
        if age > self.window_seconds:
            return False, f"attestation is {age:.1f}s old, window is {self.window_seconds:.0f}s"
        if age < -self.window_seconds:
            return False, f"attestation is dated {abs(age):.1f}s in the future"
        if attestation.nonce in self._seen_nonces:
            return False, f"nonce {attestation.nonce[:8]}… was already accepted (replay)"
        return True, f"fresh, {age:.1f}s old, nonce unseen"

    def check_egress(self, attestation: Attestation) -> tuple[bool, str]:
        ip_text = attestation.egress_ip
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError:
            return False, f"server reported a non-address {ip_text!r}"
        if not addr.is_global:
            return False, f"egress {ip_text} is not globally routable"
        if ip_text in self.local_addresses:
            return False, f"egress {ip_text} is one of our own local addresses"
        return True, f"egress {ip_text} is a public address we do not own"

    # -- the whole verdict -------------------------------------------------

    def verify(
        self,
        raw: bytes,
        now: float | None = None,
        latency_ms: float = 0.0,
        http_status: int | None = None,
        commit_nonce: bool = True,
    ) -> GateVerdict:
        """Run every check. Order matters: signature gates the rest."""
        status_ok = http_status is None or 200 <= http_status < 300
        checks: list[tuple[str, bool, str]] = [
            ("http-status", status_ok, f"status={http_status}"),
        ]
        try:
            attestation = self.parse(raw)
        except GateError as exc:
            checks.append(("attestation", False, str(exc)))
            return GateVerdict(False, tuple(checks), http_status, latency_ms)

        sig_ok, sig_note = self.check_signature(attestation)
        checks.append(("signature", sig_ok, sig_note))
        if not sig_ok:
            # Do not evaluate anything else against an unsigned body: a forger
            # controls every other field.
            return GateVerdict(False, tuple(checks), http_status, latency_ms)

        fresh_ok, fresh_note = self.check_freshness(attestation, now=now)
        checks.append(("freshness", fresh_ok, fresh_note))
        egress_ok, egress_note = self.check_egress(attestation)
        checks.append(("egress", egress_ok, egress_note))

        passed = all(ok for _, ok, _ in checks)
        if passed and commit_nonce:
            self._seen_nonces.add(attestation.nonce)
        return GateVerdict(passed, tuple(checks), http_status, latency_ms)

    def verify_status_only(self, http_status: int, latency_ms: float = 0.0) -> GateVerdict:
        """The weak check, kept so callers can see why it is weak in the report."""
        ok = 200 <= http_status < 300
        note = (
            "status alone is not evidence: a local middlebox can synthesise it"
            if ok
            else f"status={http_status}"
        )
        return GateVerdict(ok, (("http-status", ok, note),), http_status, latency_ms)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

Opener = Callable[[urllib.request.Request, float], tuple[int, bytes]]


def _default_opener(request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as handle:
            return handle.status, handle.read()
    except urllib.error.HTTPError as exc:  # a 4xx/5xx is still a result worth reporting
        return exc.code, exc.read()


def probe(
    gate: Gate,
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    opener: Opener | None = None,
    user_agent: str = "Hyperion/1.0",
) -> GateVerdict:
    """Fetch an attestation from ``url`` and verify it."""
    do_open = opener or _default_opener
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    started = time.perf_counter()
    status, raw = do_open(request, timeout)
    latency_ms = (time.perf_counter() - started) * 1000.0
    return gate.verify(raw, latency_ms=latency_ms, http_status=status)


def tcp_probe(host: str, port: int, timeout: float = 5.0) -> tuple[bool, str]:
    """Weak liveness signal only: can we even complete a TCP handshake?

    A successful handshake here means nothing on its own -- a middlebox will
    happily complete one.  It is reported alongside the attested verdict so a
    "TCP fine, attestation forged" pair is visible, which is the signature of
    local termination.
    """
    import socket

    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - started) * 1000.0
            return True, f"tcp handshake to {host}:{port} in {elapsed:.0f}ms"
    except OSError as exc:
        return False, f"tcp to {host}:{port} failed: {exc}"


__all__ = [
    "ALGORITHM",
    "DEFAULT_TIMEOUT",
    "DEFAULT_WINDOW_SECONDS",
    "Attestation",
    "Attestor",
    "format_timestamp",
    "Gate",
    "GateError",
    "GateVerdict",
    "probe",
    "tcp_probe",
    "tls_record",
]
