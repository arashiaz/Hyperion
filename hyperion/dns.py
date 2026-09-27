"""DNS over HTTPS (RFC 8484) client plus Iranian fake-DNS / hijack detection.

Why this module exists
----------------------
On Iranian mobile and fixed networks the operator's resolver routinely returns
either NXDOMAIN or a sinkhole address for blocked domains.  Two sinkhole
addresses are observed constantly enough to be treated as known-bad:
``10.10.34.35`` and ``10.10.34.36`` (carrier-grade NAT space, RFC 6598).  A
resolver that hands one of those back is not broken, it is *injected*; and a
resolver that answers ``google.com`` with an address inside RFC 1918 is doing
the same thing with a private sinkhole.

This module therefore does two independent jobs:

1. Talk DoH directly to a resolver of our choosing, in the wire format of
   RFC 8484 (``application/dns-message`` over HTTPS POST) with a JSON
   (``application/dns-json``) fallback, bypassing whatever the ISP's resolver
   is configured to do.
2. Score every resolver it meets and rank them, so the orchestrator can pick a
   trustworthy one and *prove* the choice rather than assume it.

The module never touches the network at import time and every network function
takes an injectable opener, which is what makes it unit-testable offline.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import socket
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

# ---------------------------------------------------------------------------
# DNS wire format
# ---------------------------------------------------------------------------

QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DNS_MESSAGE_MEDIA_TYPE = "application/dns-message"
DNS_JSON_MEDIA_TYPE = "application/dns-json"

#: Transaction id stamped on every query so a forged reply can be caught.
QUERY_ID = 0x4859  # "HY" for Hyperion

# Sinkhole / hijack indicators.
KNOWN_SINKHOLES: frozenset[str] = frozenset({"10.10.34.35", "10.10.34.36"})
NXDOMAIN_PROBE_DOMAIN = "this-domain-does-not-exist-hyperion.invalid"

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; DoH/1.0)"


class DnsError(ValueError):
    """Malformed DNS message."""


@dataclass(frozen=True)
class DnsAnswer:
    """One answer RR, with only the fields we care about."""

    name: str
    rtype: int
    data: str


@dataclass(frozen=True)
class DnsResponse:
    id: int
    flags: int
    rcode: int
    answers: tuple[DnsAnswer, ...]

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")

    @property
    def addresses(self) -> tuple[str, ...]:
        return tuple(a.data for a in self.answers if a.rtype in (QTYPE_A, QTYPE_AAAA))


# ---------------------------------------------------------------------------
# Encoding / decoding
# ---------------------------------------------------------------------------


def _encode_label(label: str) -> bytes:
    """Encode one DNS label, applying IDNA to anything non-ASCII.

    Persian and Arabic domains are the common case for this project's users, so
    ``مثال.ir`` must go out as its Punycode form rather than raising.
    """
    try:
        return label.encode("ascii")
    except UnicodeEncodeError:
        pass
    try:
        return label.encode("idna")
    except UnicodeError as exc:
        raise DnsError(f"label {label!r} is not a valid internationalised name") from exc


def _split_name(name: str) -> list[str]:
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        raise DnsError("empty domain name")
    return labels


def encode_query(name: str, qtype: int = QTYPE_A, rd: bool = True, qid: int | None = None) -> bytes:
    """Build a minimal DNS query message."""
    if qid is None:
        qid = QUERY_ID
    flags = 0x0100 if rd else 0x0000
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(encoded)]) + encoded for encoded in (_encode_label(label) for label in _split_name(name))
    )
    return header + qname + b"\x00" + struct.pack(">HH", qtype, 1)


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    consumed = 0
    seen: set[int] = set()
    pos = offset
    while True:
        if pos >= len(msg):
            raise DnsError("name runs past the end of the message")
        length = msg[pos]
        if length == 0:
            pos += 1
            if not jumped:
                consumed = pos - offset
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise DnsError("truncated compression pointer")
            pointer = struct.unpack(">H", msg[pos : pos + 2])[0] & 0x3FFF
            if not jumped:
                consumed = pos + 2 - offset
                jumped = True
            if pointer in seen or pointer >= len(msg):
                raise DnsError("compression pointer loop or out of range")
            seen.add(pointer)
            pos = pointer
            continue
        pos += 1
        label = msg[pos : pos + length]
        if len(label) != length:
            raise DnsError("label truncated")
        labels.append(label.decode("ascii", errors="replace"))
        pos += length
    if not jumped:
        consumed = pos - offset
    return ".".join(labels), consumed


def decode_response(msg: bytes) -> DnsResponse:
    """Decode a DNS message into the header plus its answer RRs."""
    if len(msg) < 12:
        raise DnsError("DNS message shorter than the 12-byte header")
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", msg[:12])
    rcode = flags & 0x000F
    pos = 12
    for _ in range(qdcount):
        _, size = _read_name(msg, pos)
        pos += size + 4
    answers: list[DnsAnswer] = []
    for _ in range(ancount + nscount + arcount):
        if pos >= len(msg):
            break
        name, size = _read_name(msg, pos)
        pos += size
        if pos + 10 > len(msg):
            break
        rtype, _klass, _ttl, rdlength = struct.unpack(">HHIH", msg[pos : pos + 10])
        pos += 10
        rdata = msg[pos : pos + rdlength]
        if len(rdata) != rdlength:
            raise DnsError("rdata truncated")
        pos += rdlength
        if rtype == QTYPE_A and len(rdata) == 4:
            answers.append(DnsAnswer(name, rtype, socket.inet_ntoa(rdata)))
        elif rtype == QTYPE_AAAA and len(rdata) == 16:
            answers.append(DnsAnswer(name, rtype, socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == QTYPE_CNAME:
            try:
                target, _ = _read_name(rdata, 0)
            except DnsError:
                target = ""
            answers.append(DnsAnswer(name, rtype, target))
        else:
            answers.append(DnsAnswer(name, rtype, binascii.hexlify(rdata).decode()))
    return DnsResponse(qid, flags, rcode, tuple(answers))


def b64url_param(msg: bytes) -> str:
    """``dns=`` query parameter encoding used by the JSON interface."""
    return base64.urlsafe_b64encode(msg).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# Hijack / sinkhole analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """Interpretation of a single DNS exchange."""

    poisoned: bool
    reasons: tuple[str, ...]

    def __bool__(self) -> bool:  # convenience: `if verdict:` == "is poisoned"
        return self.poisoned


def analyse_response(name: str, response: DnsResponse) -> Verdict:
    """Decide whether a DNS answer looks injected rather than authoritative."""
    reasons: list[str] = []
    for addr in response.addresses:
        if addr in KNOWN_SINKHOLES:
            reasons.append(f"known Iranian sinkhole {addr}")
            continue
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            reasons.append(f"non-routable answer {addr}")
    if name.endswith(".invalid") and response.rcode == 0 and response.addresses:
        reasons.append("resolved a name under .invalid, which must be NXDOMAIN")
    return Verdict(bool(reasons), tuple(reasons))


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Resolver:
    """A DNS resolver we can reach over DoH."""

    name: str
    address: str
    doh_url: str
    json_url: str | None = None

    @property
    def is_public(self) -> bool:
        try:
            return ipaddress.ip_address(self.address).is_global
        except ValueError:
            return False


#: Public resolvers reachable over DoH without an account.
PUBLIC_DOH_RESOLVERS: tuple[Resolver, ...] = (
    Resolver(
        name="cloudflare",
        address="1.1.1.1",
        doh_url="https://1.1.1.1/dns-query",
        json_url="https://1.1.1.1/dns-query",
    ),
    Resolver(
        name="cloudflare-secondary",
        address="1.0.0.1",
        doh_url="https://1.0.0.1/dns-query",
        json_url="https://1.0.0.1/dns-query",
    ),
    Resolver(
        name="google",
        address="8.8.8.8",
        doh_url="https://dns.google/dns-query",
        json_url="https://dns.google/resolve",
    ),
    Resolver(
        name="quad9",
        address="9.9.9.9",
        doh_url="https://dns.quad9.net/dns-query",
        json_url="https://dns.quad9.net/resolve",
    ),
)


@dataclass
class ResolverReport:
    """Everything we learned about one resolver in one probe round."""

    resolver: Resolver
    reachable: bool = False
    latency_ms: float = float("inf")
    rcode: int | None = None
    answers: tuple[str, ...] = ()
    poisoned: bool = False
    poison_reasons: tuple[str, ...] = ()
    transport: str = ""
    error: str = ""

    @property
    def trusted(self) -> bool:
        return self.reachable and not self.poisoned

    @property
    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode if self.rcode is not None else -1, "n/a")

    def ranking_key(self) -> tuple:
        """Lower sorts first. Poisoned and unreachable resolvers sort last."""
        return (0 if self.trusted else 1, self.latency_ms, self.resolver.name)

    def one_line(self) -> str:
        state = "OK" if self.trusted else ("POISONED" if self.poisoned else "UNREACHABLE")
        detail = self.error or "; ".join(self.poison_reasons) or f"rcode={self.rcode_name}"
        latency = "n/a" if self.latency_ms == float("inf") else f"{self.latency_ms:.0f}ms"
        return f"{self.resolver.name:<22} {state:<11} {latency:>7}  {detail}"


Opener = Callable[[urllib.request.Request, float], bytes]


def _default_opener(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as handle:
        return handle.read()


def _get(
    url: str, opener: Opener, timeout: float, accept: str, payload: bytes | None = None
) -> bytes:
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST" if payload is not None else "GET",
        headers={
            "Accept": accept,
            "User-Agent": DEFAULT_USER_AGENT,
            **({"Content-Type": DNS_MESSAGE_MEDIA_TYPE} if payload is not None else {}),
        },
    )
    return opener(request, timeout)


def _parse_json_response(raw: bytes) -> DnsResponse:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise DnsError(f"undecodable JSON DNS reply: {exc}") from exc
    rcode = int(doc.get("Status", 0))
    answers: list[DnsAnswer] = []
    for entry in doc.get("Answer", []) or []:
        answers.append(
            DnsAnswer(
                name=entry.get("name", ""),
                rtype=int(entry.get("type", QTYPE_A)),
                data=str(entry.get("data", "")),
            )
        )
    return DnsResponse(id=QUERY_ID, flags=(1 << 8) | rcode, rcode=rcode, answers=tuple(answers))


def resolve_doh(
    resolver: Resolver,
    name: str,
    qtype: int = QTYPE_A,
    timeout: float = 5.0,
    opener: Opener | None = None,
) -> DnsResponse:
    """Resolve ``name`` through ``resolver`` using RFC 8484, JSON as fallback."""
    do_open = opener or _default_opener
    query = encode_query(name, qtype)
    wire_failed = False
    try:
        raw = _get(resolver.doh_url, do_open, timeout, DNS_MESSAGE_MEDIA_TYPE, query)
        response = decode_response(raw)
        if response.id != QUERY_ID:
            raise DnsError(
                f"transaction id mismatch: sent 0x{QUERY_ID:04x}, got 0x{response.id:04x}"
            )
        return response
    except DnsError:
        # A structurally broken or forged reply is not a transport failure, so
        # the JSON interface would be queried with the same result.  Surface it.
        raise
    except Exception as wire_error:
        if not resolver.json_url:
            raise DnsError(
                f"wire-format query failed and no JSON fallback is configured "
                f"({type(wire_error).__name__}: {wire_error})"
            ) from wire_error
        try:
            raw = _get(
                f"{resolver.json_url}?name={name}&type={qtype}",
                do_open,
                timeout,
                DNS_JSON_MEDIA_TYPE,
            )
        except Exception as json_error:
            raise DnsError(
                f"both interfaces failed; wire: {type(wire_error).__name__}: {wire_error}; "
                f"json: {type(json_error).__name__}: {json_error}"
            ) from json_error
        return _parse_json_response(raw)


def probe_resolver(
    resolver: Resolver,
    probe_domain: str = "example.com",
    timeout: float = 5.0,
    opener: Opener | None = None,
) -> ResolverReport:
    """Measure one resolver: latency, reachability, and whether it lies."""
    report = ResolverReport(resolver=resolver)
    started = time.perf_counter()
    try:
        response = resolve_doh(resolver, probe_domain, timeout=timeout, opener=opener)
    except Exception as exc:  # noqa: BLE001 - any failure makes a resolver unusable
        report.error = f"{type(exc).__name__}: {exc}"
        report.transport = "failed"
        return report
    report.latency_ms = (time.perf_counter() - started) * 1000.0
    report.reachable = True
    report.rcode = response.rcode
    report.answers = response.addresses
    report.transport = "doh"
    verdict = analyse_response(probe_domain, response)
    report.poisoned = verdict.poisoned
    report.poison_reasons = verdict.reasons
    return report


def hunt(
    resolvers: Sequence[Resolver] = PUBLIC_DOH_RESOLVERS,
    probe_domain: str = "example.com",
    timeout: float = 5.0,
    opener: Opener | None = None,
) -> list[ResolverReport]:
    """Probe every resolver and return them ranked best-first."""
    reports = [
        probe_resolver(resolver, probe_domain=probe_domain, timeout=timeout, opener=opener)
        for resolver in resolvers
    ]
    reports.sort(key=ResolverReport.ranking_key)
    return reports


def pick_best(reports: Iterable[ResolverReport]) -> ResolverReport | None:
    """The best trusted resolver, or ``None`` if every one of them lies."""
    trusted = [report for report in reports if report.trusted]
    if not trusted:
        return None
    return min(trusted, key=ResolverReport.ranking_key)


def local_resolvers() -> list[str]:
    """Read the system's configured nameservers from ``/etc/resolv.conf``.

    Kept deliberately naive: the file format has not changed in 30 years and
    pulling in a dependency to read two lines is not worth it.
    """
    found: list[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        found.append(parts[1])
    except OSError:
        return found
    return found


__all__ = [
    "DNS_JSON_MEDIA_TYPE",
    "DNS_MESSAGE_MEDIA_TYPE",
    "KNOWN_SINKHOLES",
    "NXDOMAIN_PROBE_DOMAIN",
    "PUBLIC_DOH_RESOLVERS",
    "QUERY_ID",
    "QTYPE_A",
    "QTYPE_AAAA",
    "DnsAnswer",
    "DnsError",
    "DnsResponse",
    "Resolver",
    "ResolverReport",
    "Verdict",
    "analyse_response",
    "b64url_param",
    "decode_response",
    "encode_query",
    "hunt",
    "local_resolvers",
    "pick_best",
    "probe_resolver",
    "resolve_doh",
]
