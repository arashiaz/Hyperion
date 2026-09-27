"""AmneziaWG packet obfuscation: junk packets, mutated magic headers, padding.

Provenance
----------
The wire behaviour here is ported from the upstream implementation, not guessed.
Every constant and formula below is traceable:

* junk packet sizing ``len = jmin + rand(jmax - jmin)`` with ``jc`` packets --
  ``amnezia-vpn/amneziawg-go`` ``device/noise-protocol.go``, ``Device.JunkPackets()``.
* the obfuscation tags ``<b> <t> <r> <rc> <rd> <d> <ds> <dz>`` --
  ``device/obf.go`` and its ``obf_*.go`` files.
* the configuration key names ``jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1..i5
  header_protection_key content_padding_addition rekey_after_time rekey_timeout
  reject_after_time keepalive_timeout max_handshake_attempts random_trailers
  disable_cookies`` -- ``device/uapi.go``.
* the ``.conf`` key names ``Jc Jmin Jmax S1..S4 H1..H4 I1..I5
  HeaderProtectionKey …`` -- ``amnezia-vpn/amnezia-client``
  ``client/server_scripts/awg/template.conf``.

What this module deliberately does **not** do is invent default magic header
values.  Upstream picks them per deployment; a hard-coded "0xdb2e…" default
would only match whoever wrote it and would silently fail against every real
server.  Omitting a header keeps the stock WireGuard value, which is the
correct behaviour for a config that does not set it.

Scope: this is the *packet-framing* layer.  The X25519/ChaCha20-Poly1305 Noise
handshake itself is out of scope -- on a phone that is the kernel module's job.
"""

from __future__ import annotations

import base64
import configparser
import io
import random
import struct
from dataclasses import dataclass, field
from typing import Iterable, Sequence

# Stock WireGuard handshake message type bytes.  AmneziaWG replaces these with
# per-deployment "magic headers" H1..H4 so a filter matching on the first four
# bytes of a WireGuard handshake no longer finds anything.
STOCK_HANDSHAKE_INITIATION = 1
STOCK_HANDSHAKE_RESPONSE = 2
STOCK_HANDSHAKE_COOKIE_REPLY = 3
STOCK_TRANSPORT_DATA = 4

HEADER_INIT = "h1"
HEADER_RESPONSE = "h2"
HEADER_COOKIE = "h3"
HEADER_TRANSPORT = "h4"

OBF_TAGS = ("b", "t", "r", "rc", "rd", "d", "ds", "dz")

HEADER_PROTECTION_KEY_BYTES = 32
HEADER_PROTECTION_NONCE_BYTES = 12

#: Largest UDP payload we are willing to build.
MAX_PACKET_SIZE = 65507

_CHARS52 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class AmneziaConfigError(ValueError):
    """Raised when a config is internally inconsistent."""


# ---------------------------------------------------------------------------
# Integer ranges ("123" or "100-200")
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UintRange:
    lo: int
    hi: int

    def __post_init__(self) -> None:
        if self.hi < self.lo:
            raise AmneziaConfigError(f"range {self.lo}-{self.hi} is inverted")
        for value in (self.lo, self.hi):
            if not 0 <= value <= 0xFFFFFFFF:
                raise AmneziaConfigError(f"{value} does not fit in uint32")

    @classmethod
    def parse(cls, text: str) -> "UintRange":
        text = text.strip()
        if "-" in text:
            lo_text, hi_text = text.split("-", 1)
            lo = _parse_maybe_hex(lo_text)
            hi = _parse_maybe_hex(hi_text)
        else:
            lo = hi = _parse_maybe_hex(text)
        return cls(lo, hi)

    def pick(self, rng: random.Random | None = None) -> int:
        rand = rng or random
        return rand.randint(self.lo, self.hi)

    def __str__(self) -> str:
        if self.lo == self.hi:
            return str(self.lo)
        return f"{self.lo}-{self.hi}"


def _parse_maybe_hex(text: str) -> int:
    text = text.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    if all(c in "0123456789abcdefABCDEF" for c in text) and any(
        c in "abcdefABCDEF" for c in text
    ):
        return int(text, 16)
    return int(text)


# ---------------------------------------------------------------------------
# Obfuscation chains  (<tag value> …)
# ---------------------------------------------------------------------------


def parse_obf_spec(spec: str) -> list[tuple[str, str]]:
    """Parse an ``i1``-style spec such as ``<b 0xdead><r 8><d>`` into tags."""
    if not spec:
        return []
    out: list[tuple[str, str]] = []
    remaining = spec
    while True:
        start = remaining.find("<")
        if start == -1:
            break
        end = remaining.find(">", start)
        if end == -1:
            raise AmneziaConfigError(f"missing closing '>' in obfuscation spec {spec!r}")
        tag = remaining[start + 1 : end].split()
        if not tag:
            raise AmneziaConfigError(f"empty tag in obfuscation spec {spec!r}")
        key = tag[0]
        if key not in OBF_TAGS:
            raise AmneziaConfigError(f"unknown obfuscation tag <{key}>")
        value = tag[1] if len(tag) > 1 else ""
        out.append((key, value))
        remaining = remaining[end + 1 :]
    return out


def obf_render(spec: str, payload: bytes, rng: random.Random | None = None) -> bytes:
    """Apply an obfuscation chain to ``payload`` (the ``I1``..``I5`` mechanism)."""
    rand = rng or random
    out = bytearray()
    for key, value in parse_obf_spec(spec):
        if key == "b":
            raw = value[2:] if value.lower().startswith("0x") else value
            if not raw or len(raw) % 2:
                raise AmneziaConfigError(f"<b> needs an even number of hex digits, got {value!r}")
            out += bytes.fromhex(raw)
        elif key == "t":
            out += struct.pack(">Q", int(value) if value else 0)
        elif key == "r":
            out += bytes(rand.randrange(256) for _ in range(int(value)))
        elif key == "rc":
            out += bytes(ord(_CHARS52[rand.randrange(52)]) for _ in range(int(value)))
        elif key == "rd":
            out += bytes(ord(str(rand.randrange(10))) for _ in range(int(value)))
        elif key == "d":
            out += payload
        elif key == "ds":
            out += base64.b64encode(payload).rstrip(b"=")
        elif key == "dz":
            length = int(value)
            out += struct.pack(">Q", len(payload))[-length:] if length < 8 else (
                len(payload).to_bytes(length, "big")
            )
        else:  # pragma: no cover - parse_obf_spec already rejects unknown tags
            raise AmneziaConfigError(f"unknown obfuscation tag <{key}>")
    return bytes(out)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class AmneziaConfig:
    """The obfuscation half of an AmneziaWG interface configuration."""

    jc: int = 0
    jmin: int = 0
    jmax: int = 0
    s1: int = 0  # padding before a handshake initiation
    s2: int = 0  # padding before a handshake response
    s3: int = 0  # padding before a cookie reply
    s4: int = 0  # padding before transport data
    h1: UintRange | None = None
    h2: UintRange | None = None
    h3: UintRange | None = None
    h4: UintRange | None = None
    i1: str = ""
    i2: str = ""
    i3: str = ""
    i4: str = ""
    i5: str = ""
    header_protection_key: str = ""
    content_padding_addition: UintRange | None = None
    random_trailers: bool = False
    disable_cookies: bool = False

    # WireGuard fields kept so a full .conf can round-trip.
    private_key: str = ""
    address: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.jc and not (self.jmin and self.jmax):
            raise AmneziaConfigError("jc is set but jmin/jmax are not; junk size is undefined")
        if self.jmin > self.jmax:
            raise AmneziaConfigError(f"jmin {self.jmin} exceeds jmax {self.jmax}")
        if self.jmin and not self.jc:
            raise AmneziaConfigError("jmin is set but jc is 0; no junk packets would be sent")
        for name in ("s1", "s2", "s3", "s4"):
            if getattr(self, name) < 0:
                raise AmneziaConfigError(f"{name} cannot be negative")
        if self.header_protection_key:
            raw = _decode_key(self.header_protection_key)
            if len(raw) != HEADER_PROTECTION_KEY_BYTES:
                raise AmneziaConfigError(
                    f"header protection key must be {HEADER_PROTECTION_KEY_BYTES} bytes, got {len(raw)}"
                )
        for name in ("i1", "i2", "i3", "i4", "i5"):
            parse_obf_spec(getattr(self, name))

    # -- constructors ------------------------------------------------------

    @classmethod
    def from_conf(cls, text: str) -> "AmneziaConfig":
        """Parse an AmneziaWG ``.conf`` file (the ``[Interface]`` section)."""
        parser = configparser.ConfigParser(strict=False, interpolation=None)
        parser.optionxform = str  # keep H1 vs h1 exactly as written
        parser.read_string(text)
        if not parser.has_section("Interface"):
            raise AmneziaConfigError("config has no [Interface] section")
        section = {k.lower(): v.strip() for k, v in parser.items("Interface")}

        def num(key: str, default: int = 0) -> int:
            return int(section[key]) if key in section and section[key] else default

        def rng(key: str) -> UintRange | None:
            return UintRange.parse(section[key]) if section.get(key) else None

        return cls(
            jc=num("jc"),
            jmin=num("jmin"),
            jmax=num("jmax"),
            s1=num("s1"),
            s2=num("s2"),
            s3=num("s3"),
            s4=num("s4"),
            h1=rng("h1"),
            h2=rng("h2"),
            h3=rng("h3"),
            h4=rng("h4"),
            i1=section.get("i1", ""),
            i2=section.get("i2", ""),
            i3=section.get("i3", ""),
            i4=section.get("i4", ""),
            i5=section.get("i5", ""),
            header_protection_key=section.get("headerprotectionkey", ""),
            content_padding_addition=rng("contentpaddingaddition"),
            random_trailers=section.get("randomtrailers", "").lower() in ("1", "true"),
            disable_cookies=section.get("disablecookies", "").lower() in ("1", "true"),
            private_key=section.get("privatekey", ""),
            address=[a.strip() for a in section.get("address", "").split(",") if a.strip()],
            dns=[d.strip() for d in section.get("dns", "").split(",") if d.strip()],
        )

    @classmethod
    def from_uapi(cls, text: str) -> "AmneziaConfig":
        """Parse the ``key=value`` stream spoken by the wg(8) uapi socket."""
        section = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                section[key.strip().lower()] = value.strip()
        if not section:
            raise AmneziaConfigError("no key=value pairs found")
        return cls(
            jc=int(section.get("jc", 0)),
            jmin=int(section.get("jmin", 0)),
            jmax=int(section.get("jmax", 0)),
            s1=int(section.get("s1", 0)),
            s2=int(section.get("s2", 0)),
            s3=int(section.get("s3", 0)),
            s4=int(section.get("s4", 0)),
            h1=UintRange.parse(section["h1"]) if section.get("h1") else None,
            h2=UintRange.parse(section["h2"]) if section.get("h2") else None,
            h3=UintRange.parse(section["h3"]) if section.get("h3") else None,
            h4=UintRange.parse(section["h4"]) if section.get("h4") else None,
            i1=section.get("i1", ""),
            i2=section.get("i2", ""),
            i3=section.get("i3", ""),
            i4=section.get("i4", ""),
            i5=section.get("i5", ""),
            header_protection_key=section.get("header_protection_key", ""),
            content_padding_addition=(
                UintRange.parse(section["content_padding_addition"])
                if section.get("content_padding_addition")
                else None
            ),
            random_trailers=section.get("random_trailers", "") in ("1", "true"),
            disable_cookies=section.get("disable_cookies", "") in ("1", "true"),
        )

    # -- serialisation -----------------------------------------------------

    def to_conf_interface_lines(self) -> list[str]:
        """The obfuscation keys, in upstream template order."""
        lines: list[str] = []
        if self.private_key:
            lines.append(f"PrivateKey = {self.private_key}")
        if self.address:
            lines.append(f"Address = {', '.join(self.address)}")
        if self.dns:
            lines.append(f"DNS = {', '.join(self.dns)}")
        if self.jc:
            lines.append(f"Jc = {self.jc}")
        if self.jmin:
            lines.append(f"Jmin = {self.jmin}")
        if self.jmax:
            lines.append(f"Jmax = {self.jmax}")
        for key, value in (("S1", self.s1), ("S2", self.s2), ("S3", self.s3), ("S4", self.s4)):
            if value:
                lines.append(f"{key} = {value}")
        for key, value in (("H1", self.h1), ("H2", self.h2), ("H3", self.h3), ("H4", self.h4)):
            if value is not None:
                lines.append(f"{key} = {value}")
        for key, value in (
            ("I1", self.i1),
            ("I2", self.i2),
            ("I3", self.i3),
            ("I4", self.i4),
            ("I5", self.i5),
        ):
            if value:
                lines.append(f"{key} = {value}")
        if self.header_protection_key:
            lines.append(f"HeaderProtectionKey = {self.header_protection_key}")
        if self.content_padding_addition is not None:
            lines.append(f"ContentPaddingAddition = {self.content_padding_addition}")
        if self.random_trailers:
            lines.append("RandomTrailers = true")
        if self.disable_cookies:
            lines.append("DisableCookies = true")
        return lines

    def to_conf(self, peer: dict[str, str] | None = None) -> str:
        out = io.StringIO()
        out.write("[Interface]\n")
        for line in self.to_conf_interface_lines():
            out.write(line + "\n")
        if peer:
            out.write("\n[Peer]\n")
            for key, value in peer.items():
                out.write(f"{key} = {value}\n")
        return out.getvalue()

    def to_uapi(self) -> str:
        """Render as uapi ``key=value`` lines (only non-default keys, as upstream does)."""
        lines: list[str] = []
        if self.jc:
            lines.append(f"jc={self.jc}")
        if self.jmin:
            lines.append(f"jmin={self.jmin}")
        if self.jmax:
            lines.append(f"jmax={self.jmax}")
        for key, value in (("s1", self.s1), ("s2", self.s2), ("s3", self.s3), ("s4", self.s4)):
            if value:
                lines.append(f"{key}={value}")
        for key, value in (
            ("h1", self.h1),
            ("h2", self.h2),
            ("h3", self.h3),
            ("h4", self.h4),
        ):
            if value is not None:
                lines.append(f"{key}={value}")
        for key, value in (
            ("i1", self.i1),
            ("i2", self.i2),
            ("i3", self.i3),
            ("i4", self.i4),
            ("i5", self.i5),
        ):
            if value:
                lines.append(f"{key}={value}")
        if self.header_protection_key:
            lines.append(f"header_protection_key={self.header_protection_key}")
        if self.content_padding_addition is not None:
            lines.append(f"content_padding_addition={self.content_padding_addition}")
        if self.random_trailers:
            lines.append("random_trailers=true")
        if self.disable_cookies:
            lines.append("disable_cookies=true")
        return "\n".join(lines) + ("\n" if lines else "")

    def describe(self) -> str:
        return (
            f"jc={self.jc} jmin={self.jmin} jmax={self.jmax} "
            f"s1={self.s1} s2={self.s2} s3={self.s3} s4={self.s4} "
            f"h1={self.h1} h2={self.h2} h3={self.h3} h4={self.h4}"
        )


def _decode_key(text: str) -> bytes:
    text = text.strip()
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=False)
    except (ValueError, TypeError):
        raw = b""
    if len(raw) == HEADER_PROTECTION_KEY_BYTES:
        return raw
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise AmneziaConfigError(f"unparseable key {text!r}") from exc


# ---------------------------------------------------------------------------
# Packet construction
# ---------------------------------------------------------------------------


def junk_packets(count: int, jmin: int, jmax: int, rng: random.Random | None = None) -> list[bytes]:
    """``jc`` random-length junk datagrams, sized ``jmin + rand(jmax - jmin)``.

    Sent before the handshake so a flow's first packets look like nothing in
    particular.  Mirrors ``Device.JunkPackets()`` upstream.
    """
    if count <= 0:
        return []
    if jmin > jmax:
        raise AmneziaConfigError(f"jmin {jmin} exceeds jmax {jmax}")
    rand = rng or random
    spread = jmax - jmin
    return [
        bytes(
            rand.randrange(256)
            for _ in range(jmin + (rand.randrange(spread) if spread else 0))
        )
        for _ in range(count)
    ]


def header_magic(config: AmneziaConfig, message_type: int, rng: random.Random | None = None) -> bytes:
    """The 4-byte header a message of ``message_type`` must carry."""
    mapping = {
        STOCK_HANDSHAKE_INITIATION: config.h1,
        STOCK_HANDSHAKE_RESPONSE: config.h2,
        STOCK_HANDSHAKE_COOKIE_REPLY: config.h3,
        STOCK_TRANSPORT_DATA: config.h4,
    }
    if message_type not in mapping:
        raise AmneziaConfigError(f"unknown message type {message_type}")
    chosen = mapping[message_type]
    if chosen is None:
        # No override configured: keep the stock WireGuard type byte layout.
        return struct.pack("<I", message_type)
    return struct.pack(">I", chosen.pick(rng))


def padding_for(config: AmneziaConfig, message_type: int) -> int:
    return {
        STOCK_HANDSHAKE_INITIATION: config.s1,
        STOCK_HANDSHAKE_RESPONSE: config.s2,
        STOCK_HANDSHAKE_COOKIE_REPLY: config.s3,
        STOCK_TRANSPORT_DATA: config.s4,
    }[message_type]


def frame_packet(
    config: AmneziaConfig,
    message_type: int,
    body: bytes,
    rng: random.Random | None = None,
) -> bytes:
    """Build one obfuscated datagram: ``junk padding | magic header | body``."""
    rand = rng or random
    magic = header_magic(config, message_type, rand)
    padding_len = padding_for(config, message_type)
    padding = bytes(rand.randrange(256) for _ in range(padding_len))
    trailer = b""
    if config.random_trailers:
        trailer = bytes(rand.randrange(256) for _ in range(rand.randrange(1, 17)))
    packet = padding + magic + body + trailer
    if len(packet) > MAX_PACKET_SIZE:
        raise AmneziaConfigError(
            f"framed packet is {len(packet)} bytes, over the {MAX_PACKET_SIZE}-byte UDP limit"
        )
    return packet


def unframe_packet(
    config: AmneziaConfig, packet: bytes, message_type: int | None = None
) -> bytes | None:
    """Strip padding/magic from a received datagram; ``None`` if it is not ours.

    This is the receiving half of :func:`frame_packet`.  Random junk datagrams
    sent by the peer fall out here as ``None``, which is exactly the intended
    behaviour -- they are noise, not messages.
    """
    if message_type is None:
        for candidate in (
            STOCK_HANDSHAKE_INITIATION,
            STOCK_HANDSHAKE_RESPONSE,
            STOCK_HANDSHAKE_COOKIE_REPLY,
            STOCK_TRANSPORT_DATA,
        ):
            result = unframe_packet(config, packet, candidate)
            if result is not None:
                return result
        return None
    padding_len = padding_for(config, message_type)
    if len(packet) < padding_len + 4:
        return None
    magic = header_magic(config, message_type)
    if packet[padding_len : padding_len + 4] != magic:
        return None
    return packet[padding_len + 4 :]


def describe_flow(config: AmneziaConfig, rng: random.Random | None = None) -> list[str]:
    """Human-readable trace of the datagrams a connection start would emit."""
    rand = rng or random
    lines = [f"config: {config.describe()}"]
    for index, junk in enumerate(junk_packets(config.jc, config.jmin, config.jmax, rand), start=1):
        lines.append(f"datagram {index}: junk {len(junk)} bytes (random)")
    lines.append(
        f"datagram {config.jc + 1}: s1={config.s1} padding | "
        f"h1={header_magic(config, STOCK_HANDSHAKE_INITIATION, rand).hex()} | handshake initiation"
    )
    return lines


__all__ = [
    "HEADER_PROTECTION_KEY_BYTES",
    "MAX_PACKET_SIZE",
    "OBF_TAGS",
    "STOCK_HANDSHAKE_COOKIE_REPLY",
    "STOCK_HANDSHAKE_INITIATION",
    "STOCK_HANDSHAKE_RESPONSE",
    "STOCK_TRANSPORT_DATA",
    "AmneziaConfig",
    "AmneziaConfigError",
    "UintRange",
    "describe_flow",
    "frame_packet",
    "header_magic",
    "junk_packets",
    "obf_render",
    "padding_for",
    "parse_obf_spec",
    "unframe_packet",
]
