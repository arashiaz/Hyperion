"""Byte-accurate TLS 1.2/1.3 record handling, ClientHello parsing and fragmentation.

Design notes (read this before changing anything):

A TLS record on the wire is exactly 5 header bytes followed by ``length`` payload
bytes::

    octet 0      : content type   (22 == handshake)
    octets 1-2   : legacy version (0x0301 in practice, even for TLS 1.3)
    octets 3-4   : big-endian payload length (max 2**14 == 16384)

The legacy "shard the record at byte N" folklore is wrong: a DPI engine never
sees byte offsets, it reassembles the *handshake message* by following the
4-byte length field at the start of a ClientHello.  If you split the record at
an arbitrary offset the message simply continues in the next record and any
competent parser still recovers the SNI.  The only splits that actually defeat
such parsers are splits at a point where the parser must either buffer or give
up, i.e. inside the handshake message *and* before the SNI extension has been
seen.  :func:`split_client_hello` implements that rule and, unlike folklore
implementations, refuses to produce an invalid split instead of silently
emitting garbage.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

RECORD_HEADER_SIZE = 5
MAX_RECORD_PAYLOAD = 2 ** 14  # 16384, RFC 8446 §5.1
MAX_HANDSHAKE_PAYLOAD = 2 ** 24 - 1

CONTENT_TYPE_INVALID = 0
CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
CONTENT_TYPE_ALERT = 21
CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_APPLICATION_DATA = 23

HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2

# TLS 1.3 hides the real version in the record header and advertises it in the
# supported_versions extension instead.
LEGACY_VERSION_TLS10 = 0x0301
LEGACY_VERSION_TLS12 = 0x0303

EXT_SERVER_NAME = 0x0000
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PADDING = 0x0015

SNI_TYPE_HOST_NAME = 0


class TlsError(ValueError):
    """Raised when input bytes are not a well-formed TLS construct."""


class TlsIncomplete(TlsError):
    """Raised when a record is truncated (a normal condition on a socket)."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TlsRecord:
    """One TLS record: header plus payload."""

    content_type: int
    legacy_version: int
    payload: bytes

    @property
    def length(self) -> int:
        return len(self.payload)

    def to_bytes(self) -> bytes:
        if self.length > MAX_RECORD_PAYLOAD:
            raise TlsError(
                f"record payload {self.length} exceeds the {MAX_RECORD_PAYLOAD}-byte limit"
            )
        return (
            struct.pack(">BHH", self.content_type, self.legacy_version, self.length)
            + self.payload
        )

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> "TlsRecord":
        header = data[offset : offset + RECORD_HEADER_SIZE]
        if len(header) < RECORD_HEADER_SIZE:
            raise TlsIncomplete(
                f"need {RECORD_HEADER_SIZE} header bytes, have {len(header)}"
            )
        content_type, legacy_version, length = struct.unpack(">BHH", header)
        if length > MAX_RECORD_PAYLOAD:
            raise TlsError(f"declared record length {length} is illegal")
        payload = data[offset + RECORD_HEADER_SIZE : offset + RECORD_HEADER_SIZE + length]
        if len(payload) < length:
            raise TlsIncomplete(
                f"record declares {length} payload bytes, only {len(payload)} available"
            )
        return cls(content_type, legacy_version, payload)

    @classmethod
    def peek_length(cls, data: bytes) -> int | None:
        """Total on-the-wire size of the next record, or ``None`` if unknown."""
        if len(data) < RECORD_HEADER_SIZE:
            return None
        length = struct.unpack(">H", data[3:5])[0]
        if length > MAX_RECORD_PAYLOAD:
            raise TlsError(f"declared record length {length} is illegal")
        return RECORD_HEADER_SIZE + length


def iter_records(data: bytes) -> Iterator[TlsRecord]:
    """Yield every complete record in ``data``; trailing partial data is dropped."""
    offset = 0
    while offset < len(data):
        total = TlsRecord.peek_length(data[offset:])
        if total is None or offset + total > len(data):
            return
        yield TlsRecord.parse(data, offset)
        offset += total


def build_record(content_type: int, payload: bytes, legacy_version: int = LEGACY_VERSION_TLS10) -> bytes:
    return TlsRecord(content_type, legacy_version, payload).to_bytes()


# ---------------------------------------------------------------------------
# ClientHello parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Extension:
    ext_type: int
    body: bytes


@dataclass(frozen=True)
class ClientHello:
    """The fields of a ClientHello that matter for censorship analysis."""

    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: bytes
    compression_methods: bytes
    extensions: tuple[Extension, ...]
    handshake_payload: bytes = field(repr=False)

    # -- derived views -----------------------------------------------------

    @property
    def extension_types(self) -> tuple[int, ...]:
        return tuple(e.ext_type for e in self.extensions)

    def extension(self, ext_type: int) -> Extension | None:
        for ext in self.extensions:
            if ext.ext_type == ext_type:
                return ext
        return None

    @property
    def sni(self) -> str | None:
        """Server name from the server_name extension, or ``None`` if absent."""
        ext = self.extension(EXT_SERVER_NAME)
        if ext is None:
            return None
        return parse_server_name(ext.body)

    @property
    def advertised_tls_versions(self) -> tuple[int, ...]:
        """Versions the client actually offers (TLS 1.3 aware)."""
        ext = self.extension(EXT_SUPPORTED_VERSIONS)
        if ext is None:
            return (self.legacy_version,)
        body = ext.body
        if len(body) < 1:
            raise TlsError("empty supported_versions extension")
        count = body[0]
        versions = body[1 : 1 + count]
        if len(versions) != count or count % 2:
            raise TlsError("malformed supported_versions extension")
        return tuple(
            struct.unpack(">H", versions[i : i + 2])[0] for i in range(0, count, 2)
        )

    # -- parsing -----------------------------------------------------------

    @classmethod
    def parse(cls, payload: bytes) -> "ClientHello":
        """Parse the *payload of a handshake record* holding a ClientHello."""
        if len(payload) < 4:
            raise TlsIncomplete("handshake header truncated")
        msg_type = payload[0]
        if msg_type != HANDSHAKE_CLIENT_HELLO:
            raise TlsError(f"not a ClientHello (handshake type {msg_type})")
        (msg_len,) = struct.unpack(">I", b"\x00" + payload[1:4])
        body = payload[4 : 4 + msg_len]
        if len(body) < msg_len:
            raise TlsIncomplete(
                f"ClientHello declares {msg_len} bytes, only {len(body)} present"
            )
        if len(body) < 38:
            raise TlsIncomplete("ClientHello body truncated before cipher suites")

        pos = 0
        legacy_version = struct.unpack(">H", body[0:2])[0]
        random = body[2:34]
        pos = 34

        sid_len = body[pos]
        pos += 1
        session_id = body[pos : pos + sid_len]
        if len(session_id) != sid_len:
            raise TlsIncomplete("session_id truncated")
        pos += sid_len

        (cs_len,) = struct.unpack(">H", body[pos : pos + 2])
        pos += 2
        cipher_suites = body[pos : pos + cs_len]
        if len(cipher_suites) != cs_len or cs_len % 2:
            raise TlsIncomplete("cipher_suites truncated or malformed")
        pos += cs_len

        cm_len = body[pos]
        pos += 1
        compression_methods = body[pos : pos + cm_len]
        if len(compression_methods) != cm_len:
            raise TlsIncomplete("compression_methods truncated")
        pos += cm_len

        extensions: list[Extension] = []
        if pos + 2 <= len(body):
            (ext_total,) = struct.unpack(">H", body[pos : pos + 2])
            pos += 2
            end = pos + ext_total
            if end > len(body):
                raise TlsIncomplete("extensions block runs past the message")
            while pos + 4 <= end:
                ext_type, ext_len = struct.unpack(">HH", body[pos : pos + 4])
                pos += 4
                ext_body = body[pos : pos + ext_len]
                if len(ext_body) != ext_len:
                    raise TlsIncomplete(f"extension 0x{ext_type:04x} truncated")
                extensions.append(Extension(ext_type, ext_body))
                pos += ext_len

        return cls(
            legacy_version=legacy_version,
            random=random,
            session_id=session_id,
            cipher_suites=cipher_suites,
            compression_methods=compression_methods,
            extensions=tuple(extensions),
            handshake_payload=payload[: 4 + msg_len],
        )

    @classmethod
    def from_record_bytes(cls, data: bytes) -> "ClientHello":
        return cls.parse(TlsRecord.parse(data).payload)


def parse_server_name(ext_body: bytes) -> str | None:
    """Decode a server_name extension body (RFC 6066 §3)."""
    if len(ext_body) < 2:
        raise TlsError("server_name extension too short")
    (list_len,) = struct.unpack(">H", ext_body[0:2])
    entries = ext_body[2 : 2 + list_len]
    pos = 0
    while pos + 3 <= len(entries):
        name_type = entries[pos]
        name_len = struct.unpack(">H", entries[pos + 1 : pos + 3])[0]
        pos += 3
        name = entries[pos : pos + name_len]
        pos += name_len
        if name_type == SNI_TYPE_HOST_NAME:
            return name.decode("ascii", errors="replace")
    return None


def server_name_extension(host: str) -> Extension:
    encoded = host.encode("idna")
    entry = bytes([SNI_TYPE_HOST_NAME]) + struct.pack(">H", len(encoded)) + encoded
    body = struct.pack(">H", len(entry)) + entry
    return Extension(EXT_SERVER_NAME, body)


def serialize_extensions(extensions: Iterable[Extension]) -> bytes:
    out = bytearray()
    for ext in extensions:
        out += struct.pack(">HH", ext.ext_type, len(ext.body)) + ext.body
    return struct.pack(">H", len(out)) + bytes(out)


def build_client_hello(
    sni: str | None,
    cipher_suites: Sequence[int] = (0x1301, 0x1303, 0xC02B, 0xC02F),
    tls_versions: Sequence[int] = (0x0303, 0x0304),
    legacy_version: int = LEGACY_VERSION_TLS10,
    random_bytes: bytes | None = None,
    extra_extensions: Sequence[Extension] = (),
) -> bytes:
    """Build a real, valid ClientHello record.

    Used by the test suite to have something authentic to fragment, and by the
    diagnostic CLI to probe what a middlebox does to a handshake.  Deliberately
    small: no GREASE, no ALPN unless asked for, because every extra extension is
    another thing that can trip up a reassembling middlebox.
    """
    if random_bytes is None:
        random_bytes = bytes(range(32))
    if len(random_bytes) != 32:
        raise TlsError("random must be exactly 32 bytes")

    extensions: list[Extension] = list(extra_extensions)
    if sni:
        extensions.append(server_name_extension(sni))
    if tls_versions:
        body = bytes([2 * len(tls_versions)]) + b"".join(
            struct.pack(">H", v) for v in tls_versions
        )
        extensions.append(Extension(EXT_SUPPORTED_VERSIONS, body))

    cs_bytes = b"".join(struct.pack(">H", suite) for suite in cipher_suites)
    hello_body = (
        struct.pack(">H", LEGACY_VERSION_TLS12)
        + random_bytes
        + b"\x00"  # empty session id
        + struct.pack(">H", len(cs_bytes))
        + cs_bytes
        + b"\x01\x00"  # one compression method: null
        + serialize_extensions(extensions)
    )
    payload = (
        bytes([HANDSHAKE_CLIENT_HELLO])
        + struct.pack(">I", len(hello_body))[1:]
        + hello_body
    )
    return build_record(CONTENT_TYPE_HANDSHAKE, payload, legacy_version)


# ---------------------------------------------------------------------------
# Fragmentation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FragmentPlan:
    """How a ClientHello is going to be split, and why it is safe to do so."""

    record_sizes: tuple[int, ...]
    splits: tuple[int, ...]
    sni_record_index: int | None
    reason: str

    @property
    def sni_is_isolated(self) -> bool:
        """True when the SNI extension lands in a record of its own.

        That is the property that defeats a single-record DPI parser: it must
        buffer across a record boundary or drop the flow, and in practice the
        cheap inline filters do the latter.
        """
        return self.sni_record_index is not None

    def describe(self) -> str:
        sizes = ",".join(str(s) for s in self.record_sizes)
        return f"[{sizes}] {self.reason}"


def first_extension_offset(hello: ClientHello) -> int:
    """Offset of the extensions length field inside the handshake message."""
    pos = 1 + 3  # handshake type + 3-byte length
    pos += 2 + 32  # legacy version + random
    sid_len = hello.handshake_payload[pos]
    pos += 1 + sid_len
    (cs_len,) = struct.unpack(">H", hello.handshake_payload[pos : pos + 2])
    pos += 2 + cs_len
    cm_len = hello.handshake_payload[pos]
    pos += 1 + cm_len
    return pos


def sni_extension_span(hello: ClientHello) -> tuple[int, int] | None:
    """Absolute (start, end) of the server_name extension in the handshake message."""
    base = first_extension_offset(hello)
    (ext_total,) = struct.unpack(">H", hello.handshake_payload[base : base + 2])
    pos = base + 2
    end = base + 2 + ext_total
    for ext in hello.extensions:
        width = 4 + len(ext.body)
        if ext.ext_type == EXT_SERVER_NAME:
            return pos, pos + width
        pos += width
        if pos > end:
            raise TlsError("extension walk overran the extensions block")
    return None


def split_client_hello(
    hello: ClientHello,
    legacy_version: int = LEGACY_VERSION_TLS10,
    isolate_sni: bool = True,
) -> tuple[list[bytes], FragmentPlan]:
    """Fragment a ClientHello into several *individually valid* TLS records.

    Every output record carries a correct 5-byte header and a correct declared
    length, so the concatenation is a byte-for-byte valid TLS 1.2 stream that a
    real server reassembles without noticing.  When ``isolate_sni`` is set and a
    server_name extension exists, the split points are chosen so the SNI bytes
    end up alone in one record.

    Raises :class:`TlsError` rather than emitting a broken split.
    """
    payload = hello.handshake_payload
    if len(payload) > MAX_HANDSHAKE_PAYLOAD:
        raise TlsError("ClientHello too large to fragment")

    span = sni_extension_span(hello)
    if span is None:
        # Nothing to hide: still emit one well-formed record so callers can use
        # this as a generic record writer.
        return [build_record(CONTENT_TYPE_HANDSHAKE, payload, legacy_version)], FragmentPlan(
            record_sizes=(RECORD_HEADER_SIZE + len(payload),),
            splits=(),
            sni_record_index=None,
            reason="no server_name extension present; nothing to isolate",
        )

    sni_start, sni_end = span
    if not isolate_sni:
        # Cut once, just before the SNI extension.
        cut = sni_start
        if cut <= 0 or cut >= len(payload):
            raise TlsError("cannot split before the server_name extension")
        parts = [payload[:cut], payload[cut:]]
        plan = FragmentPlan(
            record_sizes=tuple(RECORD_HEADER_SIZE + len(p) for p in parts),
            splits=(cut,),
            sni_record_index=1,
            reason="single split immediately before server_name",
        )
        return [build_record(CONTENT_TYPE_HANDSHAKE, p, legacy_version) for p in parts], plan

    # Isolate the SNI extension in a record of its own: [.. pre ..][sni][.. post ..]
    chunks: list[bytes] = []
    sni_record_index = 0
    cursor = 0
    for boundary in (sni_start, sni_end):
        if boundary > cursor:
            if cursor == 0 and boundary <= RECORD_HEADER_SIZE:
                raise TlsError(
                    "server_name extension sits inside the handshake header; cannot isolate"
                )
            chunks.append(payload[cursor:boundary])
            cursor = boundary
    if cursor < len(payload):
        chunks.append(payload[cursor:])
    if not any(chunks):
        raise TlsError("degenerate split produced empty records")
    sni_record_index = next(
        i for i, chunk in enumerate(chunks) if payload[sni_start:sni_end] == chunk
    )
    plan = FragmentPlan(
        record_sizes=tuple(RECORD_HEADER_SIZE + len(c) for c in chunks),
        splits=(sni_start, sni_end),
        sni_record_index=sni_record_index,
        reason=f"server_name extension isolated in record #{sni_record_index}",
    )
    return [build_record(CONTENT_TYPE_HANDSHAKE, c, legacy_version) for c in chunks], plan


def strip_server_name(hello: ClientHello, legacy_version: int = LEGACY_VERSION_TLS10) -> tuple[bytes, ClientHello]:
    """Rebuild a ClientHello with the server_name extension removed.

    This is what a Zero-SNI client actually sends: no SNI at all, so there is
    nothing for an SNI filter to match.  The returned record is a complete,
    valid ClientHello; the second element is the rewritten hello for inspection.
    """
    kept = [e for e in hello.extensions if e.ext_type != EXT_SERVER_NAME]
    pos = first_extension_offset(hello)
    prefix = hello.handshake_payload[:pos]
    body = prefix + serialize_extensions(kept)
    # Rewrite the 3-byte handshake length to match the new body length.
    body_len = len(body) - 4
    if body_len < 0 or body_len > MAX_HANDSHAKE_PAYLOAD:
        raise TlsError("rewritten ClientHello has an illegal length")
    body = bytes([HANDSHAKE_CLIENT_HELLO]) + struct.pack(">I", body_len)[1:] + body[4:]
    record = build_record(CONTENT_TYPE_HANDSHAKE, body, legacy_version)
    return record, ClientHello.parse(body)


def looks_like_tls(data: bytes) -> bool:
    """Cheap pre-filter used to tell a real peer from an injected middlebox."""
    if len(data) < RECORD_HEADER_SIZE:
        return False
    if data[0] not in (
        CONTENT_TYPE_CHANGE_CIPHER_SPEC,
        CONTENT_TYPE_ALERT,
        CONTENT_TYPE_HANDSHAKE,
        CONTENT_TYPE_APPLICATION_DATA,
    ):
        return False
    total = TlsRecord.peek_length(data)
    return total is not None and data[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03")


def sni_in_bytes(data: bytes) -> str | None:
    """Best-effort SNI extraction straight from a raw byte buffer."""
    try:
        record = TlsRecord.parse(data)
        if record.content_type != CONTENT_TYPE_HANDSHAKE:
            return None
        return ClientHello.parse(record.payload).sni
    except TlsError:
        return None


def is_public_address(text: str) -> bool:
    """True for a routable, globally reachable address."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return addr.is_global


__all__ = [
    "ClientHello",
    "Extension",
    "FragmentPlan",
    "TlsError",
    "TlsIncomplete",
    "TlsRecord",
    "CONTENT_TYPE_ALERT",
    "CONTENT_TYPE_APPLICATION_DATA",
    "CONTENT_TYPE_HANDSHAKE",
    "EXT_PADDING",
    "EXT_SERVER_NAME",
    "EXT_SUPPORTED_VERSIONS",
    "HANDSHAKE_CLIENT_HELLO",
    "LEGACY_VERSION_TLS10",
    "LEGACY_VERSION_TLS12",
    "MAX_RECORD_PAYLOAD",
    "RECORD_HEADER_SIZE",
    "build_client_hello",
    "build_record",
    "first_extension_offset",
    "is_public_address",
    "iter_records",
    "looks_like_tls",
    "parse_server_name",
    "serialize_extensions",
    "server_name_extension",
    "sni_extension_span",
    "sni_in_bytes",
    "split_client_hello",
    "strip_server_name",
]
