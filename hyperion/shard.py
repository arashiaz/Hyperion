"""SHARD engine: send a ClientHello in pieces a DPI engine will not reassemble.

Two independent tricks live here and they compose:

``fragment_records``
    Split the ClientHello into several valid TLS records so that the
    ``server_name`` extension is alone in one of them.  A filter that parses a
    single record and gives up sees a ClientHello with no SNI at all.

``fragment_bytes``
    Cut an already-built byte string into TCP segments and pace them.  Cheap
    inline classifiers are usually per-packet: the first packet holds the
    record header and part of the handshake, the rest arrives later and never
    gets classified.

Both are byte-exact: ``b"".join(pieces) == original`` is asserted by the test
suite, because a fragmenter that quietly drops or reorders a byte turns a
censorship-evasion tool into a connection-breaker.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from . import tls_record
from .tls_record import (
    CONTENT_TYPE_HANDSHAKE,
    RECORD_HEADER_SIZE,
    ClientHello,
    FragmentPlan,
    TlsError,
    build_record,
    strip_server_name,
)

Sleeper = Callable[[float], None]


def _real_sleep(seconds: float) -> None:
    if seconds > 0:
        time.sleep(seconds)


@dataclass(frozen=True)
class ShardResult:
    pieces: tuple[bytes, ...]
    plan: FragmentPlan | None
    mode: str
    #: The handshake bytes the peer will reassemble.  Stored rather than derived
    #: because a byte-level split produces pieces that are not whole records.
    stream_payload: bytes = b""

    @property
    def stream(self) -> bytes:
        """Everything to put on the wire, in order."""
        return b"".join(self.pieces)

    @property
    def sizes(self) -> tuple[int, ...]:
        return tuple(len(p) for p in self.pieces)

    def describe(self) -> str:
        sizes = ",".join(str(s) for s in self.sizes)
        plan = self.plan.describe() if self.plan else "no record plan"
        return f"mode={self.mode} pieces=[{sizes}] {plan}"


def _record_payloads(pieces: Sequence[bytes]) -> bytes:
    return b"".join(tls_record.TlsRecord.parse(piece).payload for piece in pieces)


def fragment_records(
    client_hello: bytes,
    isolate_sni: bool = True,
) -> ShardResult:
    """Split a raw ClientHello record into record-aligned pieces."""
    record = tls_record.TlsRecord.parse(client_hello)
    if record.content_type != CONTENT_TYPE_HANDSHAKE:
        raise TlsError("fragment_records expects a handshake record")
    hello = ClientHello.parse(record.payload)
    pieces, plan = tls_record.split_client_hello(
        hello, legacy_version=record.legacy_version, isolate_sni=isolate_sni
    )
    return ShardResult(
        tuple(pieces), plan, mode="record-split", stream_payload=_record_payloads(pieces)
    )


def fragment_bytes(data: bytes, first: int, rest: int) -> tuple[bytes, ...]:
    """Cut ``data`` into TCP segments: ``first`` bytes, then ``rest`` at a time."""
    if first <= 0:
        raise TlsError("first segment must be at least one byte")
    if rest <= 0:
        raise TlsError("rest must be at least one byte")
    if first >= len(data):
        return (data,)
    pieces = [data[:first]]
    pieces.extend(data[i : i + rest] for i in range(first, len(data), rest))
    return tuple(pieces)


def fragment_client_hello_bytes(
    client_hello: bytes,
    first: int = RECORD_HEADER_SIZE + 1,
    rest: int = 1,
) -> ShardResult:
    """The folklore "5/94/1" shape, done correctly.

    The first segment carries the record header plus one payload byte, and the
    remainder is dribbled out one byte at a time.  Unlike a naive
    implementation this one validates the input first, so a caller cannot feed
    it a non-TLS buffer and get a plausible-looking stream of garbage.
    """
    record = tls_record.TlsRecord.parse(client_hello)
    if record.content_type != CONTENT_TYPE_HANDSHAKE:
        raise TlsError("fragment_client_hello_bytes expects a handshake record")
    ClientHello.parse(record.payload)  # validate before we start cutting
    pieces = fragment_bytes(client_hello, first=first, rest=rest)
    # A byte split changes no bytes, so the whole record -- and therefore the
    # whole handshake message inside it -- survives intact.
    return ShardResult(
        pieces,
        None,
        mode=f"byte-dribble first={first} rest={rest}",
        stream_payload=record.payload,
    )


def zero_sni_hello(client_hello: bytes) -> ShardResult:
    """Rebuild the ClientHello with the server_name extension removed entirely."""
    record = tls_record.TlsRecord.parse(client_hello)
    hello = ClientHello.parse(record.payload)
    rebuilt, new_hello = strip_server_name(hello, legacy_version=record.legacy_version)
    plan = FragmentPlan(
        record_sizes=(len(rebuilt),),
        splits=(),
        sni_record_index=None,
        reason="server_name extension removed; nothing to fragment",
    )
    assert new_hello.sni is None, "strip_server_name left an SNI behind"
    return ShardResult(
        (rebuilt,),
        plan,
        mode="zero-sni",
        stream_payload=tls_record.TlsRecord.parse(rebuilt).payload,
    )


def send_pieces(
    sock: socket.socket,
    pieces: Sequence[bytes],
    gap_seconds: float = 0.0,
    sleeper: Sleeper = _real_sleep,
) -> int:
    """Write ``pieces`` one at a time, optionally pausing between them."""
    total = 0
    for index, piece in enumerate(pieces):
        if index and gap_seconds:
            sleeper(gap_seconds)
        sock.sendall(piece)
        total += len(piece)
    return total


def best_strategy_for(hello: ClientHello) -> str:
    """Pick the strategy that fits the handshake we were given.

    ``zero-sni`` wins whenever the peer is addressed by IP or the caller has
    another way to prove identity, because there is then nothing left to
    classify.  Otherwise isolate the SNI extension in its own record.
    """
    if hello.sni is None:
        return "zero-sni"
    span = tls_record.sni_extension_span(hello)
    if span is None:
        return "zero-sni"
    sni_start, sni_end = span
    if sni_start <= RECORD_HEADER_SIZE:
        # SNI sits at the very front of the message: it cannot be isolated in a
        # later record, so drop it instead of pretending otherwise.
        return "zero-sni"
    return "isolate-sni"


def shard(
    client_hello: bytes,
    strategy: str | None = None,
    isolate_sni: bool = True,
) -> ShardResult:
    """One entry point: give it a ClientHello, get back the pieces to send."""
    hello = ClientHello.parse(tls_record.TlsRecord.parse(client_hello).payload)
    chosen = strategy or best_strategy_for(hello)
    if chosen == "zero-sni":
        return zero_sni_hello(client_hello)
    if chosen == "isolate-sni":
        return fragment_records(client_hello, isolate_sni=isolate_sni)
    if chosen == "byte-dribble":
        return fragment_client_hello_bytes(client_hello)
    if chosen == "none":
        return ShardResult(
            (client_hello,), None, mode="passthrough", stream_payload=hello.handshake_payload
        )
    raise TlsError(f"unknown sharding strategy {chosen!r}")


__all__ = [
    "ShardResult",
    "best_strategy_for",
    "build_record",
    "fragment_bytes",
    "fragment_client_hello_bytes",
    "fragment_records",
    "send_pieces",
    "shard",
    "zero_sni_hello",
]
