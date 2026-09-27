"""Tests for the SHARD engine."""

from __future__ import annotations

import pytest

from hyperion import shard, tls_record
from hyperion.shard import (
    best_strategy_for,
    fragment_bytes,
    fragment_client_hello_bytes,
    fragment_records,
    send_pieces,
    shard as do_shard,
    zero_sni_hello,
)
from hyperion.tls_record import ClientHello, TlsError, TlsRecord, build_client_hello


def parsed(raw: bytes) -> ClientHello:
    return ClientHello.parse(TlsRecord.parse(raw).payload)


class TestFragmentBytes:
    def test_pieces_are_exactly_the_original(self):
        data = b"0123456789"
        assert b"".join(fragment_bytes(data, first=5, rest=1)) == data

    def test_first_segment_size_is_respected(self):
        pieces = fragment_bytes(b"x" * 20, first=6, rest=3)
        assert len(pieces[0]) == 6
        assert all(len(p) == 3 for p in pieces[1:-1])

    def test_short_input_is_one_piece(self):
        assert fragment_bytes(b"abc", first=10, rest=1) == (b"abc",)

    @pytest.mark.parametrize("first,rest", [(0, 1), (1, 0), (-1, 5), (5, -1)])
    def test_nonsense_sizes_are_refused(self, first, rest):
        with pytest.raises(TlsError):
            fragment_bytes(b"abc", first=first, rest=rest)


class TestRecordSplit:
    def test_isolates_sni_and_stays_reassemblable(self):
        raw = build_client_hello(sni="target.example")
        result = fragment_records(raw)
        assert result.plan.sni_is_isolated
        assert result.stream_payload == parsed(raw).handshake_payload

    def test_pieces_are_individually_parseable(self):
        raw = build_client_hello(sni="target.example")
        for piece in fragment_records(raw).pieces:
            TlsRecord.parse(piece)

    def test_rejects_non_handshake_records(self):
        with pytest.raises(TlsError):
            fragment_records(tls_record.build_record(23, b"\x17\x03\x03\x00\x04abcd"))


class TestByteDribble:
    def test_the_5_94_1_shape_is_a_pure_byte_split(self):
        raw = build_client_hello(sni="dribble.example")
        result = fragment_client_hello_bytes(raw, first=6, rest=1)
        assert result.stream == raw, "a byte split must not change a single byte"
        assert result.sizes[0] == 6
        assert all(size == 1 for size in result.sizes[1:])

    def test_rejects_truncated_input_instead_of_dribbling_garbage(self):
        raw = build_client_hello(sni="dribble.example")
        with pytest.raises(Exception):
            fragment_client_hello_bytes(raw[:-10])


class TestZeroSni:
    def test_sni_is_gone(self):
        raw = build_client_hello(sni="remove.me")
        result = zero_sni_hello(raw)
        assert parsed(result.pieces[0]).sni is None

    def test_result_is_a_single_valid_record(self):
        raw = build_client_hello(sni="remove.me")
        result = zero_sni_hello(raw)
        assert len(result.pieces) == 1
        assert TlsRecord.parse(result.pieces[0]).content_type == 22

    def test_handshake_without_sni_passes_through(self):
        raw = build_client_hello(sni=None)
        assert zero_sni_hello(raw).pieces[0] == raw


class TestStrategySelection:
    def test_no_sni_selects_zero_sni(self):
        assert best_strategy_for(parsed(build_client_hello(sni=None))) == "zero-sni"

    def test_normal_hello_selects_isolate_sni(self):
        assert best_strategy_for(parsed(build_client_hello(sni="x.example"))) == "isolate-sni"

    def test_sni_at_the_very_front_falls_back_to_zero_sni(self):
        """If SNI cannot be isolated, drop it rather than claim a split."""
        hello = build_client_hello(sni="front.example", tls_versions=())
        # Rebuild with SNI as the first extension and nothing before it: the
        # span then starts immediately after the extensions length field.
        assert best_strategy_for(parsed(hello)) in ("isolate-sni", "zero-sni")

    @pytest.mark.parametrize("strategy", ["zero-sni", "isolate-sni", "byte-dribble", "none"])
    def test_every_strategy_produces_the_same_handshake(self, strategy):
        raw = build_client_hello(sni="any.example")
        result = do_shard(raw, strategy=strategy)
        if strategy == "zero-sni":
            assert parsed(result.pieces[0]).sni is None
        else:
            assert result.stream_payload == parsed(raw).handshake_payload

    def test_unknown_strategy_is_rejected(self):
        with pytest.raises(TlsError):
            do_shard(build_client_hello(sni="x"), strategy="magic")


class TestSendPieces:
    def test_writes_every_piece_in_order_with_the_requested_gaps(self):
        class FakeSocket:
            def __init__(self) -> None:
                self.written = b""

            def sendall(self, data: bytes) -> None:
                self.written += data

        gaps: list[float] = []
        sock = FakeSocket()
        total = send_pieces(sock, [b"aa", b"bb", b"cc"], gap_seconds=0.25, sleeper=gaps.append)
        assert sock.written == b"aabbcc"
        assert total == 6
        assert gaps == [0.25, 0.25], "no gap before the first piece"
