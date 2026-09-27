"""Byte-level tests for TLS record parsing and fragmentation."""

from __future__ import annotations

import struct

import pytest

from hyperion import tls_record
from hyperion.tls_record import (
    CONTENT_TYPE_HANDSHAKE,
    RECORD_HEADER_SIZE,
    ClientHello,
    TlsError,
    TlsIncomplete,
    TlsRecord,
    build_client_hello,
    build_record,
    iter_records,
    looks_like_tls,
    sni_in_bytes,
    split_client_hello,
    strip_server_name,
)


def hello(sni: str | None = "blocked.example.com") -> bytes:
    return build_client_hello(sni=sni)


class TestRecordParsing:
    def test_header_is_five_bytes(self):
        assert RECORD_HEADER_SIZE == 5

    def test_parse_round_trip(self):
        raw = hello()
        record = TlsRecord.parse(raw)
        assert record.content_type == CONTENT_TYPE_HANDSHAKE
        assert record.legacy_version == 0x0301
        assert record.to_bytes() == raw

    def test_declared_length_matches_payload(self):
        raw = hello()
        declared = struct.unpack(">H", raw[3:5])[0]
        record = TlsRecord.parse(raw)
        assert declared == record.length
        assert len(raw) == RECORD_HEADER_SIZE + declared

    def test_truncated_record_raises_incomplete_not_garbage(self):
        raw = hello()
        with pytest.raises(TlsIncomplete):
            TlsRecord.parse(raw[:-3])

    def test_oversized_declared_length_is_rejected(self):
        bogus = bytes([CONTENT_TYPE_HANDSHAKE, 0x03, 0x01, 0xFF, 0xFF]) + b"\x00" * 4
        with pytest.raises(TlsError):
            TlsRecord.parse(bogus)

    def test_iter_records_walks_a_concatenated_stream(self):
        a = build_record(CONTENT_TYPE_HANDSHAKE, b"first")
        b = build_record(CONTENT_TYPE_HANDSHAKE, b"second")
        payloads = [r.payload for r in iter_records(a + b + b"\x16\x03\x01\x00\x09par")]
        assert payloads == [b"first", b"second"]

    def test_rejects_a_record_payload_over_16k(self):
        with pytest.raises(TlsError):
            build_record(CONTENT_TYPE_HANDSHAKE, b"x" * (tls_record.MAX_RECORD_PAYLOAD + 1))


class TestClientHello:
    def test_sni_is_recovered(self):
        parsed = ClientHello.parse(TlsRecord.parse(hello("www.example.org")).payload)
        assert parsed.sni == "www.example.org"

    def test_absent_sni_is_none_not_empty_string(self):
        parsed = ClientHello.parse(TlsRecord.parse(hello(None)).payload)
        assert parsed.sni is None
        assert tls_record.EXT_SERVER_NAME not in parsed.extension_types

    def test_tls13_is_detected_via_supported_versions(self):
        record = TlsRecord.parse(hello())
        parsed = ClientHello.parse(record.payload)
        # RFC 8446 §5.1: the record header stays at TLS 1.0 for compatibility...
        assert record.legacy_version == 0x0301
        # ...while the ClientHello's own field says 1.2...
        assert parsed.legacy_version == 0x0303
        # ...and the real offer lives in supported_versions.
        assert 0x0304 in parsed.advertised_tls_versions

    def test_truncated_client_hello_is_incomplete(self):
        raw = hello()
        with pytest.raises(TlsIncomplete):
            ClientHello.parse(TlsRecord.parse(raw[:30]).payload)

    def test_sni_in_bytes_shortcut(self):
        assert sni_in_bytes(hello("a.test")) == "a.test"
        assert sni_in_bytes(hello(None)) is None
        assert sni_in_bytes(b"HTTP/1.1 403 Forbidden\r\n\r\n") is None

    def test_extension_span_points_at_the_real_bytes(self):
        parsed = ClientHello.parse(TlsRecord.parse(hello("sni.test")).payload)
        payload = parsed.handshake_payload
        start, end = tls_record.sni_extension_span(parsed)
        window = payload[start:end]
        # 0x0000 is the server_name extension type, big-endian, at the front.
        assert window[0:2] == b"\x00\x00"
        assert b"sni.test" in window
        assert b"sni.test" not in payload[:start]
        assert b"sni.test" not in payload[end:]


class TestFragmentation:
    def test_payloads_reassemble_byte_exactly(self):
        """Concatenating the record *payloads* must reproduce the original message.

        The raw bytes cannot be equal: splitting one record into N records adds
        N-1 extra 5-byte headers.  What has to survive is the handshake stream.
        """
        raw = hello()
        record = TlsRecord.parse(raw)
        pieces, plan = split_client_hello(ClientHello.parse(record.payload))
        assert b"".join(TlsRecord.parse(p).payload for p in pieces) == record.payload
        assert len(b"".join(pieces)) == len(raw) + 5 * (len(pieces) - 1)

    def test_every_piece_is_a_valid_record(self):
        raw = hello()
        pieces, _ = split_client_hello(ClientHello.parse(TlsRecord.parse(raw).payload))
        for piece in pieces:
            record = TlsRecord.parse(piece)  # raises if malformed
            assert record.content_type == CONTENT_TYPE_HANDSHAKE
            assert len(piece) == RECORD_HEADER_SIZE + record.length

    def test_sni_ends_up_alone_in_one_record(self):
        raw = hello("isolated.test")
        parsed = ClientHello.parse(TlsRecord.parse(raw).payload)
        pieces, plan = split_client_hello(parsed)
        assert plan.sni_is_isolated
        carrier = pieces[plan.sni_record_index]
        assert b"isolated.test" in carrier
        others = b"".join(p for i, p in enumerate(pieces) if i != plan.sni_record_index)
        assert b"isolated.test" not in others

    def test_a_single_record_parser_sees_no_sni_in_the_first_record(self):
        """This is the actual evasion property: parse only record #0."""
        raw = hello("invisible.test")
        pieces, plan = split_client_hello(ClientHello.parse(TlsRecord.parse(raw).payload))
        assert plan.sni_record_index != 0
        first = pieces[0]
        # A naive parser that only looks at the first record finds no SNI bytes.
        assert b"invisible.test" not in first

    def test_isolate_sni_false_gives_a_two_record_split(self):
        raw = hello("split.test")
        pieces, plan = split_client_hello(
            ClientHello.parse(TlsRecord.parse(raw).payload), isolate_sni=False
        )
        assert len(pieces) == 2
        assert len(plan.splits) == 1
        assert b"split.test" in pieces[1]
        record = TlsRecord.parse(raw)
        assert b"".join(TlsRecord.parse(p).payload for p in pieces) == record.payload

    def test_no_sni_means_nothing_to_isolate(self):
        raw = hello(None)
        pieces, plan = split_client_hello(ClientHello.parse(TlsRecord.parse(raw).payload))
        assert len(pieces) == 1
        assert plan.sni_record_index is None
        assert pieces[0] == raw, "with nothing to isolate the record passes through untouched"

    def test_declared_sizes_match_actual_piece_sizes(self):
        raw = hello("sizes.test")
        pieces, plan = split_client_hello(ClientHello.parse(TlsRecord.parse(raw).payload))
        assert plan.record_sizes == tuple(len(p) for p in pieces)


class TestZeroSni:
    def test_rewritten_hello_still_parses(self):
        raw = hello("drop.me")
        parsed = ClientHello.parse(TlsRecord.parse(raw).payload)
        record, rewritten = strip_server_name(parsed)
        assert rewritten.sni is None
        assert TlsRecord.parse(record).content_type == CONTENT_TYPE_HANDSHAKE

    def test_handshake_length_field_is_rewritten_not_just_the_bytes(self):
        raw = hello("drop.me")
        parsed = ClientHello.parse(TlsRecord.parse(raw).payload)
        record, _ = strip_server_name(parsed)
        body = TlsRecord.parse(record).payload
        declared = int.from_bytes(body[1:4], "big")
        assert declared == len(body) - 4, "length field must match the shortened body"

    def test_other_extensions_survive_the_rewrite(self):
        raw = hello("drop.me")
        parsed = ClientHello.parse(TlsRecord.parse(raw).payload)
        record, rewritten = strip_server_name(parsed)
        assert tls_record.EXT_SUPPORTED_VERSIONS in rewritten.extension_types
        assert rewritten.cipher_suites == parsed.cipher_suites
        assert rewritten.random == parsed.random
        assert tls_record.EXT_SERVER_NAME not in rewritten.extension_types

    def test_rewritten_record_is_shorter_by_exactly_the_sni_extension(self):
        raw = hello("drop.me")
        parsed = ClientHello.parse(TlsRecord.parse(raw).payload)
        start, end = tls_record.sni_extension_span(parsed)
        record, _ = strip_server_name(parsed)
        assert len(raw) - len(record) == (end - start)


class TestLooksLikeTls:
    @pytest.mark.parametrize(
        "blob",
        [
            hello(),
            build_record(23, b"\x17\x03\x03\x00\x05abcde"),
            build_record(21, b"\x02\x28"),  # alert: fatal, handshake_failure
        ],
    )
    def test_accepts_tls(self, blob):
        assert looks_like_tls(blob)

    @pytest.mark.parametrize(
        "blob",
        [
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            b"<html>blocked</html>",
            b"\x16\x03\x09\x00\x10",  # implausible version
            b"\x00\x01",
            b"",
        ],
    )
    def test_rejects_non_tls(self, blob):
        assert not looks_like_tls(blob)
