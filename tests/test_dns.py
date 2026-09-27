"""Tests for the DoH client and Iranian fake-DNS detection."""

from __future__ import annotations

import json
import socket

import pytest

from hyperion import dns
from hyperion.dns import (
    KNOWN_SINKHOLES,
    DnsError,
    Resolver,
    analyse_response,
    decode_response,
    encode_query,
    hunt,
    pick_best,
    probe_resolver,
    resolve_doh,
)

POISONED = Resolver("isp", "10.10.34.35", "https://isp.invalid/dns-query")
HONEST = Resolver(
    "honest",
    "1.1.1.1",
    "https://honest.invalid/dns-query",
    json_url="https://honest.invalid/resolve",
)


def wire_answer(name: str, ip: str, rcode: int = 0) -> bytes:
    """Build a minimal DNS response with one A record."""
    header = (
        (0x4859).to_bytes(2, "big")
        + (0x8180 | rcode).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + (1 if rcode == 0 else 0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + (0).to_bytes(2, "big")
    )
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    question = qname + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
    answer = b""
    if rcode == 0:
        answer = (
            b"\xc0\x0c"
            + (1).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (300).to_bytes(4, "big")
            + (4).to_bytes(2, "big")
            + socket.inet_aton(ip)
        )
    return header + question + answer


class TestWireFormat:
    def test_query_is_well_formed(self):
        query = encode_query("example.com")
        # 12-byte header + 13-byte encoded qname + root label + 4-byte QTYPE/QCLASS
        assert len(query) == 12 + 13 + 1 + 4 - 1
        qid, flags, qd, an, ns, ar = __import__("struct").unpack(">HHHHHH", query[:12])
        assert (qid, flags, qd, an, ns, ar) == (dns.QUERY_ID, 0x0100, 1, 0, 0, 0)
        assert query[12] == 7 and query[13:20] == b"example"

    def test_encode_decode_round_trip(self):
        query = encode_query("example.com")
        response = decode_response(wire_answer("example.com", "93.184.216.34"))
        assert response.rcode == 0
        assert response.addresses == ("93.184.216.34",)
        assert query[0:2] == (dns.QUERY_ID).to_bytes(2, "big")

    def test_nxdomain_has_no_answers(self):
        response = decode_response(wire_answer("nope.example", "0.0.0.0", rcode=3))
        assert response.rcode == 3
        assert response.rcode_name == "NXDOMAIN"
        assert response.addresses == ()

    def test_truncated_message_is_an_error_not_a_guess(self):
        with pytest.raises(DnsError):
            decode_response(b"\x00" * 5)

    def test_a_compression_pointer_past_the_end_is_rejected(self):
        # Answer section starts at offset 29; make its name point beyond the
        # message, which is the shape a truncating middlebox produces.
        header = (0x4859).to_bytes(2, "big") + (0x8180).to_bytes(2, "big") + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        question = b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        bogus = b"\xc0\xff" + b"\x00\x05\x00\x01" + (300).to_bytes(4, "big") + (2).to_bytes(2, "big") + b"\xc0\x0c"
        with pytest.raises(DnsError, match="out of range"):
            decode_response(header + question + bogus)

    def test_a_compression_pointer_that_revisits_itself_is_rejected(self):
        # Two answers that point at each other: following either one loops.
        header = (0x4859).to_bytes(2, "big") + (0x8180).to_bytes(2, "big") + b"\x00\x01\x00\x02\x00\x00\x00\x00"
        question = b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        # Answers start at 29; each answer is 14 bytes, so the second starts at 43.
        first = b"\xc0\x2b" + b"\x00\x05\x00\x01" + (300).to_bytes(4, "big") + (2).to_bytes(2, "big") + b"\xc0\x1d"
        second = b"\xc0\x1d" + b"\x00\x05\x00\x01" + (300).to_bytes(4, "big") + (2).to_bytes(2, "big") + b"\xc0\x2b"
        with pytest.raises(DnsError, match="loop"):
            decode_response(header + question + first + second)


class TestPoisonDetection:
    @pytest.mark.parametrize("sinkhole", sorted(KNOWN_SINKHOLES))
    def test_known_iranian_sinkholes_are_flagged(self, sinkhole):
        verdict = analyse_response("example.com", decode_response(wire_answer("example.com", sinkhole)))
        assert verdict.poisoned
        assert any(sinkhole in reason for reason in verdict.reasons)

    @pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1"])
    def test_non_routable_answers_are_flagged(self, ip):
        verdict = analyse_response("example.com", decode_response(wire_answer("example.com", ip)))
        assert verdict.poisoned

    def test_a_real_public_answer_is_clean(self):
        verdict = analyse_response("example.com", decode_response(wire_answer("example.com", "93.184.216.34")))
        assert not verdict.poisoned
        assert verdict.reasons == ()

    def test_resolving_a_dot_invalid_name_proves_hijack(self):
        verdict = analyse_response(
            dns.NXDOMAIN_PROBE_DOMAIN,
            decode_response(wire_answer(dns.NXDOMAIN_PROBE_DOMAIN, "5.5.5.5")),
        )
        assert verdict.poisoned
        assert any(".invalid" in reason for reason in verdict.reasons)

    def test_nxdomain_for_a_dot_invalid_name_is_correct_behaviour(self):
        verdict = analyse_response(
            dns.NXDOMAIN_PROBE_DOMAIN,
            decode_response(wire_answer(dns.NXDOMAIN_PROBE_DOMAIN, "0.0.0.0", rcode=3)),
        )
        assert not verdict.poisoned


class TestResolution:
    def test_wireformat_path_is_used_first(self, doh_wire_opener):
        response = resolve_doh(HONEST, "example.com", opener=doh_wire_opener("93.184.216.34"))
        assert response.addresses == ("93.184.216.34",)

    def test_transaction_id_mismatch_is_rejected(self):
        def bad_opener(request, timeout):
            return wire_answer("example.com", "93.184.216.34").replace(b"\x48\x59", b"\x99\x99", 1)

        with pytest.raises(DnsError):
            resolve_doh(HONEST, "example.com", opener=bad_opener)

    def test_json_fallback_is_used_when_wireformat_fails(self, json_opener):
        calls = []

        def opener(request, timeout):
            calls.append(request.get_header("Accept"))
            if request.get_header("Accept") == dns.DNS_MESSAGE_MEDIA_TYPE:
                raise ValueError("middlebox returned HTML")
            return json.dumps(
                {"Status": 0, "Answer": [{"name": "example.com", "type": 1, "data": "93.184.216.34"}]}
            ).encode()

        response = resolve_doh(HONEST, "example.com", opener=opener)
        assert response.addresses == ("93.184.216.34",)
        assert calls == [dns.DNS_MESSAGE_MEDIA_TYPE, dns.DNS_JSON_MEDIA_TYPE]


class TestHunting:
    def test_a_poisoned_resolver_ranks_below_an_honest_one(self, doh_wire_opener):
        def opener(request, timeout):
            if b"isp.invalid" in request.full_url.encode():
                return wire_answer("example.com", "10.10.34.35")
            return wire_answer("example.com", "93.184.216.34")

        reports = hunt([POISONED, HONEST], opener=opener)
        assert reports[0].resolver.name == "honest"
        assert pick_best(reports).resolver.name == "honest"

    def test_unreachable_resolvers_are_reported_not_raised(self, doh_wire_opener):
        def opener(request, timeout):
            if b"honest.invalid" in request.full_url.encode():
                raise OSError("network unreachable")
            return wire_answer("example.com", "93.184.216.34")

        reports = hunt([POISONED, HONEST], opener=opener)
        honest = next(r for r in reports if r.resolver.name == "honest")
        assert not honest.reachable
        assert "network unreachable" in honest.error

    def test_when_everyone_lies_there_is_no_best(self, doh_wire_opener):
        reports = hunt([POISONED], opener=doh_wire_opener("10.10.34.35"))
        assert reports[0].poisoned
        assert pick_best(reports) is None

    def test_report_line_mentions_the_reason(self, doh_wire_opener):
        report = probe_resolver(POISONED, opener=doh_wire_opener("10.10.34.35"))
        assert "POISONED" in report.one_line()
        assert "10.10.34.35" in report.one_line()


class TestInternationalisedNames:
    def test_a_persian_domain_is_encoded_as_punycode(self):
        # Python's codec renders مثال as xn--mgbh0fb (IDNA2003).
        query = encode_query("مثال.ir")
        assert b"\x0bxn--mgbh0fb" in query
        assert b"\x02ir" in query

    def test_punycode_and_unicode_forms_produce_identical_queries(self):
        assert encode_query("مثال.ir") == encode_query("xn--mgbh0fb.ir")

    def test_a_unicode_label_survives_a_decode_round_trip(self):
        from hyperion.dns import decode_response

        query = encode_query("مثال.ir")
        header = query[:2] + b"\x81\x80" + query[4:12]
        response = decode_response(header + query[12:])
        assert response.rcode == 0

    def test_an_already_ascii_name_is_untouched(self):
        assert encode_query("example.com")[12:] == b"\x07example\x03com\x00\x00\x01\x00\x01"

    def test_an_empty_name_is_refused(self):
        with pytest.raises(DnsError):
            encode_query("...")
