"""Tests for the AmneziaWG shaping layer."""

from __future__ import annotations

import random

import pytest

from hyperion.amneziawg import (
    MAX_PACKET_SIZE,
    STOCK_HANDSHAKE_INITIATION,
    STOCK_TRANSPORT_DATA,
    AmneziaConfig,
    AmneziaConfigError,
    UintRange,
    frame_packet,
    header_magic,
    junk_packets,
    obf_render,
    parse_obf_spec,
    unframe_packet,
)

CONF = """
[Interface]
Address = 10.8.0.2/32
DNS = 1.1.1.1
PrivateKey = aGFzZ2VsbGloYXNnZWxsaWhhc2dlbGxpaGFzZ2VsbGloYXNnZWw=
Jc = 4
Jmin = 10
Jmax = 50
S1 = 15
S2 = 18
S3 = 0
S4 = 0
H1 = 1849894402
H2 = 643248164
H3 = 252645135
H4 = 1707632902
I1 = <b 0xdeadbeef><r 8>

[Peer]
PublicKey = c2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2VydmVya2V5c2VydmVyaw==
Endpoint = 203.0.113.7:54321
"""


class TestUintRange:
    @pytest.mark.parametrize("text,expected", [("10", (10, 10)), ("5-9", (5, 9)), ("0x10", (16, 16))])
    def test_parsing(self, text, expected):
        parsed = UintRange.parse(text)
        assert (parsed.lo, parsed.hi) == expected

    def test_pick_stays_inside_the_range(self):
        rng = random.Random(1234)
        span = UintRange(5, 9)
        assert all(5 <= span.pick(rng) <= 9 for _ in range(200))

    def test_inverted_range_is_refused(self):
        with pytest.raises(AmneziaConfigError):
            UintRange(9, 5)

    def test_overflowing_uint32_is_refused(self):
        with pytest.raises(AmneziaConfigError):
            UintRange(0, 2 ** 32)

    def test_single_value_renders_without_a_dash(self):
        assert str(UintRange(7, 7)) == "7"
        assert str(UintRange(7, 9)) == "7-9"


class TestConfigParsing:
    def test_conf_is_read_completely(self):
        config = AmneziaConfig.from_conf(CONF)
        assert (config.jc, config.jmin, config.jmax) == (4, 10, 50)
        assert (config.s1, config.s2) == (15, 18)
        assert config.h1 == UintRange(1849894402, 1849894402)
        assert config.i1 == "<b 0xdeadbeef><r 8>"
        assert config.address == ["10.8.0.2/32"]

    def test_missing_interface_section_is_an_error(self):
        with pytest.raises(AmneziaConfigError):
            AmneziaConfig.from_conf("[Peer]\nEndpoint = 1.2.3.4:5\n")

    def test_jc_without_jmin_jmax_is_refused(self):
        with pytest.raises(AmneziaConfigError, match="jmin/jmax"):
            AmneziaConfig(jc=3)

    def test_jmin_above_jmax_is_refused(self):
        with pytest.raises(AmneziaConfigError):
            AmneziaConfig(jc=3, jmin=90, jmax=10)

    def test_short_header_protection_key_is_refused(self):
        with pytest.raises(AmneziaConfigError, match="32 bytes"):
            AmneziaConfig(header_protection_key="AAAA")

    def test_unknown_obf_tag_is_refused(self):
        with pytest.raises(AmneziaConfigError, match="unknown obfuscation tag"):
            AmneziaConfig(i1="<zz 3>")

    def test_round_trip_through_conf(self):
        config = AmneziaConfig.from_conf(CONF)
        again = AmneziaConfig.from_conf(config.to_conf())
        assert (again.jc, again.jmin, again.jmax, again.s1, again.s2) == (
            config.jc,
            config.jmin,
            config.jmax,
            config.s1,
            config.s2,
        )
        assert again.h1 == config.h1
        assert again.i1 == config.i1

    def test_round_trip_through_uapi(self):
        config = AmneziaConfig.from_conf(CONF)
        again = AmneziaConfig.from_uapi(config.to_uapi())
        assert again.jc == config.jc
        assert again.h4 == config.h4
        assert again.i1 == config.i1

    def test_uapi_uses_upstream_key_names(self):
        uapi = AmneziaConfig.from_conf(CONF).to_uapi()
        for key in ("jc=", "jmin=", "jmax=", "s1=", "s2=", "h1=", "h4=", "i1="):
            assert key in uapi, f"missing uapi key {key}"

    def test_zero_valued_keys_are_omitted_like_upstream(self):
        assert AmneziaConfig().to_uapi() == ""


class TestJunkPackets:
    def test_count_and_size_bounds(self):
        rng = random.Random(7)
        packets = junk_packets(4, 10, 50, rng)
        assert len(packets) == 4
        assert all(10 <= len(p) <= 50 for p in packets)

    def test_zero_count_produces_nothing(self):
        assert junk_packets(0, 10, 50) == []

    def test_sizes_vary_between_packets(self):
        rng = random.Random(99)
        sizes = {len(p) for p in junk_packets(40, 10, 50, rng)}
        assert len(sizes) > 1, "every junk packet was the same size"

    def test_jmin_equals_jmax_gives_a_fixed_size(self):
        packets = junk_packets(3, 20, 20, random.Random(1))
        assert all(len(p) == 20 for p in packets)

    def test_inverted_bounds_are_refused(self):
        with pytest.raises(AmneziaConfigError):
            junk_packets(1, 50, 10)


class TestMagicHeaders:
    def test_configured_header_replaces_the_stock_type_byte(self):
        config = AmneziaConfig.from_conf(CONF)
        magic = header_magic(config, STOCK_HANDSHAKE_INITIATION)
        assert magic == (1849894402).to_bytes(4, "big")
        assert magic != (1).to_bytes(4, "little")

    def test_unconfigured_header_keeps_the_wireguard_value(self):
        magic = header_magic(AmneziaConfig(), STOCK_TRANSPORT_DATA)
        assert magic == (4).to_bytes(4, "little")

    def test_a_range_picks_inside_itself(self):
        config = AmneziaConfig(h1=UintRange(100, 200))
        rng = random.Random(3)
        values = {int.from_bytes(header_magic(config, 1, rng), "big") for _ in range(100)}
        assert values and all(100 <= v <= 200 for v in values)

    def test_unknown_message_type_is_refused(self):
        with pytest.raises(AmneziaConfigError):
            header_magic(AmneziaConfig(), 99)


class TestFraming:
    def test_frame_layout_is_padding_magic_body(self):
        config = AmneziaConfig(s1=15, h1=UintRange(0xDEADBEEF, 0xDEADBEEF))
        packet = frame_packet(config, STOCK_HANDSHAKE_INITIATION, b"BODY")
        assert len(packet) == 15 + 4 + 4
        assert packet[15:19] == (0xDEADBEEF).to_bytes(4, "big")
        assert packet[19:] == b"BODY"

    def test_unframe_recovers_the_body(self):
        config = AmneziaConfig.from_conf(CONF)
        packet = frame_packet(config, STOCK_HANDSHAKE_INITIATION, b"handshake-bytes")
        assert unframe_packet(config, packet, STOCK_HANDSHAKE_INITIATION) == b"handshake-bytes"

    def test_random_junk_does_not_unframe(self):
        config = AmneziaConfig.from_conf(CONF)
        assert unframe_packet(config, junk_packets(1, 10, 50, random.Random(5))[0]) is None

    def test_too_short_datagram_does_not_unframe(self):
        assert unframe_packet(AmneziaConfig(s1=100), b"short", STOCK_HANDSHAKE_INITIATION) is None

    def test_random_trailers_add_bytes(self):
        base = AmneziaConfig(h1=UintRange(1, 1))
        trailing = AmneziaConfig(h1=UintRange(1, 1), random_trailers=True)
        rng = random.Random(2)
        assert len(frame_packet(trailing, 1, b"x", rng)) > len(frame_packet(base, 1, b"x", rng))

    def test_oversized_frame_is_refused(self):
        with pytest.raises(AmneziaConfigError, match="UDP limit"):
            frame_packet(AmneziaConfig(s1=MAX_PACKET_SIZE), STOCK_HANDSHAKE_INITIATION, b"x")


class TestObfuscationChains:
    def test_all_upstream_tags_are_known(self):
        assert parse_obf_spec("<b 0x01><t 5><r 3><rc 3><rd 3><d><ds><dz 2>") == [
            ("b", "0x01"),
            ("t", "5"),
            ("r", "3"),
            ("rc", "3"),
            ("rd", "3"),
            ("d", ""),
            ("ds", ""),
            ("dz", "2"),
        ]

    def test_b_emits_exact_bytes(self):
        assert obf_render("<b 0xdeadbeef>", b"") == b"\xde\xad\xbe\xef"

    def test_d_passes_the_payload_through(self):
        assert obf_render("<d>", b"payload") == b"payload"

    def test_ds_is_unpadded_base64(self):
        import base64

        assert obf_render("<ds>", b"payload") == base64.b64encode(b"payload").rstrip(b"=")

    def test_rc_emits_letters_only(self):
        out = obf_render("<rc 32>", b"", random.Random(11))
        assert len(out) == 32 and out.isalpha()

    def test_rd_emits_digits_only(self):
        out = obf_render("<rd 32>", b"", random.Random(12))
        assert len(out) == 32 and out.isdigit()

    def test_tags_chain_in_order(self):
        out = obf_render("<r 4><b 0xff><d>", b"XY", random.Random(13))
        assert len(out) == 4 + 1 + 2
        assert out[4:5] == b"\xff"
        assert out[5:] == b"XY"

    def test_unclosed_tag_is_refused(self):
        with pytest.raises(AmneziaConfigError, match="missing closing"):
            parse_obf_spec("<b 0x01")
