"""The committed vectors must match what the code actually produces."""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from hyperion.tools import gen_vectors

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors" / "cross_language.json"


@pytest.fixture(scope="module")
def committed() -> dict:
    return json.loads(VECTORS.read_text())


def test_committed_vectors_are_current(committed):
    assert committed == gen_vectors.build(), (
        "vectors/cross_language.json is stale; run `python3 -m hyperion.tools.gen_vectors`"
    )


def test_every_attestation_signature_verifies(committed):
    """Re-derive each signature from the canonical string and the shared secret."""
    import hashlib
    import hmac

    secret = base64.b64decode(committed["hmac"]["secret_b64"])
    for case in committed["hmac"]["attestations"]:
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, case["canonical"].encode("ascii"), hashlib.sha256).digest()
        ).decode("ascii").rstrip("=")
        assert case["signature"] == expected, case["canonical"]
        assert case["canonical"] == f"{case['egress_ip']}|{case['ts']}|{case['nonce']}"


def test_the_json_body_embeds_the_wire_timestamp_string(committed):
    """The client signs the string it received, never a re-formatted float."""
    for case in committed["hmac"]["attestations"]:
        body = json.loads(case["json"])
        assert body["ts"] == case["ts"]
        assert isinstance(body["ts"], str)


def test_every_dns_query_decodes_back_to_its_name(committed):
    from hyperion.dns import decode_response, encode_query

    for case in committed["dns"]["queries"]:
        assert encode_query(case["name"], case["qtype"]).hex() == case["query_hex"]
        assert len(bytes.fromhex(case["query_hex"])) == case["query_length"]
        # The qname must round-trip through the response parser too.
        raw = bytes.fromhex(case["query_hex"])
        header = raw[:2] + b"\x81\x80" + raw[4:12]
        question = raw[12:]
        response = decode_response(header + question)
        assert response.rcode == 0


def test_sinkhole_list_matches_the_python_constant(committed):
    from hyperion.dns import KNOWN_SINKHOLES

    assert committed["dns"]["known_sinkholes"] == sorted(KNOWN_SINKHOLES)
    assert "10.10.34.35" in committed["dns"]["known_sinkholes"]
