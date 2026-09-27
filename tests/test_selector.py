"""Tests for the path selector. Fully offline: every probe is injected."""

from __future__ import annotations

import errno
import json
import socket
import ssl
import time

import pytest

from hyperion import selector, truth_gate
from hyperion.selector import (
    MEMORY_RECENT_CAP,
    Candidate,
    NetworkMemory,
    Outcome,
    ProbeReply,
    ProbeResult,
    SelectorError,
    classify_exception,
    evaluate,
    network_fingerprint,
    select,
    survey,
)

SECRET = b"selector-test-secret-at-least-16b"
EGRESS = "93.184.216.34"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def make_gate() -> truth_gate.Gate:
    return truth_gate.Gate(secret=SECRET)


def make_attestation(egress: str = EGRESS, when: float | None = None) -> bytes:
    attestor = truth_gate.Attestor(secret=SECRET)
    return attestor.to_json(attestor.sign(egress, timestamp=when))


def replies(reply: ProbeReply, delay: float = 0.0):
    """A probe that returns a fixed reply, optionally after a delay."""

    def probe(_candidate, _timeout):
        if delay:
            time.sleep(delay)
        return reply

    return probe


def raises(exc: BaseException):
    def probe(_candidate, _timeout):
        raise exc

    return probe


def candidate(name, transport="t", reply=None, exc=None, attest=False, delay=0.0):
    probe = raises(exc) if exc is not None else replies(reply or ProbeReply(True), delay)
    return Candidate(name=name, transport=transport, probe=probe, attest=attest)


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------


class TestClassification:
    @pytest.mark.parametrize(
        "exc,outcome",
        [
            (TimeoutError(), Outcome.FILTERED),
            (socket.timeout(), Outcome.FILTERED),
            (ConnectionResetError(), Outcome.FILTERED),
            (ConnectionAbortedError(), Outcome.FILTERED),
            (ConnectionRefusedError(), Outcome.REFUSED),
            (socket.gaierror(-2, "Name or service not known"), Outcome.REFUSED),
            (OSError(errno.EHOSTUNREACH, "No route to host"), Outcome.REFUSED),
            (OSError(errno.ENETUNREACH, "Network is unreachable"), Outcome.REFUSED),
            (OSError(errno.ETIMEDOUT, "Connection timed out"), Outcome.FILTERED),
            (ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER]"), Outcome.REFUSED),
            (ValueError("boom"), Outcome.REFUSED),
        ],
    )
    def test_errors_map_onto_outcomes(self, exc, outcome):
        got, detail = classify_exception(exc)
        assert got is outcome
        assert detail, "every classification carries a reason"

    def test_a_timeout_beats_the_ssl_branch(self):
        """ssl.SSLError can wrap a stall; the timeout check has to win."""
        exc = socket.timeout()
        assert isinstance(exc, OSError)
        assert classify_exception(exc)[0] is Outcome.FILTERED

    def test_filtered_is_not_retryable_and_refused_is(self):
        assert Outcome.REFUSED in selector.RETRYABLE
        assert Outcome.FILTERED not in selector.RETRYABLE
        assert Outcome.LYING not in selector.RETRYABLE
        assert Outcome.WORKS not in selector.RETRYABLE


# --------------------------------------------------------------------------
# evaluate
# --------------------------------------------------------------------------


class TestEvaluate:
    def test_a_plain_success_is_works_but_not_attested(self):
        result = evaluate(candidate("plain", reply=ProbeReply(True)))
        assert result.outcome is Outcome.WORKS
        assert result.attested is False
        assert result.usable is True

    def test_an_endpoint_that_says_no_is_refused(self):
        result = evaluate(
            candidate("closed", reply=ProbeReply(False, detail="port closed"))
        )
        assert result.outcome is Outcome.REFUSED
        assert result.retryable is True
        assert "port closed" in result.detail

    def test_an_exception_is_classified_not_raised(self):
        result = evaluate(candidate("dead", exc=TimeoutError()))
        assert result.outcome is Outcome.FILTERED
        assert result.usable is False

    def test_a_signed_reply_is_works_and_attested(self):
        gate = make_gate()
        result = evaluate(
            candidate(
                "honest",
                reply=ProbeReply(True, attestation=make_attestation()),
                attest=True,
            ),
            gate=gate,
        )
        assert result.outcome is Outcome.WORKS
        assert result.attested is True
        assert result.usable is True

    def test_a_forged_signature_is_lying_not_works(self):
        gate = make_gate()
        forged = json.loads(make_attestation())
        forged["egress_ip"] = "203.0.113.9"  # body changed, signature did not
        result = evaluate(
            candidate(
                "forger",
                reply=ProbeReply(True, attestation=json.dumps(forged).encode()),
                attest=True,
            ),
            gate=gate,
        )
        assert result.outcome is Outcome.LYING
        assert "signature" in result.detail
        assert result.usable is False

    def test_a_stale_attestation_is_lying(self):
        gate = make_gate()
        stale = make_attestation(when=time.time() - 3600)
        result = evaluate(
            candidate("stale", reply=ProbeReply(True, attestation=stale), attest=True),
            gate=gate,
        )
        assert result.outcome is Outcome.LYING
        assert "freshness" in result.detail

    def test_a_non_routable_egress_is_lying(self):
        """A real signature over a private address is still not an exit."""
        gate = make_gate()
        body = make_attestation(egress="10.10.34.35")  # a known Iranian sinkhole
        result = evaluate(
            candidate("sinkhole", reply=ProbeReply(True, attestation=body), attest=True),
            gate=gate,
        )
        assert result.outcome is Outcome.LYING
        assert "egress" in result.detail

    def test_promising_an_attestation_and_sending_none_is_lying(self):
        result = evaluate(
            candidate("silent", reply=ProbeReply(True), attest=True),
            gate=make_gate(),
        )
        assert result.outcome is Outcome.LYING
        assert "sent none" in result.detail

    def test_attesting_without_a_gate_is_an_error_not_a_pass(self):
        """The dangerous default would be to report it as an unproven success."""
        with pytest.raises(SelectorError, match="no truth_gate.Gate"):
            evaluate(
                candidate("ungated", reply=ProbeReply(True), attest=True), gate=None
            )

    def test_latency_is_measured(self):
        result = evaluate(candidate("slow", delay=0.05))
        assert result.latency_ms >= 40.0


# --------------------------------------------------------------------------
# selecting
# --------------------------------------------------------------------------


class TestSelect:
    def test_the_first_working_path_wins(self):
        report = select(
            [
                candidate("slow-ok", delay=0.20),
                candidate("fast-ok", delay=0.01),
            ],
            width=2,
        )
        assert report.winner is not None
        assert report.winner.candidate == "fast-ok"
        assert report.ok is True

    def test_a_lying_path_is_never_the_winner(self):
        gate = make_gate()
        report = select(
            [
                candidate(
                    "liar",
                    reply=ProbeReply(True, attestation=make_attestation("10.0.0.1")),
                    attest=True,
                    delay=0.001,
                ),
                candidate(
                    "honest",
                    reply=ProbeReply(True, attestation=make_attestation()),
                    attest=True,
                    delay=0.05,
                ),
            ],
            width=2,
            gate=gate,
        )
        assert report.winner.candidate == "honest"
        lying = report.by_outcome(Outcome.LYING)
        assert [r.candidate for r in lying] == ["liar"]

    def test_all_filtered_means_no_path(self):
        report = select(
            [candidate(f"dead-{i}", exc=TimeoutError()) for i in range(3)], width=3
        )
        assert report.winner is None
        assert report.ok is False
        assert len(report.by_outcome(Outcome.FILTERED)) == 3

    def test_refusal_alone_is_not_a_path(self):
        report = select([candidate("closed", exc=ConnectionRefusedError())], width=1)
        assert report.winner is None
        assert report.by_outcome(Outcome.REFUSED)[0].retryable is True

    def test_an_unproven_success_is_flagged(self):
        report = select([candidate("plain")], width=1)
        assert report.winner.candidate == "plain"
        assert [r.candidate for r in report.unproven] == ["plain"]
        assert "UNPROVEN" in report.winner.one_line()

    def test_abandoned_candidates_are_reported_not_dropped(self):
        report = select(
            [candidate("first"), candidate("never-1"), candidate("never-2")],
            width=1,
        )
        assert report.winner.candidate == "first"
        assert report.stopped_early is True
        assert set(report.not_run) == {"never-1", "never-2"}
        text = "\n".join(report.lines())
        assert "not run" in text

    def test_an_empty_candidate_list_is_refused(self):
        with pytest.raises(SelectorError, match="nothing to select"):
            select([])

    def test_a_zero_width_is_refused(self):
        with pytest.raises(SelectorError, match="at least 1"):
            select([candidate("a")], width=0)

    def test_ranking_puts_lying_last_even_when_it_is_fastest(self):
        gate = make_gate()
        report = survey(
            [
                candidate("filtered", exc=TimeoutError()),
                candidate("refused", exc=ConnectionRefusedError()),
                candidate(
                    "liar",
                    reply=ProbeReply(True, attestation=b"not json"),
                    attest=True,
                ),
                candidate(
                    "honest",
                    reply=ProbeReply(True, attestation=make_attestation()),
                    attest=True,
                    delay=0.05,
                ),
            ],
            width=4,
            gate=gate,
        )
        order = [r.candidate for r in report.ranked]
        assert order[-1] == "liar"
        assert order[0] == "honest"

    def test_survey_probes_everything_and_never_stops_early(self):
        report = survey(
            [candidate(f"c{i}", exc=TimeoutError()) for i in range(6)], width=2
        )
        assert len(report.results) == 6
        assert report.stopped_early is False
        assert report.not_run == ()
        assert report.winner is None


# --------------------------------------------------------------------------
# memory
# --------------------------------------------------------------------------


class TestNetworkFingerprint:
    def test_it_is_stable_and_short(self):
        a = network_fingerprint("wlan0", "192.168.1.1")
        b = network_fingerprint("wlan0", "192.168.1.1")
        assert a == b
        assert len(a) == 16

    def test_order_matters(self):
        assert network_fingerprint("a", "b") != network_fingerprint("b", "a")

    def test_a_different_network_is_a_different_key(self):
        assert network_fingerprint("wlan0", "192.168.1.1") != network_fingerprint(
            "rmnet0", "10.64.0.1"
        )

    def test_padding_is_not_ignored(self):
        """'a b' + 'c' and 'a' + 'b c' must not collide."""
        assert network_fingerprint("a b", "c") != network_fingerprint("a", "b c")


class TestNetworkMemory:
    def result(self, name, outcome=Outcome.WORKS, latency=10.0, attested=True):
        return ProbeResult(
            candidate=name,
            transport="t",
            outcome=outcome,
            latency_ms=latency,
            detail="",
            attested=attested,
        )

    def test_round_trip_through_disk(self, tmp_path):
        path = str(tmp_path / "mem.json")
        memory = NetworkMemory(fingerprint="abc123")
        memory.record(self.result("alpha"))
        memory.record(self.result("beta", outcome=Outcome.FILTERED))
        memory.save(path)

        loaded = NetworkMemory.load(path, "abc123")
        assert loaded.remembered() == ("alpha",)
        # Both survive the round trip; the working one still sorts first,
        # because ordering a dead path ahead of a live one would be a bug.
        everything = loaded.remembered(only_usable=False)
        assert set(everything) == {"alpha", "beta"}
        assert everything[0] == "alpha"
        assert {e.candidate: e.outcome for e in loaded.entries} == {
            "alpha": "works",
            "beta": "filtered",
        }

    def test_another_networks_history_is_ignored_not_merged(self, tmp_path):
        path = str(tmp_path / "mem.json")
        memory = NetworkMemory(fingerprint="home")
        memory.record(self.result("home-only"))
        memory.save(path)

        other = NetworkMemory.load(path, "work")
        assert other.entries == []
        assert other.remembered() == ()

    def test_a_missing_or_corrupt_file_is_an_empty_memory(self, tmp_path):
        assert NetworkMemory.load(str(tmp_path / "nope.json"), "x").entries == []
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        assert NetworkMemory.load(str(broken), "x").entries == []

    def test_an_old_schema_is_ignored(self, tmp_path):
        path = tmp_path / "old.json"
        path.write_text(json.dumps({"schema": 999, "fingerprint": "x"}), encoding="utf-8")
        assert NetworkMemory.load(str(path), "x").entries == []

    def test_the_recent_list_is_capped(self):
        memory = NetworkMemory(fingerprint="x")
        for i in range(MEMORY_RECENT_CAP + 5):
            memory.record(self.result(f"c{i}"))
        assert len(memory.entries) == MEMORY_RECENT_CAP

    def test_recording_twice_moves_it_to_the_front(self):
        memory = NetworkMemory(fingerprint="x")
        memory.record(self.result("a"))
        memory.record(self.result("b"))
        memory.record(self.result("a"))
        assert [e.candidate for e in memory.entries] == ["a", "b"]

    def test_an_attested_path_outranks_an_unproven_one(self):
        memory = NetworkMemory(fingerprint="x")
        memory.record(self.result("unproven", latency=1.0, attested=False))
        memory.record(self.result("signed", latency=99.0, attested=True))
        assert memory.remembered() == ("signed", "unproven")

    def test_ordering_never_removes_a_candidate(self):
        memory = NetworkMemory(fingerprint="x")
        memory.record(self.result("known-good"))
        pool = [candidate("unknown-1"), candidate("known-good"), candidate("unknown-2")]
        ordered = memory.order(pool)
        assert [c.name for c in ordered] == ["known-good", "unknown-1", "unknown-2"]

    def test_ordering_without_a_memory_preserves_the_given_order(self):
        pool = [candidate("a"), candidate("b"), candidate("c")]
        assert [c.name for c in NetworkMemory("x").order(pool)] == ["a", "b", "c"]

    def test_a_memory_can_drive_a_selection(self, tmp_path):
        """The end-to-end shape: survey, remember, then select in that order."""
        path = str(tmp_path / "mem.json")
        fingerprint = network_fingerprint("rmnet0", "10.64.0.1")

        first = survey(
            [candidate("slow-good", delay=0.05), candidate("dead", exc=TimeoutError())],
            width=2,
        )
        assert first.winner.candidate == "slow-good"
        memory = NetworkMemory.load(path, fingerprint)
        memory.record_all(first.results)
        memory.save(path)

        reloaded = NetworkMemory.load(path, fingerprint)
        pool = [candidate("dead", exc=TimeoutError()), candidate("slow-good")]
        ordered = reloaded.order(pool)
        assert ordered[0].name == "slow-good"
        second = select(ordered, width=2)
        assert second.winner.candidate == "slow-good"
