"""Path selection: measure which way out is live, then prove it.

Why this module exists
----------------------
Every strong circumvention project converged on the same move: they do not
pick a protocol, they measure and then pick.

* ``mbm110/MSN-GUARD`` orders its Psiphon ladder by *measured* time-to-connect
  on a hostile carrier, because on the worst Iranian carrier every direct dial
  dies at the TCP layer -- null-routed addresses, no RST, no alert.
* ``120hdd/ovpn-pin`` races exits and takes the first that answers. Its own
  measurements put the width at eight; racing wider is *slower*, because the
  handshakes compete for the same upstream.
* ``CluvexStudio/Aether`` hunts the best MASQUE gateway and remembers it in
  ``lastconn.rs`` -- but the key it remembers under is the *transport* name
  (``CARRIER_MASQUE_H3 = "masque-h3"``), not the network. So it can answer
  "which gateway worked last time I used MASQUE-H3", and cannot answer "which
  way out is live on *this* network right now".

What is added here is the missing generalisation: race *across* transports
rather than within one, key the memory on the network, and classify failures
the way they actually need to be treated rather than as a single "failed".

The four outcomes
-----------------
``WORKS``, ``REFUSED``, ``FILTERED`` and ``LYING`` are not four flavours of the
same thing; they carry different instructions:

``REFUSED``
    The endpoint answered, and said no. A refusal is information: the address
    is reachable, the port is closed or the credentials are wrong. Retrying
    later, or trying another endpoint, is reasonable.

``FILTERED``
    Nobody answered, or the line answered on the endpoint's behalf. TCP
    completes at the normal round trip and then the handshake is swallowed --
    which is what ``ovpn-pin`` calls ``ErrFiltered`` and what MSN-GUARD hit on
    the worst carrier. Retrying this address on this line cannot help; the
    correct response is a different path, not another attempt.

``LYING``
    Something answered and the answer did not check out -- a bad attestation
    signature, a stale one, or an egress address that is not routable. This is
    the outcome that a naive client reports as "connected", and it is kept
    apart on purpose: a path that lies is worse than a path that is closed,
    because it will be chosen again.

``WORKS``
    Answered, and proved. ``ProbeResult.attested`` says whether the proof was
    a signature or merely a successful handshake, because "it answered" and
    "it is where it says it is" are different claims and only the second one
    is worth acting on.

An RST is ambiguous and treated as such
---------------------------------------
A reset can be a closed port or a DPI box injecting one. The split used here
is by *when* it arrived: a reset to the SYN is recorded as ``REFUSED`` (the
common case really is a closed port), while a reset after TCP was established
is recorded as ``FILTERED`` (the line intervened once there was something to
intervene in). That is a heuristic, not a proof, and it is stated as one.
"""

from __future__ import annotations

import concurrent.futures
import errno
import hashlib
import json
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Mapping, Sequence

from . import truth_gate

# ovpn-pin's measured width. Wider is not better: the handshakes compete for
# the same upstream, and its table shows width 24 taking more than twice as
# long as width 6 on the line it was measured on.
DEFAULT_WIDTH = 8
DEFAULT_TIMEOUT = 8.0
MEMORY_SCHEMA = 1
MEMORY_RECENT_CAP = 8


class Outcome(str, Enum):
    """What a probe concluded. The string values are the on-disk vocabulary."""

    WORKS = "works"
    REFUSED = "refused"
    FILTERED = "filtered"
    LYING = "lying"


#: Outcomes where trying again later, or elsewhere, is a reasonable response.
#: ``FILTERED`` is deliberately absent -- the line is swallowing this path, and
#: retrying it is how a client ends up hanging for minutes on a dead route.
RETRYABLE = frozenset({Outcome.REFUSED})


class SelectorError(RuntimeError):
    """Raised for a selector that cannot be run, not for a path that failed."""


@dataclass(frozen=True)
class Candidate:
    """One way out, described declaratively.

    ``transport`` is a free-form label used for reporting and for grouping;
    nothing here understands MASQUE or WireGuard, and nothing needs to. A
    candidate is "dial this, expect this", which is why transports from other
    projects can be wrapped as candidates without being reimplemented.
    """

    name: str
    transport: str
    probe: Callable[["Candidate", float], "ProbeReply"]
    #: When true, the reply must carry a truth-gate attestation and a ``Gate``
    #: must be supplied to ``select``; a reply without one is ``LYING``, not
    #: ``WORKS``. Refusing to downgrade silently is the whole point.
    attest: bool = False


@dataclass(frozen=True)
class ProbeReply:
    """What a probe returned, before the selector has classified it."""

    ok: bool
    detail: str = ""
    egress_ip: str | None = None
    #: Raw truth-gate body, for transports that carry one.
    attestation: bytes | None = None


@dataclass(frozen=True)
class ProbeResult:
    """A classified probe."""

    candidate: str
    transport: str
    outcome: Outcome
    latency_ms: float
    detail: str
    egress_ip: str | None = None
    attested: bool = False

    @property
    def usable(self) -> bool:
        return self.outcome is Outcome.WORKS

    @property
    def retryable(self) -> bool:
        return self.outcome in RETRYABLE

    def one_line(self) -> str:
        proof = ""
        if self.outcome is Outcome.WORKS:
            proof = " [signed]" if self.attested else " [UNPROVEN]"
        return (
            f"{self.outcome.value:<8} {self.candidate:<24} "
            f"{self.latency_ms:7.0f}ms  {self.transport}{proof}"
            + (f"  -- {self.detail}" if self.detail else "")
        )


def classify_exception(exc: BaseException) -> tuple[Outcome, str]:
    """Map a transport error onto an outcome.

    The rules are ordered so that "the line swallowed it" wins over "the
    endpoint said no" whenever both readings are available, because acting on
    the wrong one of those costs a user minutes of retrying.
    """
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return Outcome.FILTERED, "no answer before the deadline"
    if isinstance(exc, ssl.SSLError):
        # An alert is an answer; a handshake that stalls is not. SSLError wraps
        # both, so the timeout check has to come first -- and it does, above.
        # getattr because .reason is only present on errors the TLS stack
        # raised itself, and a classifier is the wrong place to crash.
        reason = getattr(exc, "reason", None) or str(exc)
        return Outcome.REFUSED, f"tls rejected the handshake: {reason}"
    if isinstance(exc, ConnectionRefusedError):
        # An RST to the SYN. Usually a closed port, occasionally injected; the
        # client cannot tell, and a closed port is the commoner cause.
        return Outcome.REFUSED, "connection refused at the TCP layer"
    if isinstance(exc, ConnectionResetError):
        # TCP was up and then the line cut it. Treated as filtering because
        # that is the case where retrying is known not to help.
        return Outcome.FILTERED, "reset after the connection was established"
    if isinstance(exc, ConnectionAbortedError):
        return Outcome.FILTERED, "connection aborted after it was established"
    if isinstance(exc, socket.gaierror):
        return Outcome.REFUSED, (
            f"the name did not resolve ({exc.strerror or exc}); on a censored "
            "line this is as often poisoning as absence"
        )
    if isinstance(exc, OSError):
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN):
            return Outcome.REFUSED, f"no route: {exc.strerror or exc}"
        if exc.errno in (errno.ETIMEDOUT,):
            return Outcome.FILTERED, "the socket timed out"
        return Outcome.REFUSED, f"socket error: {exc.strerror or exc}"
    return Outcome.REFUSED, f"{type(exc).__name__}: {exc}"


def evaluate(
    candidate: Candidate,
    timeout: float = DEFAULT_TIMEOUT,
    gate: truth_gate.Gate | None = None,
    now: float | None = None,
) -> ProbeResult:
    """Probe one candidate and classify what came back.

    A candidate that asks to be attested and cannot be is ``LYING``, never
    ``WORKS`` -- including the configuration error of no gate being supplied,
    which would otherwise silently turn every attest-candidate into an
    unproven success.
    """
    if candidate.attest and gate is None:
        raise SelectorError(
            f"candidate {candidate.name!r} requires attestation but no truth_gate.Gate "
            "was supplied; refusing to report it as verified"
        )

    started = time.perf_counter()
    try:
        reply = candidate.probe(candidate, timeout)
    except BaseException as exc:  # noqa: BLE001 - classification is the contract
        outcome, detail = classify_exception(exc)
        return ProbeResult(
            candidate=candidate.name,
            transport=candidate.transport,
            outcome=outcome,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            detail=detail,
        )
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    if not reply.ok:
        return ProbeResult(
            candidate=candidate.name,
            transport=candidate.transport,
            outcome=Outcome.REFUSED,
            latency_ms=elapsed_ms,
            detail=reply.detail or "the endpoint said no",
            egress_ip=reply.egress_ip,
        )

    if not candidate.attest:
        return ProbeResult(
            candidate=candidate.name,
            transport=candidate.transport,
            outcome=Outcome.WORKS,
            latency_ms=elapsed_ms,
            detail=reply.detail,
            egress_ip=reply.egress_ip,
            attested=False,
        )

    if reply.attestation is None:
        return ProbeResult(
            candidate=candidate.name,
            transport=candidate.transport,
            outcome=Outcome.LYING,
            latency_ms=elapsed_ms,
            detail="promised an attestation and sent none",
            egress_ip=reply.egress_ip,
        )

    assert gate is not None  # guarded above
    verdict = gate.verify(reply.attestation, now=now, latency_ms=elapsed_ms)
    if not verdict.passed:
        return ProbeResult(
            candidate=candidate.name,
            transport=candidate.transport,
            outcome=Outcome.LYING,
            latency_ms=elapsed_ms,
            detail="attestation failed: " + ", ".join(verdict.failed),
            egress_ip=reply.egress_ip,
        )
    return ProbeResult(
        candidate=candidate.name,
        transport=candidate.transport,
        outcome=Outcome.WORKS,
        latency_ms=elapsed_ms,
        detail=verdict.one_line(),
        egress_ip=reply.egress_ip,
        attested=True,
    )


# --------------------------------------------------------------------------
# Selecting
# --------------------------------------------------------------------------

_RANK = {
    Outcome.WORKS: 0,
    Outcome.REFUSED: 1,
    Outcome.FILTERED: 2,
    Outcome.LYING: 3,
}


def _rank_key(result: ProbeResult) -> tuple[int, float, str]:
    # A lying path sorts last whatever its latency: a fast answer from
    # somewhere that is not where it claims to be is the worst outcome here,
    # because it is the one most likely to be chosen again.
    return (_RANK[result.outcome], result.latency_ms, result.candidate)


@dataclass(frozen=True)
class SelectReport:
    """What a selection run concluded."""

    results: tuple[ProbeResult, ...]
    winner: ProbeResult | None
    width: int
    elapsed_ms: float
    stopped_early: bool = False
    not_run: tuple[str, ...] = ()

    @property
    def ranked(self) -> tuple[ProbeResult, ...]:
        return tuple(sorted(self.results, key=_rank_key))

    def by_outcome(self, outcome: Outcome) -> tuple[ProbeResult, ...]:
        return tuple(r for r in self.results if r.outcome is outcome)

    @property
    def unproven(self) -> tuple[ProbeResult, ...]:
        """Paths that answered but proved nothing. Kept visible on purpose."""
        return tuple(r for r in self.results if r.usable and not r.attested)

    @property
    def ok(self) -> bool:
        return self.winner is not None

    def lines(self) -> Iterable[str]:
        for result in self.ranked:
            yield result.one_line()
        for name in self.not_run:
            yield f"{'--':<8} {name:<24} {'':>7}     not run"
        if self.winner is None:
            yield "no path is live"
        else:
            proof = "signed" if self.winner.attested else "UNPROVEN"
            yield (
                f"selected {self.winner.candidate} ({self.winner.transport}) "
                f"in {self.winner.latency_ms:.0f}ms [{proof}]"
            )


def survey(
    candidates: Sequence[Candidate],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    width: int = DEFAULT_WIDTH,
    gate: truth_gate.Gate | None = None,
    now: float | None = None,
) -> SelectReport:
    """Probe every candidate and report the whole picture.

    This is the learning pass: it costs more than ``select`` and returns the
    full ranking, which is what a memory should be built from.
    """
    if not candidates:
        raise SelectorError("nothing to survey")
    if width < 1:
        raise SelectorError(f"width must be at least 1, got {width}")

    started = time.perf_counter()
    results: list[ProbeResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=width) as pool:
        futures = [
            pool.submit(evaluate, candidate, timeout, gate, now)
            for candidate in candidates
        ]
        for future in futures:
            results.append(future.result())
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    ranked = sorted(results, key=_rank_key)
    winner = ranked[0] if ranked and ranked[0].usable else None
    return SelectReport(
        results=tuple(results),
        winner=winner,
        width=width,
        elapsed_ms=elapsed_ms,
    )


def select(
    candidates: Sequence[Candidate],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    width: int = DEFAULT_WIDTH,
    gate: truth_gate.Gate | None = None,
    now: float | None = None,
) -> SelectReport:
    """Race the candidates and take the first that works.

    First rather than best. Waiting for two so the quicker can be picked costs
    the difference between them on every connect, which is not worth a second
    of somebody's time -- and the loser of a race is usually close enough that
    the ranking would not have been stable anyway.

    Candidates that never got their turn are reported as ``not_run`` rather
    than dropped, so a report cannot look more complete than it is.
    """
    if not candidates:
        raise SelectorError("nothing to select from")
    if width < 1:
        raise SelectorError(f"width must be at least 1, got {width}")

    started = time.perf_counter()
    results: list[ProbeResult] = []
    not_run: list[str] = []
    winner: ProbeResult | None = None
    stopped_early = False

    pending = list(candidates)
    with concurrent.futures.ThreadPoolExecutor(max_workers=width) as pool:
        while pending and winner is None:
            batch, pending = pending[:width], pending[width:]
            futures = {
                pool.submit(evaluate, candidate, timeout, gate, now): candidate
                for candidate in batch
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                if result.usable and winner is None:
                    winner = result
            if winner is not None and pending:
                # The rest of the queue is abandoned, not failed: it was never
                # asked, and saying otherwise would put a lie in the report.
                stopped_early = True
                not_run.extend(candidate.name for candidate in pending)
                pending = []

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return SelectReport(
        results=tuple(results),
        winner=winner,
        width=width,
        elapsed_ms=elapsed_ms,
        stopped_early=stopped_early,
        not_run=tuple(not_run),
    )


# --------------------------------------------------------------------------
# Remembering what worked, keyed on the network
# --------------------------------------------------------------------------


def network_fingerprint(*facts: str) -> str:
    """Hash whatever the caller can observe about the current network.

    This deliberately does not try to identify the ISP. On Android the honest
    key is ``ConnectivityManager``'s network handle, which is free and changes
    when the phone changes networks; on a desktop it is the default route and
    its gateway. Both are facts the platform already knows, and guessing from
    latency or a traceroute would produce a key that drifts -- which is worse
    than no key, because a memory that half-matches is consulted confidently.

    Order matters: the same facts in a different order are a different network.
    """
    digest = hashlib.sha256()
    for fact in facts:
        digest.update(fact.strip().encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:16]


@dataclass
class MemoryEntry:
    """One remembered path."""

    candidate: str
    transport: str
    outcome: str
    latency_ms: float
    attested: bool
    seen_at: float


@dataclass
class NetworkMemory:
    """What worked, on which network, most recent first.

    Mirrors the refusal semantics of Aether's ``lastconn.rs``: an entry saved
    under a different fingerprint is ignored rather than merged, because a
    gateway that worked on one carrier says nothing about another. The
    difference is that the key here is the network, not the transport.
    """

    fingerprint: str
    entries: list[MemoryEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: str, fingerprint: str) -> "NetworkMemory":
        """Load the memory for ``fingerprint``, or an empty one."""
        memory = cls(fingerprint=fingerprint)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                blob = json.load(handle)
        except (OSError, ValueError):
            return memory
        if not isinstance(blob, dict) or blob.get("schema") != MEMORY_SCHEMA:
            return memory
        stored = blob.get("fingerprint")
        if stored != fingerprint:
            # Not an error and not a merge: a different network's history is
            # simply not this network's history.
            return memory
        for raw in blob.get("entries", []):
            if not isinstance(raw, dict):
                continue
            try:
                memory.entries.append(
                    MemoryEntry(
                        candidate=str(raw["candidate"]),
                        transport=str(raw.get("transport", "")),
                        outcome=str(raw.get("outcome", "")),
                        latency_ms=float(raw.get("latency_ms", 0.0)),
                        attested=bool(raw.get("attested", False)),
                        seen_at=float(raw.get("seen_at", 0.0)),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return memory

    def save(self, path: str) -> None:
        blob = {
            "schema": MEMORY_SCHEMA,
            "fingerprint": self.fingerprint,
            "entries": [
                {
                    "candidate": entry.candidate,
                    "transport": entry.transport,
                    "outcome": entry.outcome,
                    "latency_ms": entry.latency_ms,
                    "attested": entry.attested,
                    "seen_at": entry.seen_at,
                }
                for entry in self.entries
            ],
        }
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(blob, handle, indent=2, sort_keys=True)

    def record(self, result: ProbeResult, now: float | None = None) -> None:
        """Remember an outcome, most recent first, capped."""
        entry = MemoryEntry(
            candidate=result.candidate,
            transport=result.transport,
            outcome=result.outcome.value,
            latency_ms=result.latency_ms,
            attested=result.attested,
            seen_at=now if now is not None else time.time(),
        )
        self.entries = [e for e in self.entries if e.candidate != result.candidate]
        self.entries.insert(0, entry)
        del self.entries[MEMORY_RECENT_CAP:]

    def record_all(self, results: Iterable[ProbeResult], now: float | None = None) -> None:
        for result in results:
            self.record(result, now=now)

    def remembered(self, *, only_usable: bool = True) -> tuple[str, ...]:
        """Candidate names in the order they should be tried."""

        def key(entry: MemoryEntry) -> tuple[int, float]:
            # A path that proved itself outranks one that merely answered,
            # and among equals the faster one goes first.
            return (0 if (entry.outcome == Outcome.WORKS.value and entry.attested) else 1,
                    entry.latency_ms)

        pool = [
            e
            for e in self.entries
            if (e.outcome == Outcome.WORKS.value) or not only_usable
        ]
        return tuple(e.candidate for e in sorted(pool, key=key))

    def order(self, candidates: Sequence[Candidate]) -> list[Candidate]:
        """Put remembered-good candidates first, leaving the rest in order.

        Never removes a candidate. A memory is a hint about ordering, not a
        filter: a path that worked last week may be the only one that works
        today, and dropping the others would turn a hint into a dead end.
        """
        ranked = self.remembered()
        position = {name: index for index, name in enumerate(ranked)}
        return sorted(
            candidates,
            key=lambda c: (position.get(c.name, len(position) + 1),),
        )


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_WIDTH",
    "MEMORY_RECENT_CAP",
    "MEMORY_SCHEMA",
    "RETRYABLE",
    "Candidate",
    "MemoryEntry",
    "NetworkMemory",
    "Outcome",
    "ProbeReply",
    "ProbeResult",
    "SelectReport",
    "SelectorError",
    "classify_exception",
    "evaluate",
    "network_fingerprint",
    "select",
    "survey",
]
