"""Hyperion orchestrator: run the whole chain and report what was *proven*.

The orchestrator is deliberately boring.  It calls four things in order, records
what each one actually returned, and refuses to report success on the strength
of a step that did not produce evidence:

1. :mod:`hyperion.dns`         -- find a resolver that is not lying.
2. :mod:`hyperion.shard`       -- decide how the ClientHello leaves the device.
3. :mod:`hyperion.zero_sni`    -- complete a handshake with no SNI and prove the peer.
4. :mod:`hyperion.truth_gate`  -- prove the bytes left the country.

A step that is skipped is reported as ``skipped`` with a reason, never as
``ok``.  That distinction is the whole point of the module: the earlier version
of this project reported "100% success" from a run that never touched a network,
which is not a test result, it is a tautology.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from . import dns, shard, truth_gate, zero_sni
from .tls_record import ClientHello, build_client_hello

STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"


@dataclass
class StepResult:
    name: str
    status: str
    detail: str
    evidence: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def one_line(self) -> str:
        return f"[{self.status.upper():<7}] {self.name}: {self.detail}"


@dataclass
class RunReport:
    steps: list[StepResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    duration_ms: float = 0.0

    def add(self, step: StepResult) -> StepResult:
        self.steps.append(step)
        return step

    def step(self, name: str) -> StepResult | None:
        for step in self.steps:
            if step.name == name:
                return step
        return None

    @property
    def ok(self) -> bool:
        """True only when every step that ran succeeded and none was skipped."""
        return bool(self.steps) and all(step.ok for step in self.steps)

    @property
    def failed_steps(self) -> tuple[str, ...]:
        return tuple(s.name for s in self.steps if not s.ok)

    def render(self) -> str:
        lines = [f"Hyperion run report  ({self.duration_ms:.0f} ms)"]
        lines.append("=" * 72)
        for step in self.steps:
            lines.append(step.one_line())
            for line in step.evidence:
                lines.append(f"          {line}")
        lines.append("=" * 72)
        lines.append(
            "RESULT: "
            + (
                "ALL STEPS VERIFIED"
                if self.ok
                else "NOT VERIFIED -> " + ", ".join(self.failed_steps)
            )
        )
        return "\n".join(lines)


@dataclass
class HyperionConfig:
    """Everything the orchestrator needs; no hidden defaults that reach the network."""

    server_host: str = ""
    server_port: int = 443
    probe_url: str = ""
    attestation_secret: bytes = b""
    trust_anchors: tuple[zero_sni.TrustAnchor, ...] = ()
    insecure_skip_verify: bool = False
    timeout: float = 8.0
    dns_probe_domain: str = "example.com"
    alpn: tuple[str, ...] = ()

    def validate(self) -> list[str]:
        problems: list[str] = []
        if not self.server_host:
            problems.append("server_host is empty")
        if not 0 < self.server_port < 65536:
            problems.append(f"server_port {self.server_port} is not a valid port")
        if not self.probe_url:
            problems.append("probe_url is empty")
        if len(self.attestation_secret) < 16:
            problems.append("attestation_secret must be at least 16 bytes")
        if not self.trust_anchors and not self.insecure_skip_verify:
            problems.append(
                "no trust_anchors and insecure_skip_verify is False; the Zero-SNI "
                "step would be refused"
            )
        return problems


def run(
    config: HyperionConfig,
    dns_opener: dns.Opener | None = None,
    gate_opener: truth_gate.Opener | None = None,
    resolvers: Sequence[dns.Resolver] = dns.PUBLIC_DOH_RESOLVERS,
    connect_fn: Callable[..., tuple[object, zero_sni.HandshakeReport]] = zero_sni.connect,
    skip_network: bool = False,
) -> RunReport:
    """Execute the chain.  Inject the openers to test offline."""
    report = RunReport()
    started = time.perf_counter()

    problems = config.validate()
    if problems:
        report.add(
            StepResult(
                "config",
                STATUS_FAIL,
                "configuration is not usable",
                tuple(problems),
            )
        )
        report.duration_ms = (time.perf_counter() - started) * 1000.0
        return report
    report.add(StepResult("config", STATUS_OK, f"server {config.server_host}:{config.server_port}"))

    # -- 1. DNS ------------------------------------------------------------
    if skip_network:
        report.add(
            StepResult(
                "dns",
                STATUS_SKIPPED,
                "no resolver was contacted; nothing is known about DNS on this path",
            )
        )
    else:
        reports = dns.hunt(
            resolvers, probe_domain=config.dns_probe_domain, timeout=config.timeout, opener=dns_opener
        )
        best = dns.pick_best(reports)
        poisoned = [r for r in reports if r.poisoned]
        if best is None:
            report.add(
                StepResult(
                    "dns",
                    STATUS_FAIL,
                    "every resolver either failed or lied",
                    tuple(r.one_line() for r in reports),
                )
            )
        else:
            report.add(
                StepResult(
                    "dns",
                    STATUS_OK,
                    f"using {best.resolver.name} ({best.latency_ms:.0f} ms)",
                    tuple(r.one_line() for r in reports),
                )
            )
        if poisoned:
            report.step("dns").evidence += (  # type: ignore[union-attr]
                f"WARNING: {len(poisoned)} resolver(s) returned injected answers",
            )

    # -- 2. ClientHello strategy ------------------------------------------
    hello_bytes = build_client_hello(sni=None)
    hello = ClientHello.parse(_payload(hello_bytes))
    strategy = shard.best_strategy_for(hello)
    result = shard.shard(hello_bytes, strategy=strategy)
    report.add(
        StepResult(
            "shard",
            STATUS_OK,
            result.describe(),
            (
                f"reassembled == original: {result.stream_payload == _payload(hello_bytes)}",
                f"wire bytes: {len(result.stream)} across {len(result.pieces)} piece(s)",
            ),
        )
    )

    # -- 3. Zero-SNI handshake --------------------------------------------
    if skip_network:
        report.add(
            StepResult(
                "zero-sni",
                STATUS_SKIPPED,
                "no TLS handshake was performed; peer identity is unproven",
            )
        )
    else:
        try:
            sock, handshake = connect_fn(
                config.server_host,
                port=config.server_port,
                anchors=list(config.trust_anchors),
                timeout=config.timeout,
                alpn=list(config.alpn) or None,
                insecure_skip_verify=config.insecure_skip_verify,
            )
        except Exception as exc:  # noqa: BLE001 - report, do not crash
            report.add(StepResult("zero-sni", STATUS_FAIL, f"{type(exc).__name__}: {exc}"))
        else:
            try:
                report.add(
                    StepResult(
                        "zero-sni",
                        STATUS_OK,
                        handshake.one_line(),
                        (
                            f"subject CN: {handshake.peer_subject_cn}",
                            f"not after: {handshake.peer_not_after}",
                            f"full pin: {handshake.peer_pin}",
                            f"SNI sent: {handshake.sni_sent}",
                        ),
                    )
                )
            finally:
                sock.close()

    # -- 4. Truth gate -----------------------------------------------------
    if skip_network:
        report.add(
            StepResult(
                "truth-gate",
                STATUS_SKIPPED,
                "no attestation was requested; egress is unproven",
            )
        )
    else:
        gate = truth_gate.Gate(secret=config.attestation_secret)
        try:
            verdict = truth_gate.probe(gate, config.probe_url, timeout=config.timeout, opener=gate_opener)
        except Exception as exc:  # noqa: BLE001
            report.add(StepResult("truth-gate", STATUS_FAIL, f"{type(exc).__name__}: {exc}"))
        else:
            report.add(
                StepResult(
                    "truth-gate",
                    STATUS_OK if verdict.passed else STATUS_FAIL,
                    verdict.one_line(),
                    tuple(verdict.detail_lines()),
                )
            )

    report.duration_ms = (time.perf_counter() - started) * 1000.0
    return report


def _payload(record: bytes) -> bytes:
    from .tls_record import TlsRecord

    return TlsRecord.parse(record).payload


__all__ = [
    "STATUS_FAIL",
    "STATUS_OK",
    "STATUS_SKIPPED",
    "HyperionConfig",
    "RunReport",
    "StepResult",
    "run",
]
