"""Hyperion command line interface.

Every subcommand prints what it actually observed.  Nothing here reports success
that it did not measure.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import time

from . import (
    __version__,
    amneziawg,
    dns,
    orchestrator,
    selector,
    shard,
    tls_record,
    transport,
    truth_gate,
    zero_sni,
)


def cmd_hunt(args: argparse.Namespace) -> int:
    """Probe DoH resolvers and rank them."""
    reports = dns.hunt(
        timeout=args.timeout,
        probe_domain=args.domain,
    )
    print(f"probing {len(reports)} resolvers for '{args.domain}'")
    for report in reports:
        print("  " + report.one_line())
        for reason in report.poison_reasons:
            print(f"      ! {reason}")
    best = dns.pick_best(reports)
    print()
    if best is None:
        print("no trustworthy resolver found on this path")
        return 1
    print(f"best: {best.resolver.name} via {best.resolver.doh_url}")
    return 0


def cmd_hello(args: argparse.Namespace) -> int:
    """Build a ClientHello and show exactly how it would be fragmented."""
    hello_bytes = tls_record.build_client_hello(sni=args.sni)
    hello = tls_record.ClientHello.parse(tls_record.TlsRecord.parse(hello_bytes).payload)
    print(f"ClientHello: {len(hello_bytes)} bytes, SNI={hello.sni!r}")
    print(f"  tls versions offered: {[hex(v) for v in hello.advertised_tls_versions]}")
    print(f"  extensions: {[hex(t) for t in hello.extension_types]}")
    print()
    chosen = args.strategy or shard.best_strategy_for(hello)
    result = shard.shard(hello_bytes, strategy=chosen)
    print(f"strategy {chosen}: {result.describe()}")
    for index, piece in enumerate(result.pieces):
        print(f"  piece {index}: {len(piece):>5} bytes  {piece[:16].hex()}…")
    reassembled = result.stream_payload == tls_record.TlsRecord.parse(hello_bytes).payload
    print(f"  byte-exact reassembly: {reassembled}")
    print(f"  wire bytes: {len(result.stream)} in {len(result.pieces)} piece(s)")
    if not reassembled:
        return 1
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    """Complete a Zero-SNI handshake and report what was proven."""
    anchors: list[zero_sni.TrustAnchor] = []
    if args.ca:
        with open(args.ca, "r", encoding="utf-8") as handle:
            anchors.append(zero_sni.TrustAnchor(ca_pem=handle.read()))
    if args.pin:
        anchors.append(zero_sni.TrustAnchor(spki_sha256_hex=args.pin))
    try:
        sock, report = zero_sni.connect(
            args.host,
            port=args.port,
            anchors=anchors,
            timeout=args.timeout,
            insecure_skip_verify=args.insecure,
        )
    except zero_sni.ZeroSniError as exc:
        print(f"REFUSED: {exc}")
        return 1
    except OSError as exc:
        print(f"FAILED: {exc}")
        return 1
    with sock:
        print(report.one_line())
        print(f"  subject CN : {report.peer_subject_cn}")
        print(f"  not after  : {report.peer_not_after}")
        print(f"  SPKI pin   : {report.peer_pin}")
        print(f"  matched    : {report.matched_anchor}")
        print(f"  SNI sent   : {report.sni_sent}")
    return 0 if report.trusted else 1


def cmd_gate(args: argparse.Namespace) -> int:
    """Fetch and verify a signed egress attestation."""
    secret = base64.b64decode(args.secret + "=" * (-len(args.secret) % 4))
    gate = truth_gate.Gate(secret=secret)
    verdict = truth_gate.probe(gate, args.url, timeout=args.timeout)
    print(verdict.one_line())
    for line in verdict.detail_lines():
        print("  " + line.strip())
    return 0 if verdict.passed else 1


def cmd_select(args: argparse.Namespace) -> int:
    """Race exits and report which is live, and whether it proved itself.

    Exit status is three-valued on purpose: 0 attested, 2 answered but proved
    nothing, 1 no path at all. Collapsing 2 into 0 is exactly the mistake this
    project keeps finding in other clients.
    """
    anchors: list[zero_sni.TrustAnchor] = []
    if args.ca:
        with open(args.ca, "r", encoding="utf-8") as handle:
            anchors.append(zero_sni.TrustAnchor(ca_pem=handle.read()))
    if args.pin:
        anchors.append(zero_sni.TrustAnchor(spki_sha256_hex=args.pin))

    gate = None
    if args.secret:
        gate = truth_gate.Gate(
            secret=base64.b64decode(args.secret + "=" * (-len(args.secret) % 4))
        )
    attest = gate is not None
    if not attest:
        print("NOTE: no --secret, so nothing can be attested; a winner is UNPROVEN")

    candidates = []
    for index, target in enumerate(args.targets):
        host, sep, port_text = target.rpartition(":")
        port = int(port_text) if sep else args.port
        name = args.name[index] if args.name and index < len(args.name) else f"exit-{index + 1}"
        candidates.append(
            transport.zero_sni_candidate(
                name,
                host or target,
                port,
                anchors=anchors,
                attest_path=args.path,
                insecure_skip_verify=args.insecure,
                attest=attest,
            )
        )

    memory = None
    if args.memory:
        if not args.net:
            print("REFUSED: --memory needs at least one --net fact to key on")
            return 1
        fingerprint = selector.network_fingerprint(*args.net)
        memory = selector.NetworkMemory.load(args.memory, fingerprint)
        candidates = memory.order(candidates)
        print(f"network fingerprint: {fingerprint}")

    report = selector.select(
        candidates, timeout=args.timeout, width=args.width, gate=gate
    )
    for line in report.lines():
        print(line)
    print(f"  ({len(report.results)} probed, width {report.width}, "
          f"{report.elapsed_ms:.0f}ms total)")

    if memory is not None:
        memory.record_all(report.results)
        memory.save(args.memory)
        print(f"remembered {len(memory.entries)} paths in {args.memory}")

    if report.winner is None:
        return 1
    return 0 if report.winner.attested else 2


def cmd_keygen(args: argparse.Namespace) -> int:
    """Print a fresh attestation secret (base64) for the server and the client."""
    print(base64.b64encode(truth_gate.Attestor.generate_secret()).decode("ascii"))
    return 0


def cmd_amnezia(args: argparse.Namespace) -> int:
    """Parse an AmneziaWG config and describe the datagrams it would produce."""
    with open(args.config, "r", encoding="utf-8") as handle:
        config = amneziawg.AmneziaConfig.from_conf(handle.read())
    print(config.describe())
    print()
    for line in amneziawg.describe_flow(config):
        print("  " + line)
    print()
    print("uapi form:")
    for line in config.to_uapi().splitlines():
        print("  " + line)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Run the full chain against a server."""
    anchors: list[zero_sni.TrustAnchor] = []
    if args.ca:
        with open(args.ca, "r", encoding="utf-8") as handle:
            anchors.append(zero_sni.TrustAnchor(ca_pem=handle.read()))
    if args.pin:
        anchors.append(zero_sni.TrustAnchor(spki_sha256_hex=args.pin))
    secret = base64.b64decode(args.secret + "=" * (-len(args.secret) % 4)) if args.secret else b""
    config = orchestrator.HyperionConfig(
        server_host=args.host,
        server_port=args.port,
        probe_url=args.probe,
        attestation_secret=secret,
        trust_anchors=tuple(anchors),
        insecure_skip_verify=args.insecure,
        timeout=args.timeout,
    )
    report = orchestrator.run(config, skip_network=args.dry_run)
    print(report.render())
    return 0 if report.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hyperion", description=__doc__)
    parser.add_argument("--version", action="version", version=f"hyperion {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    hunt = sub.add_parser("hunt", help="rank DoH resolvers and flag injected answers")
    hunt.add_argument("--domain", default="example.com")
    hunt.add_argument("--timeout", type=float, default=5.0)
    hunt.set_defaults(func=cmd_hunt)

    hello = sub.add_parser("hello", help="show how a ClientHello is fragmented")
    hello.add_argument("--sni", default="blocked.example.com")
    hello.add_argument(
        "--strategy",
        choices=["zero-sni", "isolate-sni", "byte-dribble", "none"],
        default=None,
    )
    hello.set_defaults(func=cmd_hello)

    connect = sub.add_parser("connect", help="Zero-SNI TLS handshake with pin verification")
    connect.add_argument("host")
    connect.add_argument("--port", type=int, default=443)
    connect.add_argument("--ca", help="PEM trust anchor")
    connect.add_argument("--pin", help="SPKI SHA-256 pin (base64 or hex)")
    connect.add_argument("--insecure", action="store_true", help="skip verification (lab only)")
    connect.add_argument("--timeout", type=float, default=8.0)
    connect.set_defaults(func=cmd_connect)

    gate = sub.add_parser("gate", help="verify a signed egress attestation")
    gate.add_argument("url")
    gate.add_argument("--secret", required=True, help="base64 HMAC secret")
    gate.add_argument("--timeout", type=float, default=8.0)
    gate.set_defaults(func=cmd_gate)

    select = sub.add_parser(
        "select",
        help="race exits; 0 attested, 2 answered but unproven, 1 no path",
    )
    select.add_argument("targets", nargs="+", metavar="HOST[:PORT]",
                        help="exit addresses to race")
    select.add_argument("--name", action="append", metavar="LABEL",
                        help="label for a target, in order; defaults to exit-N")
    select.add_argument("--port", type=int, default=443,
                        help="port for a target written without one")
    select.add_argument("--ca", help="PEM trust anchor")
    select.add_argument("--pin", help="SPKI SHA-256 pin")
    select.add_argument("--secret", help="base64 attestation secret; without it nothing is proven")
    select.add_argument("--path", default=transport.DEFAULT_ATTEST_PATH,
                        help="attestation path on the exit")
    select.add_argument("--insecure", action="store_true",
                        help="skip certificate verification (lab benches only)")
    select.add_argument("--width", type=int, default=selector.DEFAULT_WIDTH,
                        help="how many to ask at once (measured best: 8)")
    select.add_argument("--timeout", type=float, default=8.0)
    select.add_argument("--memory", help="JSON file remembering what worked")
    select.add_argument("--net", action="append", metavar="FACT",
                        help="an observable fact about this network, to key the memory on")
    select.set_defaults(func=cmd_select)

    keygen = sub.add_parser("keygen", help="print a fresh attestation secret")
    keygen.set_defaults(func=cmd_keygen)

    amnezia = sub.add_parser("amnezia", help="describe an AmneziaWG config's packet shaping")
    amnezia.add_argument("config")
    amnezia.set_defaults(func=cmd_amnezia)

    run = sub.add_parser("run", help="run the whole chain")
    run.add_argument("--host", default="")
    run.add_argument("--port", type=int, default=443)
    run.add_argument("--probe", default="")
    run.add_argument("--secret", default="")
    run.add_argument("--ca")
    run.add_argument("--pin")
    run.add_argument("--insecure", action="store_true")
    run.add_argument("--dry-run", action="store_true", help="do the offline steps only")
    run.add_argument("--timeout", type=float, default=8.0)
    run.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
