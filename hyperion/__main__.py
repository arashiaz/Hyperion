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

from . import __version__, amneziawg, dns, orchestrator, shard, tls_record, truth_gate, zero_sni


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
