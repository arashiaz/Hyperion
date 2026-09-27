# Hyperion

A censorship-circumvention toolkit built around one rule: **a step is only
reported as passing if it produced evidence.**

The project started from an earlier attempt that announced "integration test
passed, 100% success" from a run that never opened a socket. That result was not
a test outcome, it was a tautology, and for a tool whose entire purpose is
detecting a censor that *pretends* to let you through, it was the worst possible
failure mode. Everything here is rebuilt so that cannot happen again.

## What is actually here

| Component | File | Status |
| --- | --- | --- |
| TLS record + ClientHello parsing, byte-exact fragmentation | `hyperion/tls_record.py` | Implemented, 32 tests |
| SHARD engine (record split / byte dribble / zero-SNI rewrite) | `hyperion/shard.py` | Implemented, 24 tests |
| DoH client (RFC 8484) + Iranian fake-DNS detection | `hyperion/dns.py` | Implemented, 27 tests |
| Zero-SNI TLS client with CA/SPKI pin verification | `hyperion/zero_sni.py` | Implemented, 16 tests against a real local TLS server |
| AmneziaWG junk packets, magic headers, padding | `hyperion/amneziawg.py` | Framing layer implemented, 40 tests. **No Noise handshake** |
| Truth Gate (signed egress attestation) | `hyperion/truth_gate.py` | Implemented, 24 tests |
| Orchestrator + CLI | `hyperion/orchestrator.py`, `hyperion/__main__.py` | Implemented, 22 tests (17 orchestrator + 5 vector drift) |
| Android app (diagnostics + config validation) | `android/` | Builds in CI; JVM unit tests run against Python-generated vectors |
| Android traffic tunnel | — | **Not implemented.** See below |

Run the suite — 185 tests, all offline:

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Three claims from the earlier design that did not survive contact

### 1. "Fragment at byte 99 with lengths 5/94/1"

`5 + 94 + 1 = 100`, not 99, and the arithmetic was never the real problem. A DPI
engine does not count bytes; it reassembles the handshake message by following
the 4-byte length field at the start of a ClientHello. Cut a record at an
arbitrary offset and the message simply continues in the next record.

What does work is cutting at a point where the parser must either buffer or give
up: `split_client_hello()` places the `server_name` extension alone in one record
and asserts that no other record contains it. `zero_sni_hello()` removes the
extension entirely, at which point there is nothing left to classify. Both are
covered by tests that reassemble the pieces and compare them to the original.

### 2. "Truth Gate rejects fake connections with HTTP 204"

A middlebox can synthesise `204 No Content` without a single byte leaving the
country. A self-answered probe is negative evidence at best, so the design was
inverted: the server now signs an attestation with HMAC-SHA256 over
`egress_ip|timestamp|nonce`, and the client checks three things —

* **authorship** (the signature), which a local terminator cannot forge;
* **freshness** (a time window plus a nonce, so a capture cannot be replayed);
* **egress** (the reported IP must be globally routable and not one of ours).

`verify()` names which of the three failed, because "the tunnel is down" and
"the tunnel is up but a censor is answering" need different responses. A bare 204
now fails; there is a test asserting exactly that.

The timestamp is signed **as a string, exactly as transmitted**. Re-formatting a
float on the verify side makes the Kotlin client and the Python server disagree
about rounding — one of the vectors (`1799999999.9995`) exists to catch that.

### 3. "AmneziaWG H1–H4 mutations"

The key names are real (`jc jmin jmax s1..s4 h1..h4 i1..i5`, confirmed in
`amnezia-vpn/amneziawg-go` `device/uapi.go` and `amnezia-vpn/amnezia-client`'s
`template.conf`), and so is the junk sizing `jmin + rand(jmax - jmin)`. But the
header values are chosen **per deployment** by the server. Hard-coding a default
like `0xdb2e…` would match nobody, so `hyperion/amneziawg.py` refuses to invent
one: an unset `H1` keeps the stock WireGuard type byte, which is correct.

This module is the packet-framing layer only. The X25519/ChaCha20-Poly1305 Noise
handshake is not implemented — on a phone that is the kernel module's job.

## The Android app, and why there is no VpnService

The earlier plan had a `HyperionVpnService.kt` owning a TUN interface. A TUN
service with no packet forwarder behind it does one thing: it reports
"Connected" while forwarding nothing. That is the precise failure the Truth Gate
exists to detect, so shipping it would have contradicted the project's own
thesis.

What the app does instead, all of it verified in CI:

* **`TruthGate.kt`** — the full attestation verifier, checked against signatures
  produced by the Python core.
* **`DohResolver.kt`** — RFC 8484 query encoding, byte-identical to the Python
  encoder, plus sinkhole detection.
* **`AmneziaConfig.kt`** — parse, validate and render AmneziaWG configs.
* **`ClientHelloBuilder.kt`** — builds a ClientHello with no `server_name` and
  can inspect a captured one.

The cross-language agreement is not asserted by hand. `vectors/cross_language.json`
is generated by the Python core, loaded by the Kotlin unit tests as a classpath
resource, and CI fails if either side drifts.

For actual traffic, the honest options are to drive
[`amnezia-vpn/amneziawg-android`](https://github.com/amnezia-vpn/amneziawg-android)
with a config this app has validated, or to run a userspace TCP/IP stack. Neither
is included, and nothing here pretends otherwise.

## CLI

```bash
python -m hyperion hunt                     # rank DoH resolvers, flag injected answers
python -m hyperion hello --sni blocked.example
python -m hyperion connect HOST --ca ca.pem # or --pin <SPKI sha256>
python -m hyperion gate URL --secret <b64>
python -m hyperion amnezia wg.conf
python -m hyperion run --host H --probe URL --secret <b64> --ca ca.pem
python -m hyperion run --dry-run ...        # exits 1; prints NOT VERIFIED
```

`run --dry-run` deliberately exits non-zero. An unverified run that exits 0 is
how the original "100% success" happened.

## Regenerating the vectors

```bash
python -m hyperion.tools.gen_vectors
```

`tests/test_vectors.py` fails if the committed file no longer matches the code,
and the CI workflow re-generates and diffs it as a separate check.

## Not verified here

* No APK was built or installed during development — this sandbox has no JDK and
  cannot reach `dl.google.com`. The Android code is compiled and unit-tested by
  GitHub Actions, not locally.
* Nothing was tested against a real Iranian network path. The sinkhole addresses
  and hijack behaviours are encoded as detection rules; they have not been
  observed by this code in the field.
* The AmneziaWG framing layer has no peer to talk to in this repository, so
  `frame_packet`/`unframe_packet` round-tripping is tested only against itself.
