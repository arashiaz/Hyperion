"""Hyperion -- a censorship-circumvention toolkit.

Submodules
----------
:mod:`hyperion.tls_record`   TLS record and ClientHello parsing, byte-exact fragmentation
:mod:`hyperion.shard`        the SHARD engine (record split, byte dribble, zero-SNI rewrite)
:mod:`hyperion.dns`          DoH client (RFC 8484) and Iranian fake-DNS detection
:mod:`hyperion.zero_sni`     TLS client that sends no SNI and proves the peer by pin
:mod:`hyperion.amneziawg`    AmneziaWG junk packets, magic headers and padding
:mod:`hyperion.truth_gate`   signed egress attestation (replaces the naive HTTP-204 check)
:mod:`hyperion.orchestrator` runs the chain and reports what was proven
"""

from . import amneziawg, dns, orchestrator, shard, tls_record, truth_gate, zero_sni

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "amneziawg",
    "dns",
    "orchestrator",
    "shard",
    "tls_record",
    "truth_gate",
    "zero_sni",
]
