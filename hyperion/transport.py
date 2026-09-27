"""The reference transport: no-SNI HTTPS to an exit you control, attested.

Why this one
------------
It is the shape that ``120hdd/ovpn-pin`` shipped and that its own README says
was used through China's filtering: TLS on 443, addressed by IP so nothing is
announced, and the certificate still proved. Its comment on the port is the
whole argument -- *"the port the line cannot tell from any other TLS
connection."*

What is added here is what that project cannot have: the exit is yours, so the
exit can *sign* what it saw. ``ovpn-pin`` learns where it came out by asking
``https://1.1.1.1/cdn-cgi/trace``, which works only because Cloudflare runs a
public trace endpoint and its certificate carries 1.1.1.1 as an IP SAN. A
Marzban or 3x-ui node has no such endpoint, and ``CluvexStudio/Aether`` -- which
has no attestation anywhere in its source -- falls back to a plaintext
``http://www.cloudflare.com/cdn-cgi/trace`` that any local terminator can
answer. :mod:`hyperion.truth_gate` closes that, and this module is the client
half of it.

Scope, stated plainly
---------------------
This is a **control path**: it proves that a path is live and that the far end
is where it says it is. It does not carry application traffic. The data path
is ``zero_sni.http_connect_tunnel``, which is separate because a CONNECT
consumes its connection and a probe should not.

The HTTP handling is deliberately minimal -- one GET, a status line, an
optional ``Content-Length`` body. It is not a client, and it does not pretend
to be one.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Sequence

from . import selector, truth_gate, zero_sni

HEAD_END = b"\r\n\r\n"
MAX_HEAD_BYTES = 65536
MAX_BODY_BYTES = 1 << 20
DEFAULT_ATTEST_PATH = "/hyperion/attest"
TRANSPORT_NAME = "zero-sni-https"


class TransportError(RuntimeError):
    """The transport could not complete. Distinct from a path being blocked."""


@dataclass(frozen=True)
class HttpResponse:
    """A parsed HTTP/1.x response: status, and the body if one was framed."""

    status: int
    body: bytes
    reason: str = ""


def split_head(raw: bytes) -> tuple[bytes, bytes] | None:
    """Split at the blank line, or None if the head has not arrived yet."""
    index = raw.find(HEAD_END)
    if index < 0:
        return None
    return raw[:index], raw[index + len(HEAD_END) :]


def parse_status_line(line: bytes) -> tuple[int, str]:
    """``HTTP/1.1 200 OK`` -> ``(200, "OK")``.

    Raises rather than guessing: a status line that cannot be parsed means
    whatever answered is not speaking HTTP, and reporting that as a failure
    would hide a local terminator.
    """
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise TransportError(f"not an HTTP response: {line[:80]!r}")
    try:
        status = int(parts[1])
    except ValueError as exc:
        raise TransportError(f"unreadable status code in {line[:80]!r}") from exc
    reason = parts[2].decode("latin-1").strip() if len(parts) > 2 else ""
    return status, reason


def content_length(head: bytes) -> int | None:
    """The declared body length, or None if the response did not declare one."""
    for raw_line in head.split(b"\r\n")[1:]:
        name, _, value = raw_line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


def read_http(sock: ssl.SSLSocket, timeout: float) -> HttpResponse:
    """Read one response. Requires the head to declare a length.

    A response with no ``Content-Length`` is refused rather than read to EOF.
    Reading to EOF is how a client ends up waiting out a whole timeout on a
    connection that has already said everything it was going to say -- which
    ``ovpn-pin`` measured at 8.34s against 0.53s for the same question asked
    by hand.
    """
    sock.settimeout(timeout)
    raw = b""
    while True:
        split = split_head(raw)
        if split is not None:
            break
        if len(raw) > MAX_HEAD_BYTES:
            raise TransportError("response head exceeded the limit")
        chunk = sock.recv(4096)
        if not chunk:
            raise TransportError("the connection closed before the head arrived")
        raw += chunk

    head, body = split_head(raw) or (b"", b"")
    status_line, _, rest = head.partition(b"\r\n")
    status, reason = parse_status_line(status_line)
    del rest

    length = content_length(head)
    if length is None:
        return HttpResponse(status, body, reason)
    if length > MAX_BODY_BYTES:
        raise TransportError(f"declared body of {length} bytes exceeds the limit")
    while len(body) < length:
        chunk = sock.recv(min(4096, length - len(body)))
        if not chunk:
            raise TransportError(
                f"the connection closed with {len(body)} of {length} body bytes"
            )
        body += chunk
    return HttpResponse(status, body[:length], reason)


def http_get_over_tls(
    sock: ssl.SSLSocket,
    path: str,
    host_header: str,
    timeout: float,
) -> HttpResponse:
    """Send one GET and read its answer, over an already-established socket."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "User-Agent: Hyperion/1.0\r\n"
        "\r\n"
    ).encode("ascii")
    sock.sendall(request)
    return read_http(sock, timeout)


def make_probe(
    host: str,
    port: int,
    anchors: Sequence[zero_sni.TrustAnchor],
    *,
    attest_path: str = DEFAULT_ATTEST_PATH,
    insecure_skip_verify: bool = False,
    expect_name: str | None = None,
):
    """Build the probe callable the selector runs.

    The order is the point: TLS with no SNI, certificate proved for the name,
    then the attestation. A path that answers HTTP but cannot prove where it
    came out is reported by the selector as ``LYING``, which is the outcome a
    naive client would have called "connected".
    """

    def probe(_candidate: selector.Candidate, timeout: float) -> selector.ProbeReply:
        sock, report = zero_sni.connect(
            host,
            port,
            anchors=anchors,
            timeout=timeout,
            insecure_skip_verify=insecure_skip_verify,
            expect_name=expect_name,
        )
        try:
            response = http_get_over_tls(sock, attest_path, f"{host}:{port}", timeout)
        finally:
            sock.close()

        if not 200 <= response.status < 300:
            return selector.ProbeReply(
                False, detail=f"the exit answered HTTP {response.status}"
            )
        return selector.ProbeReply(
            True,
            detail=report.one_line(),
            attestation=response.body,
        )

    return probe


def zero_sni_candidate(
    name: str,
    host: str,
    port: int = 443,
    *,
    anchors: Sequence[zero_sni.TrustAnchor] | None = None,
    attest_path: str = DEFAULT_ATTEST_PATH,
    insecure_skip_verify: bool = False,
    expect_name: str | None = None,
    attest: bool = True,
) -> selector.Candidate:
    """A ready-to-race candidate for the reference transport."""
    if not anchors and not insecure_skip_verify:
        raise zero_sni.ZeroSniError(
            f"candidate {name!r} needs a trust anchor; pass anchors=[...] or set "
            "insecure_skip_verify=True explicitly"
        )
    return selector.Candidate(
        name=name,
        transport=TRANSPORT_NAME,
        probe=make_probe(
            host,
            port,
            tuple(anchors or ()),
            attest_path=attest_path,
            insecure_skip_verify=insecure_skip_verify,
            expect_name=expect_name,
        ),
        attest=attest,
    )


def timed_tcp(host: str, port: int, timeout: float = 5.0) -> tuple[bool, float, str]:
    """A bare TCP handshake, timed. A weak signal, and labelled as one.

    Kept next to the real probe because the interesting case is the pair: a
    handshake that completes and an attestation that fails is the signature of
    local termination, and neither half says that on its own.
    """
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, (time.perf_counter() - started) * 1000.0, "tcp handshake completed"
    except OSError as exc:
        outcome, detail = selector.classify_exception(exc)
        return False, (time.perf_counter() - started) * 1000.0, f"{outcome.value}: {detail}"


__all__ = [
    "DEFAULT_ATTEST_PATH",
    "MAX_BODY_BYTES",
    "MAX_HEAD_BYTES",
    "TRANSPORT_NAME",
    "HttpResponse",
    "TransportError",
    "content_length",
    "http_get_over_tls",
    "make_probe",
    "parse_status_line",
    "read_http",
    "split_head",
    "timed_tcp",
    "zero_sni_candidate",
]
