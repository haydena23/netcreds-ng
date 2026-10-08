"""Parity floor: every exposure the original reports must also be found by the new engine.

The legacy engine (verified byte-identical to the Python 2 original) provides the
original's messages; each message is mapped to a predicate over new-engine findings.
Known false positives and per-packet artifacts of the original are documented inline.
"""

from __future__ import annotations

import re

import pytest

from conftest import REAL_CAPTURES, SYNTHETIC_CAPTURES, run_legacy
from netcreds_ng.model import Kind
from netcreds_ng.testing.harness import analyze

ESC_OPEN = b"\x1b[93m"
ESC_CLOSE = b"\x1b[0m"
LINE_SPLIT = re.compile(rb"(?<=\x1b\[0m)\n|\n(?=\[)")
CHUNK_HEAD = re.compile(r"^[0-9a-fA-F]+\r\n")
CHUNK_TAIL = re.compile(r"\r\n0\r\n\r?$")
STRIP = " \x00"


def legacy_messages(capture):
    """(src, dst, message) for every line the original printed."""
    stdout, _ = run_legacy(capture)
    out = []
    for raw in LINE_SPLIT.split(stdout):
        raw = raw.rstrip(b"\n")
        if not raw:
            continue
        head, _, rest = raw.partition(b"] ")
        endpoints = head.lstrip(b"[").decode()
        src, _, dst = endpoints.partition(" > ")
        msg = rest.removeprefix(ESC_OPEN).removesuffix(ESC_CLOSE)
        out.append((src, dst, msg.decode("utf-8", "replace")))
    return out


def _server_side(src: str) -> bool:
    port = int(src.rsplit(":", 1)[1]) if ":" in src else 0
    return port < 1024 or port in (2121, 8080, 6667)


def covered(src: str, dst: str, msg: str, findings) -> bool | None:
    """True if covered, False if missing, None for known false positives / advisories."""
    secrets = {f.secret for f in findings if f.secret}
    users = {f.username for f in findings if f.username}

    def has_secret(text: str) -> bool:
        return any(s and s in text for s in secrets)

    def has_user(text: str) -> bool:
        return any(u and u in text for u in users)

    if msg.startswith("FTP User: "):
        return msg[10:].strip() in users
    if msg.startswith("FTP Pass: "):
        return msg[10:].strip() in secrets
    if msg.startswith("Nonstandard FTP port"):
        # Advisory, not an exposure; the original also prints it for POP3 USER/PASS on port 110.
        return True if any("nonstandard-port" in f.tags for f in findings) else None
    if msg.startswith("Telnet username: "):
        return msg[17:].strip(STRIP) in {u.strip() for u in users}
    if msg.startswith("Telnet password: "):
        return msg[17:].strip(STRIP) in {s.strip() for s in secrets}
    if msg.startswith("HTTP password: "):
        return has_secret(msg)
    if msg.startswith("HTTP username: "):
        # The original matches field names as substrings ("remember=1" counts as "member"), so its
        # username line is unreliable; covered when the request's credential/password was found.
        return has_user(msg) or any(f.kind in (Kind.CREDENTIAL, Kind.PASSWORD) and f.secret for f in findings)
    if msg.startswith("Basic Authentication: "):
        user, _, pw = msg[22:].partition(":")
        return user in users and pw in secrets
    if msg.startswith("Mail authentication: "):
        return True if has_secret(msg) or has_user(msg) else None  # raw base64 echo; covered via "Decoded:"
    if msg.startswith("Decoded: "):
        return has_secret(msg)
    if msg.startswith("Authentication: "):
        if _server_side(src):
            return None  # false positive on server replies such as "230 Login successful."
        return has_secret(msg)
    if msg in ("Authentication successful", "Authentication failed"):
        return any(f.kind is Kind.AUTH_RESULT for f in findings)
    if msg.startswith("IRC nick: "):
        return msg[10:].strip() in users
    if msg.startswith("IRC pass: "):
        # "nickserv :identify" values are lower-cased by the original.
        return any(s and s.lower() in msg.lower() for s in secrets)
    if msg.startswith(("NETNTLMv1: ", "NETNTLMv2: ")):
        user, _, rest = msg.split(" ", 1)[1].partition("::")
        domain = rest.split(":", 1)[0]
        return any(f.kind is Kind.AUTH_EVENT and f.username == user and (f.domain or "") == domain for f in findings)
    if msg.startswith("MS Kerberos: "):
        parts = msg.split("$")
        user, realm = parts[3], parts[4]
        return any(f.protocol == "Kerberos" and f.username == user and f.domain == realm for f in findings)
    if msg.startswith("SNMPv") and "community string: " in msg:
        return msg.split("community string: ", 1)[1] in secrets
    if msg.startswith("Searched "):
        term = msg.split(": ", 1)[1]
        return any(f.kind is Kind.SEARCH and f.value == term for f in findings)
    if msg.startswith("POST load: "):
        # The original prints raw per-packet data: partial bodies and chunked framing included.
        body = CHUNK_TAIL.sub("", CHUNK_HEAD.sub("", msg[11:].removesuffix("...")))
        return any(
            f.kind is Kind.POST and f.value and (f.value.startswith(body) or body.startswith(f.value))
            for f in findings
        )
    if not dst:  # URL line "METHOD host/path"; the host may be cut short when the request spans packets
        _method, _, rest = msg.partition(" ")
        rest = rest.removesuffix("...")
        path = rest[rest.find("/") :] if "/" in rest else rest
        return any(f.kind is Kind.URL and f.value and path in f.value for f in findings)
    return False


@pytest.mark.parametrize("capture", SYNTHETIC_CAPTURES + REAL_CAPTURES, ids=lambda p: p.name)
def test_new_engine_covers_original(capture):
    findings = analyze(str(capture), dedup="off")
    missing = []
    for src, dst, msg in legacy_messages(capture):
        if covered(src, dst, msg, findings) is False:
            missing.append(msg.split(":")[0])  # label only: never print values
    assert not missing, f"original findings not covered: {missing}"
