"""NTLMSSP message parsing for authentication-exposure reporting.

netcreds-ng reports *that* an NTLM authentication happened, by whom, from
where, and how weak it is (e.g. NTLMv1, or NTLM over a cleartext carrier). It
deliberately does not format challenge/response material for offline cracking.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

SIGNATURE = b"NTLMSSP\x00"
NEGOTIATE_UNICODE = 0x00000001


@dataclass
class Challenge:
    flags: int
    target_name: str = ""


@dataclass
class Authenticate:
    domain: str
    user: str
    workstation: str
    flags: int
    nt_response_len: int
    lm_response_len: int

    @property
    def version(self) -> str:
        """'NTLMv1', 'NTLMv2', or 'anonymous'."""
        if not self.user and self.nt_response_len <= 1:
            return "anonymous"
        if self.nt_response_len == 24:
            return "NTLMv1"
        if self.nt_response_len > 24:
            return "NTLMv2"
        return "unknown"

    @property
    def principal(self) -> str:
        return f"{self.domain}\\{self.user}" if self.domain else self.user


def _secbuf(msg: bytes, off: int) -> bytes:
    length, _maxlen, offset = struct.unpack("<HHI", msg[off : off + 8])
    if offset + length > len(msg):
        raise ValueError("security buffer outside message")
    return msg[offset : offset + length]


def _text(raw: bytes, unicode: bool) -> str:
    if unicode:
        return raw.decode("utf-16-le", "backslashreplace")
    return raw.decode("latin-1")


def message_type(msg: bytes) -> int | None:
    if len(msg) < 12 or not msg.startswith(SIGNATURE):
        return None
    return int(struct.unpack("<I", msg[8:12])[0])


def parse_challenge(msg: bytes) -> Challenge | None:
    if message_type(msg) != 2 or len(msg) < 32:
        return None
    (flags,) = struct.unpack("<I", msg[20:24])
    try:
        target = _text(_secbuf(msg, 12), bool(flags & NEGOTIATE_UNICODE))
    except (ValueError, struct.error):
        target = ""
    return Challenge(flags, target)


def parse_authenticate(msg: bytes) -> Authenticate | None:
    if message_type(msg) != 3 or len(msg) < 52:
        return None
    try:
        (flags,) = struct.unpack("<I", msg[60:64]) if len(msg) >= 64 else (NEGOTIATE_UNICODE,)
        lm = _secbuf(msg, 12)
        nt = _secbuf(msg, 20)
        dom_raw = _secbuf(msg, 28)
        user_raw = _secbuf(msg, 36)
        ws_raw = _secbuf(msg, 44)
    except (ValueError, struct.error):
        return None
    uni = bool(flags & NEGOTIATE_UNICODE)
    return Authenticate(_text(dom_raw, uni), _text(user_raw, uni), _text(ws_raw, uni), flags, len(nt), len(lm))


def find_messages(data: bytes) -> list[bytes]:
    """Every NTLMSSP message embedded in ``data`` (any carrier: SMB, LDAP, decoded HTTP, ...)."""
    out: list[bytes] = []
    pos = data.find(SIGNATURE)
    while pos != -1:
        out.append(data[pos:])
        pos = data.find(SIGNATURE, pos + 8)
    return out
