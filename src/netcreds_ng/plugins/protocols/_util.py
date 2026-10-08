"""Shared helpers for protocol plugins."""

from __future__ import annotations

import base64
import binascii
import re


def text(raw: bytes) -> str:
    """Decode wire bytes for display: UTF-8, with undecodable bytes shown as \\xNN escapes."""
    return raw.decode("utf-8", "backslashreplace")


def b64decode(value: bytes | str) -> bytes | None:
    """Lenient base64 decode; None on invalid input."""
    if isinstance(value, str):
        value = value.encode("ascii", "ignore")
    value = value.strip()
    if not value:
        return None
    try:
        return base64.b64decode(value + b"=" * (-len(value) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None


def sasl_plain(decoded: bytes) -> tuple[str, str, str] | None:
    """Split a SASL PLAIN message into (authzid, authcid, password)."""
    parts = decoded.split(b"\x00")
    if len(parts) != 3:
        return None
    return text(parts[0]), text(parts[1]), text(parts[2])


class LineBuffer:
    """Accumulates stream bytes and yields complete lines (LF or CRLF terminated, terminator stripped)."""

    def __init__(self, max_line: int = 64 * 1024) -> None:
        self._buf = bytearray()
        self.max_line = max_line
        self.overflowed = False
        self._skip_partial = False

    def gap(self) -> None:
        """Bytes were lost: drop the partial line before the hole and the rest of the line after it."""
        self._buf.clear()
        self._skip_partial = True

    def feed(self, data: bytes) -> list[bytes]:
        if self._skip_partial:
            idx = data.find(b"\n")
            if idx < 0:
                return []
            data = data[idx + 1 :]
            self._skip_partial = False
        self._buf += data
        lines: list[bytes] = []
        while True:
            idx = self._buf.find(b"\n")
            if idx < 0:
                break
            line = bytes(self._buf[:idx])
            del self._buf[: idx + 1]
            if line.endswith(b"\r"):
                line = line[:-1]
            lines.append(line)
        if len(self._buf) > self.max_line:
            self.overflowed = True
            self._buf.clear()
        return lines

    def reset(self) -> None:
        self._buf.clear()
        self._skip_partial = False

    @property
    def pending(self) -> bytes:
        return bytes(self._buf)


IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


class TelnetDecoder:
    """Strips Telnet option negotiation (RFC 854) from a byte stream, statefully."""

    def __init__(self) -> None:
        self._state = 0  # 0 data, 1 after IAC, 2 after WILL/WONT/DO/DONT, 3 in SB, 4 SB after IAC

    def feed(self, data: bytes) -> bytes:
        out = bytearray()
        st = self._state
        for b in data:
            if st == 0:
                if b == IAC:
                    st = 1
                else:
                    out.append(b)
            elif st == 1:
                if b == IAC:
                    out.append(IAC)
                    st = 0
                elif b in (WILL, WONT, DO, DONT):
                    st = 2
                elif b == SB:
                    st = 3
                else:
                    st = 0
            elif st == 2:
                st = 0
            elif st == 3:
                if b == IAC:
                    st = 4
            elif st == 4:
                st = 0 if b == SE else 3
        self._state = st
        return bytes(out)


_PRINTABLE = re.compile(rb"^[\x09\x0a\x0d\x20-\x7e]*$")


def printable_ascii(data: bytes) -> bool:
    return bool(_PRINTABLE.match(data))
