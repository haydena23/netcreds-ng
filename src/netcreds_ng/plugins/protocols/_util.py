"""Shared helpers for protocol plugins."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable


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
        lines: list[bytes] = []
        if b"\n" not in data:  # the buffer never holds a newline, so no line ends here
            self._buf += data
        else:
            parts = (bytes(self._buf) + data if self._buf else data).split(b"\n")
            self._buf = bytearray(parts.pop())
            lines = [p[:-1] if p.endswith(b"\r") else p for p in parts]
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
        self.negotiated = False  # real option negotiation seen (strong evidence of Telnet)

    def feed(self, data: bytes) -> bytes:
        st = self._state
        if st == 0 and IAC not in data:
            return data  # fast path: plain data, nothing to strip
        out = bytearray()
        pos, n = 0, len(data)
        while pos < n:
            if st == 0:  # copy the run up to the next IAC in one step
                idx = data.find(b"\xff", pos)
                if idx < 0:
                    out += data[pos:]
                    break
                out += data[pos:idx]
                pos, st = idx + 1, 1
                continue
            b = data[pos]
            pos += 1
            if st == 1:
                if b == IAC:
                    out.append(IAC)
                    st = 0
                elif b in (WILL, WONT, DO, DONT):
                    st = 2
                    self.negotiated = True
                elif b == SB:
                    st = 3
                    self.negotiated = True
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


def whole_messages(data: bytes, message_end: Callable[[bytes, int], int | None]) -> bool:
    """Whether ``data`` is one or more complete messages and nothing else (E-5 resync).

    Length-framed protocols have no sync marker, but data after a capture gap always starts a
    TCP segment, and requests and replies usually fill whole segments. ``message_end(data, pos)``
    returns the end offset of a plausible message header at ``pos``, or None.
    """
    pos = 0
    while pos < len(data):
        end = message_end(data, pos)
        if end is None or end <= pos or end > len(data):
            return False
        pos = end
    return bool(data)


_PLACEHOLDER = re.compile(
    # Masks are only asterisks or 4+ x; shell variables only ${NAME} or an ALL-CAPS $NAME, so
    # real values such as "$Secret1" or "xx" are kept (review M32 MED-3).
    rb"^(?:\*+|[xX]{4,}|%s|%\(\w+\)s|\$\{\w+\}|\$[A-Z_][A-Z0-9_]{2,}|\{\{?\s*[\w.]+\s*\}?\}|<[^<>]*>|\[[^\[\]]*\]"
    rb"|(?i:null|none|nil|undefined)"
    rb"|\"\"|''|\"\*+\"|'\*+')$"
    rb"|^(?:\{\{|\{%|\$\{)",  # a template expression, possibly cut at its first space
)


def placeholder(value: bytes) -> bool:
    """A template, masked or empty marker in place of a value: ``****``, ``%s``, ``${PASS}``, ``<password>``,
    ``{{ pw }}``, ``null``. Heuristic plugins do not report these as secrets (M32)."""
    return bool(_PLACEHOLDER.match(value))
