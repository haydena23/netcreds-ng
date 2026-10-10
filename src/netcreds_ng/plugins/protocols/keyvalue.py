"""Generic cleartext ``user=... pass=...`` patterns in non-HTTP TCP streams.

The original net-creds ran its HTTP form regexes over every TCP payload, so it
also caught key=value credentials in arbitrary protocols. This plugin keeps
that coverage for streams that are *not* HTTP (the HTTP plugin parses those
properly), reporting with reduced confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, placeholder, text
from netcreds_ng.plugins.protocols.http import METHODS, PASS_FIELDS, USER_FIELDS

_SCAN_LIMIT = 1 << 20


def _field_re(names: set[str]) -> re.Pattern[bytes]:
    alts = b"|".join(re.escape(n.encode()) for n in sorted(names, key=len, reverse=True))
    return re.compile(rb"(?:^|[\s&;?,])(" + alts + rb")=([^\s&;,]+)", re.IGNORECASE)


_USER = _field_re(USER_FIELDS)
_PASS = _field_re(PASS_FIELDS)
#: Every PASS_FIELDS name contains one of these (tests/test_fast_paths.py), so a line without any cannot match _PASS.
_PASS_HINTS = (b"pass", b"pw", b"secret", b"senha", b"contrasena")


def _candidate(data: bytes) -> bool:
    """False if _PASS cannot match in ``data``: no "=", or no password field name (any case)."""
    if b"=" not in data:
        return False
    low = data.lower()  # ASCII-only, like re.IGNORECASE on bytes
    return any(hint in low for hint in _PASS_HINTS)


@dataclass
class _State:
    lines: tuple[LineBuffer, LineBuffer] = field(default_factory=lambda: (LineBuffer(), LineBuffer()))
    scanned: list[int] = field(default_factory=lambda: [0, 0])
    first: list[bool] = field(default_factory=lambda: [True, True])


class KeyValuePlugin(ProtocolPlugin):
    name = "keyvalue"
    sets = ("generic", "legacy")
    description = "Generic user=/pass= credential patterns in non-HTTP cleartext streams (heuristic)"
    priority = 200

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.state.lines[direction].gap()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        d = int(direction)
        if st.first[d] and data.strip():
            st.first[d] = False
            head = data.lstrip()[:16]
            if (direction is Direction.CLIENT_TO_SERVER and head.split(b" ")[0] in METHODS) or head.startswith(b"HTTP/"):
                ctx.detach()
                return
        if st.scanned[d] > _SCAN_LIMIT:
            return
        st.scanned[d] += len(data)
        for line in st.lines[d].feed(data):
            self._scan(ctx, direction, line)

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        for d in (0, 1):
            tail = st.lines[d].pending
            if tail:
                self._scan(ctx, Direction(d), tail)

    def _scan(self, ctx: Context, direction: Direction, line: bytes) -> None:
        if not _candidate(line):
            return  # the regex alone is several times slower on binary streams
        pw = next((m for m in _PASS.finditer(line) if not placeholder(m.group(2))), None)
        if pw is None:
            return  # no password field, or only template/masked values (``pass=%s``, ``password=****``)
        user = _USER.search(line)
        ctx.emit(
            direction, Kind.CREDENTIAL if user else Kind.PASSWORD, protocol="Cleartext",
            username=text(user.group(2)) if user else None, secret=text(pw.group(2)),
            plugin=self.name, risk="medium", confidence=0.5,
            extra={"pattern": f"{text(user.group(1)) + '=' if user else ''}{text(pw.group(1))}="},
        )  # fmt: skip
