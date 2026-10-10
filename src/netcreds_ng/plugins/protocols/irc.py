"""IRC: server passwords, NickServ identification and SASL PLAIN."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, b64decode, sasl_plain, text

_NS_PRIVMSG = re.compile(rb"^PRIVMSG\s+NickServ\s+:\s*IDENTIFY\s+(\S+)(?:\s+(\S+))?", re.IGNORECASE)
_NS_SHORT = re.compile(rb"^(?:NS|NICKSERV)\s+IDENTIFY\s+(\S+)(?:\s+(\S+))?", re.IGNORECASE)
_GIVE_UP_BYTES = 16 * 1024


@dataclass
class _State:
    lines: LineBuffer = field(default_factory=LineBuffer)
    nick: str | None = None
    nick_reported: bool = False
    sasl_plain: bool = False
    pending_pass: str | None = None
    irc_seen: bool = False
    client_bytes: int = 0


class IRCPlugin(ProtocolPlugin):
    name = "irc"
    wants_encrypted = False
    sets = ("chat", "legacy")
    description = "IRC PASS, NICK, NickServ IDENTIFY and SASL PLAIN (any port)"
    default_ports = frozenset({6667, 6697, 194})
    priority = 40

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        if direction is Direction.CLIENT_TO_SERVER:
            ctx.state.lines.gap()
            ctx.state.sasl_plain = False

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        if direction is not Direction.CLIENT_TO_SERVER:
            return
        st: _State = ctx.state
        st.client_bytes += len(data)
        for line in st.lines.feed(data):
            self._line(ctx, st, line)
        if not st.irc_seen and st.client_bytes > _GIVE_UP_BYTES:
            ctx.detach()

    def _confirm(self, ctx: Context, st: _State) -> None:
        """The session is IRC: release a server password held back until now."""
        st.irc_seen = True
        if st.pending_pass is not None:
            self._emit(ctx, Kind.PASSWORD, secret=st.pending_pass, risk="high", extra={"field": "server password"})
            st.pending_pass = None

    def _emit(self, ctx: Context, kind: Kind, **kw: object) -> None:
        ctx.emit(Direction.CLIENT_TO_SERVER, kind, protocol="IRC", plugin=self.name, **kw)  # type: ignore[arg-type]

    def _line(self, ctx: Context, st: _State, line: bytes) -> None:
        upper = line[:16].upper()
        if upper.startswith(b"NICK "):
            nick = line[5:].split()[0] if line[5:].split() else b""
            st.nick = text(nick.lstrip(b":"))
            self._confirm(ctx, st)
            if not st.nick_reported and st.nick:
                st.nick_reported = True
                self._emit(ctx, Kind.USERNAME, username=st.nick, extra={"field": "nick"})
        elif upper.startswith(b"USER "):
            # IRC: USER <user> <mode> <unused> :<realname>. A single argument means FTP/POP3, not IRC.
            if len(line.split(b" ", 4)) >= 5:
                self._confirm(ctx, st)
            elif not st.irc_seen:
                ctx.detach()
        elif upper.startswith(b"PASS "):
            st.pending_pass = text(line[5:].lstrip(b":").strip())
            if st.irc_seen:
                self._confirm(ctx, st)
        elif upper.startswith(b"CAP REQ") and b"sasl" in line.lower():
            st.irc_seen = True
        elif upper.startswith(b"AUTHENTICATE "):
            st.irc_seen = True
            arg = line[13:].strip()
            if arg.upper() == b"PLAIN":
                st.sasl_plain = True
            elif st.sasl_plain and arg not in (b"+", b"*"):
                st.sasl_plain = False
                decoded = b64decode(arg)
                parts = sasl_plain(decoded) if decoded else None
                if parts:
                    self._emit(ctx, Kind.CREDENTIAL, username=parts[1] or parts[0], secret=parts[2], risk="high",
                               extra={"mechanism": "SASL PLAIN"})  # fmt: skip
        else:
            m = _NS_PRIVMSG.match(line) or _NS_SHORT.match(line)
            if m is None:
                low = line.lower()
                idx = low.find(b"nickserv :identify ")
                if idx >= 0:
                    rest = line[idx + 19 :].split()
                    m_args = rest[:2]
                else:
                    return
            else:
                m_args = [g for g in m.groups() if g]
            st.irc_seen = True
            account: str | None
            if len(m_args) == 2:
                account, password = text(m_args[0]), text(m_args[1])
            else:
                account, password = st.nick, text(m_args[0]) if m_args else ""
            self._emit(ctx, Kind.CREDENTIAL, username=account, secret=password, risk="high",
                       extra={"mechanism": "NickServ IDENTIFY"})  # fmt: skip
