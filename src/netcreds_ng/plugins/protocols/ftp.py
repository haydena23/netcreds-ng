"""FTP cleartext login (USER / PASS / ACCT) with login result tracking."""

from __future__ import annotations

from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, text

_GIVE_UP_BYTES = 16 * 1024
_MAIL_PORTS = frozenset({110, 995, 143, 993})


@dataclass
class _State:
    lines: tuple[LineBuffer, LineBuffer] = field(default_factory=lambda: (LineBuffer(), LineBuffer()))
    user: str | None = None
    password_sent: bool = False
    awaiting_result: bool = False
    client_bytes: int = 0
    greeting_seen: bool = False
    ftp_greeting: bool = False
    orphan_pass: str | None = None


class FTPPlugin(ProtocolPlugin):
    name = "ftp"
    sets = ("file-transfer", "legacy")
    description = "FTP USER/PASS logins and login success/failure (any port)"
    default_ports = frozenset({21})
    priority = 10

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.state.lines[direction].gap()  # never splice a command across missing bytes

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        lines = st.lines[direction].feed(data)
        if direction is Direction.SERVER_TO_CLIENT and st.greeting_seen and not st.awaiting_result:
            return  # _server_line only reads the greeting and login replies: nothing to do (bulk transfers)
        for line in lines:
            if ctx.detached:
                return
            if direction is Direction.SERVER_TO_CLIENT:
                self._server_line(ctx, st, line)
            else:
                self._client_line(ctx, st, line)
        if direction is Direction.CLIENT_TO_SERVER:
            st.client_bytes += len(data)
            if st.user is None and not st.password_sent and st.client_bytes > _GIVE_UP_BYTES:
                ctx.detach()

    def _server_line(self, ctx: Context, st: _State, line: bytes) -> None:
        if not st.greeting_seen and line:
            st.greeting_seen = True
            # POP3 / IMAP greetings: their USER/PASS commands belong to the mail plugin.
            if line.startswith((b"+OK", b"* OK", b"* PREAUTH")):
                ctx.detach()
                return
            if line.startswith(b"220") and b"SMTP" not in line.upper():
                st.ftp_greeting = True
                if st.orphan_pass is not None:
                    ctx.emit(Direction.CLIENT_TO_SERVER, Kind.PASSWORD, protocol="FTP", secret=st.orphan_pass,
                             plugin=self.name, risk="high")  # fmt: skip
                    st.orphan_pass = None
        if st.awaiting_result and line[:3] in (b"230", b"530", b"430"):
            st.awaiting_result = False
            ok = line.startswith(b"230")
            ctx.emit(
                Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="FTP", reverse=True,
                username=st.user, value="login succeeded" if ok else "login failed",
                plugin=self.name, extra={"reply": text(line[:120])},
            )  # fmt: skip

    def _client_line(self, ctx: Context, st: _State, line: bytes) -> None:
        cmd, _, arg = line.partition(b" ")
        verb = cmd.upper()
        tags = [] if ctx.flow.server.port == 21 else ["nonstandard-port"]
        if not st.ftp_greeting and ctx.flow.server.port in _MAIL_PORTS:
            ctx.detach()  # POP3/IMAP port without an FTP greeting: the mail plugin owns USER/PASS here
            return
        if verb in (b"NICK", b"EHLO", b"HELO", b"CAP") or (verb == b"USER" and len(arg.split()) > 1):
            ctx.detach()  # IRC / SMTP share USER/PASS-like commands; FTP's USER takes one argument
            return
        if verb == b"PASS" and st.user is None and not self._ftp_context(ctx, st):
            st.orphan_pass = text(arg.strip())  # wait: only an FTP USER/greeting makes this an FTP password
            return
        if verb == b"USER" and arg.strip():
            if st.user is not None and not st.password_sent:
                self._emit_username(ctx, st)
            st.user = text(arg.strip())
            st.password_sent = False
        elif verb == b"PASS":
            secret = text(arg.strip())
            kind = Kind.CREDENTIAL if st.user is not None else Kind.PASSWORD
            ctx.emit(
                Direction.CLIENT_TO_SERVER, kind, protocol="FTP", username=st.user, secret=secret,
                plugin=self.name, risk="high", tags=tags,
            )  # fmt: skip
            st.password_sent = True
            st.awaiting_result = True
        elif verb == b"ACCT" and arg.strip():
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.PASSWORD, protocol="FTP", secret=text(arg.strip()),
                username=st.user, plugin=self.name, risk="medium", tags=tags, extra={"command": "ACCT"},
            )  # fmt: skip

    @staticmethod
    def _ftp_context(ctx: Context, st: _State) -> bool:
        return st.ftp_greeting or ctx.flow.server.port == 21

    def _emit_username(self, ctx: Context, st: _State) -> None:
        ctx.emit(Direction.CLIENT_TO_SERVER, Kind.USERNAME, protocol="FTP", username=st.user, plugin=self.name)

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        if st.user is not None and not st.password_sent:
            self._emit_username(ctx, st)
