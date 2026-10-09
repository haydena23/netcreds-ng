"""Redis AUTH (RESP arrays and inline), HELLO ... AUTH, and the server's verdict."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import LineBuffer, text

_GIVE_UP_BYTES = 16 * 1024
_MAX_BUFFER = 64 * 1024  # larger command frames are not buffered (never an AUTH)
_MAX_ARGS = 64
# Inline (non-RESP) commands are only recognised for this small set, so that plain-text
# protocols (for example "GET / HTTP/1.1") are not mistaken for Redis.
_INLINE_COMMANDS = frozenset({b"AUTH", b"HELLO", b"PING", b"QUIT", b"INFO", b"SELECT", b"ECHO", b"CLIENT"})
_SASL_MECHANISMS = frozenset({b"PLAIN", b"LOGIN", b"CRAM-MD5", b"DIGEST-MD5", b"NTLM", b"GSSAPI", b"XOAUTH2",
                              b"OAUTHBEARER", b"SCRAM-SHA-1", b"SCRAM-SHA-256", b"SCRAM-SHA-512", b"EXTERNAL",
                              b"ANONYMOUS", b"GSS-SPNEGO", b"TLS", b"SSL"})  # fmt: skip  (TLS/SSL: FTP "AUTH TLS")


class _Malformed(ValueError):
    pass


@dataclass
class _State:
    buf: bytearray = field(default_factory=bytearray)
    lines: LineBuffer = field(default_factory=LineBuffer)
    pending: deque[str | None] = field(default_factory=deque)  # usernames of AUTHs awaiting a reply
    client_bytes: int = 0
    recognised: bool = False
    resync: bool = False  # after a gap: skip to the next RESP array header


# A command array starts a line: "\r\n*<count>\r\n$" (the previous command's terminator first).
_RESP_START = re.compile(rb"\r\n\*[1-9][0-9]?\r\n\$")


def _parse_resp(buf: bytearray) -> tuple[list[bytes], int] | None:
    """Parse one RESP array of bulk strings; None if incomplete; _Malformed if not RESP."""
    end = buf.find(b"\r\n")
    if end < 0:
        if len(buf) > 32:
            raise _Malformed("no array header")
        return None
    try:
        count = int(buf[1:end])
    except ValueError:
        raise _Malformed("bad array length") from None
    if not 1 <= count <= _MAX_ARGS:
        raise _Malformed("unsupported array length")
    pos = end + 2
    args: list[bytes] = []
    for _ in range(count):
        end = buf.find(b"\r\n", pos)
        if end < 0:
            if len(buf) - pos > 32:
                raise _Malformed("no bulk header")
            return None
        if buf[pos] != 0x24:  # '$'
            raise _Malformed("expected bulk string")
        try:
            size = int(buf[pos + 1 : end])
        except ValueError:
            raise _Malformed("bad bulk length") from None
        if not 0 <= size <= _MAX_BUFFER:
            raise _Malformed("unsupported bulk length")
        start = end + 2
        if len(buf) < start + size + 2:
            return None
        if buf[start + size : start + size + 2] != b"\r\n":
            raise _Malformed("bulk string not terminated")
        args.append(bytes(buf[start : start + size]))
        pos = start + size + 2
    return args, pos


class RedisPlugin(ProtocolPlugin):
    name = "redis"
    description = "Redis AUTH / HELLO AUTH passwords and their results (any port)"
    default_ports = frozenset({6379})
    priority = 92

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        st: _State = ctx.state
        if not st.recognised:
            ctx.detach()
            return
        if direction is Direction.SERVER_TO_CLIENT:
            st.lines.gap()
        else:
            st.buf.clear()
            st.resync = True
        # Replies are matched to AUTHs by order; a hole in either direction breaks that order.
        st.pending.clear()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        if direction is Direction.CLIENT_TO_SERVER and st.resync:
            st.buf += data
            data = b""
            # A leading CRLF lets an array that starts right at the hole match too.
            m = _RESP_START.search(b"\r\n" + bytes(st.buf))
            if m is None:
                del st.buf[: max(0, len(st.buf) - 16)]
                return
            del st.buf[: m.start()]  # offset by the prepended CRLF: buf now starts at the '*'
            st.resync = False
        if direction is Direction.SERVER_TO_CLIENT:
            if not st.recognised and data:
                # A Redis server never speaks first; greetings mean SMTP/POP3/IMAP/FTP/... instead.
                ctx.detach()
                return
            if st.pending:
                for line in st.lines.feed(data):
                    self._server_line(ctx, st, line)
            return
        st.client_bytes += len(data)
        st.buf += data
        try:
            self._client(ctx, st)
        except _Malformed:
            if st.recognised:
                st.buf.clear()  # resynchronising mid-stream is not possible; keep watching
            else:
                ctx.detach()
        if not st.recognised and st.client_bytes > _GIVE_UP_BYTES:
            ctx.detach()
        if ctx.detached:
            st.buf.clear()

    def _client(self, ctx: Context, st: _State) -> None:
        buf = st.buf
        while buf and not ctx.detached:
            if buf[0] == 0x2A:  # '*'
                parsed = _parse_resp(buf)
                if parsed is None:
                    return
                args, used = parsed
                del buf[:used]
                st.recognised = True
                self._command(ctx, st, args)
                continue
            end = buf.find(b"\n")
            if end < 0:
                if not st.recognised and (buf[0] < 0x20 or buf[0] > 0x7E):
                    ctx.detach()
                elif len(buf) > _MAX_BUFFER:
                    buf.clear()
                return
            line = bytes(buf[:end]).rstrip(b"\r")
            del buf[: end + 1]
            args = line.split()
            if args and args[0].upper() in _INLINE_COMMANDS:
                st.recognised = True
                self._command(ctx, st, args)
            elif not st.recognised and (not line or any(b < 0x20 or b > 0x7E for b in line)):
                ctx.detach()
                return

    def _command(self, ctx: Context, st: _State, args: list[bytes]) -> None:
        verb = args[0].upper()
        user: bytes | None
        if verb == b"AUTH" and len(args) in (2, 3):
            if args[1].upper() in _SASL_MECHANISMS:
                ctx.detach()  # SMTP/POP3/IMAP "AUTH <mechanism>", not Redis
                return
            user, password = (args[1], args[2]) if len(args) == 3 else (None, args[1])
        elif verb == b"HELLO":
            idx = next((i for i, a in enumerate(args) if i >= 2 and a.upper() == b"AUTH"), -1)
            if idx < 0 or len(args) < idx + 3:
                return
            user, password = args[idx + 1], args[idx + 2]
        else:
            return
        username = text(user) if user is not None else None
        tags = [] if ctx.flow.server.port == 6379 else ["nonstandard-port"]
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.CREDENTIAL if username is not None else Kind.PASSWORD,
            protocol="Redis", plugin=self.name, username=username, secret=text(password),
            risk="high", tags=tags, extra={"command": verb.decode("ascii")},
        )  # fmt: skip
        st.pending.append(username)

    def _server_line(self, ctx: Context, st: _State, line: bytes) -> None:
        if not st.pending or not line or line[:1] not in (b"+", b"-", b"%", b"*"):
            return
        upper = line.upper()
        if line[:1] == b"-":
            if not (upper.startswith(b"-WRONGPASS") or b"INVALID PASSWORD" in upper or b"AUTH" in upper):
                return  # some other error; not a verdict on the login
            ok = False
        elif line[:1] == b"+":
            if not upper.startswith(b"+OK"):
                return  # e.g. +PONG for a pipelined command
            ok = True
        else:
            ok = True  # HELLO success replies with a map / array
        user = st.pending.popleft()
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="Redis", reverse=True, plugin=self.name,
            username=user, value="login succeeded" if ok else "login failed",
            extra={"reply": text(line[:120])},
        )  # fmt: skip
