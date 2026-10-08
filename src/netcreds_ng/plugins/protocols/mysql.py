"""MySQL / MariaDB login exposure (HandshakeResponse41, AuthSwitch, OK/ERR results).

Scope: cleartext passwords (``mysql_clear_password``) are reported in full as credentials.
Challenge/response logins (``mysql_native_password``, ``caching_sha2_password``, ...) are
reported as metadata only; the scramble / auth-response bytes are never extracted or stored.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_MAX_BUFFER = 1024 * 1024
_MAX_PACKET = 64 * 1024  # authentication-phase packets are small; larger means "not MySQL"

CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SSL = 0x00000800
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000

_CLEAR = "mysql_clear_password"
_NATIVE = "mysql_native_password"

# phases
_WAIT_HELLO, _WAIT_RESPONSE, _AUTH = 0, 1, 2


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    phase: int = _WAIT_HELLO
    server_version: str | None = None
    server_plugin: str | None = None
    user: str | None = None
    database: str | None = None
    plugin: str | None = None
    switch_plugin: str | None = None  # set after an AuthSwitchRequest, until the client replies


def _cstr(buf: bytes, pos: int) -> tuple[bytes, int] | None:
    """NUL-terminated string at ``pos``; returns (value, position after NUL) or None if unterminated."""
    end = buf.find(b"\x00", pos)
    if end < 0:
        return None
    return buf[pos:end], end + 1


def _lenenc(buf: bytes, pos: int) -> tuple[int, int] | None:
    if pos >= len(buf):
        return None
    first = buf[pos]
    if first < 0xFB:
        return first, pos + 1
    if first == 0xFB:
        return 0, pos + 1
    width = {0xFC: 2, 0xFD: 3, 0xFE: 8}.get(first)
    if width is None or pos + 1 + width > len(buf):
        return None
    return int.from_bytes(buf[pos + 1 : pos + 1 + width], "little"), pos + 1 + width


class MySQLPlugin(ProtocolPlugin):
    name = "mysql"
    description = "MySQL/MariaDB logins: cleartext passwords and login metadata (any port)"
    default_ports = frozenset({3306})
    priority = 90

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    # -- stream plumbing ---------------------------------------------------------------
    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.bufs[direction]
        buf += data
        while not ctx.detached:
            if len(buf) < 4:
                break
            length = int.from_bytes(buf[0:3], "little")
            if length > _MAX_PACKET or length == 0:
                ctx.detach()
                return
            if len(buf) < 4 + length:
                break
            payload = bytes(buf[4 : 4 + length])
            del buf[: 4 + length]
            if direction is Direction.SERVER_TO_CLIENT:
                self._server_packet(ctx, st, payload)
            else:
                self._client_packet(ctx, st, payload)
        if len(buf) > _MAX_BUFFER:
            ctx.detach()

    # -- server ------------------------------------------------------------------------
    def _server_packet(self, ctx: Context, st: _State, payload: bytes) -> None:
        if st.phase == _WAIT_HELLO:
            self._hello(ctx, st, payload)
            return
        if st.phase != _AUTH:
            return
        marker = payload[0]
        if marker == 0x00:
            self._result(ctx, st, ok=True, extra={})
            ctx.detach()
        elif marker == 0xFF:
            code = struct.unpack_from("<H", payload, 1)[0] if len(payload) >= 3 else None
            msg = payload[3:]
            if msg[:1] == b"#":  # SQL state marker + 5 chars
                msg = msg[6:]
            extra: dict[str, object] = {"error_code": code} if code is not None else {}
            extra["message"] = text(msg[:120])
            self._result(ctx, st, ok=False, extra=extra)
            ctx.detach()
        elif marker == 0xFE and len(payload) > 1:
            parsed = _cstr(payload, 1)
            if parsed is None:
                return
            st.switch_plugin = text(parsed[0][:64])

    def _hello(self, ctx: Context, st: _State, payload: bytes) -> None:
        if payload[0] != 10:
            ctx.detach()
            return
        ver = _cstr(payload, 1)
        if ver is None or not ver[0] or any(b < 0x20 or b > 0x7E for b in ver[0]):
            ctx.detach()
            return
        st.server_version = text(ver[0][:64])
        pos = ver[1]
        # thread id(4) + auth-data-1(8) + filler(1) + caps-low(2) is the minimum for v10
        if len(payload) < pos + 15:
            ctx.detach()
            return
        caps = struct.unpack_from("<H", payload, pos + 13)[0]
        # Optional tail: charset(1) status(2) caps-high(2) auth-len(1) reserved(10) auth-data-2 plugin\0
        tail = pos + 15
        if len(payload) >= tail + 8:
            caps |= struct.unpack_from("<H", payload, tail + 3)[0] << 16
            auth_len = payload[tail + 5]
            if caps & CLIENT_PLUGIN_AUTH:
                at = tail + 6 + 10 + max(13, auth_len - 8)
                got = _cstr(payload, at) if at <= len(payload) else None
                rest = payload[at:] if got is None else got[0]
                if rest:
                    st.server_plugin = text(rest[:64])
        st.phase = _WAIT_RESPONSE

    # -- client ------------------------------------------------------------------------
    def _client_packet(self, ctx: Context, st: _State, payload: bytes) -> None:
        if st.phase == _WAIT_HELLO:
            ctx.detach()  # client spoke before any server handshake: not a login we can interpret
            return
        if st.phase == _WAIT_RESPONSE:
            self._response(ctx, st, payload)
            return
        if st.switch_plugin is not None:
            plugin, st.switch_plugin = st.switch_plugin, None
            if plugin == _CLEAR:
                end = payload.find(b"\x00")
                pw = payload if end < 0 else payload[:end]
                self._emit_cleartext(ctx, st, pw, plugin)
            elif plugin != st.plugin:
                st.plugin = plugin
                self._emit_event(ctx, st, plugin, empty=False)
        # Any other client packet (cache full-auth, RSA-encrypted blobs, queries) is ignored.

    def _response(self, ctx: Context, st: _State, p: bytes) -> None:
        if len(p) < 2:
            ctx.detach()
            return
        caps = struct.unpack_from("<H", p, 0)[0]
        if len(p) >= 4:
            caps = struct.unpack_from("<I", p, 0)[0]
        if not caps & CLIENT_PROTOCOL_41:
            self._response_320(ctx, st, p)
            return
        if len(p) == 32 and caps & CLIENT_SSL:
            ctx.detach()  # SSLRequest: the rest of the session is TLS
            return
        if len(p) < 33:
            ctx.detach()
            return
        user = _cstr(p, 32)
        if user is None:
            ctx.detach()
            return
        pos = user[1]
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            n = _lenenc(p, pos)
            if n is None:
                ctx.detach()
                return
            alen, pos = n
        elif caps & CLIENT_SECURE_CONNECTION:
            if pos >= len(p):
                ctx.detach()
                return
            alen, pos = p[pos], pos + 1
        else:
            nul = _cstr(p, pos)
            if nul is None:
                ctx.detach()
                return
            alen, pos = len(nul[0]), pos
        if pos + alen > len(p):
            ctx.detach()
            return
        auth = p[pos : pos + alen]
        pos += alen if (caps & (CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_SECURE_CONNECTION)) else alen + 1
        database = None
        if caps & CLIENT_CONNECT_WITH_DB:
            db = _cstr(p, pos)
            if db is not None:
                database, pos = text(db[0][:128]), db[1]
        plugin = _NATIVE
        if caps & CLIENT_PLUGIN_AUTH:
            name = _cstr(p, pos)
            raw = p[pos:] if name is None else name[0]
            if raw:
                plugin = text(raw[:64])
        st.user = text(user[0][:128])
        st.database = database
        st.plugin = plugin
        st.phase = _AUTH
        if plugin == _CLEAR:
            self._emit_cleartext(ctx, st, auth.rstrip(b"\x00") if auth.endswith(b"\x00") else auth, plugin)
        else:
            self._emit_event(ctx, st, plugin, empty=alen == 0)

    def _response_320(self, ctx: Context, st: _State, p: bytes) -> None:
        # HandshakeResponse320 (pre-4.1): caps(2) max-packet(3) user\0 [scrambled password\0 [db]]
        # The pre-4.1 password field is a scramble, not cleartext, so it is reported as metadata only.
        if len(p) < 6:
            ctx.detach()
            return
        user = _cstr(p, 5)
        if user is None:
            ctx.detach()
            return
        st.user = text(user[0][:128])
        st.plugin = "pre-4.1 authentication"
        st.phase = _AUTH
        self._emit_event(ctx, st, st.plugin, empty=False)

    # -- emission ----------------------------------------------------------------------
    def _tags(self, ctx: Context, *more: str) -> list[str]:
        tags = list(more)
        if ctx.flow.server.port != 3306:
            tags.append("nonstandard-port")
        return tags

    def _extra(self, st: _State, plugin: str) -> dict[str, object]:
        extra: dict[str, object] = {"plugin": plugin}
        if st.database is not None:
            extra["database"] = st.database
        if st.server_version is not None:
            extra["server_version"] = st.server_version
        return extra

    def _emit_event(self, ctx: Context, st: _State, plugin: str, *, empty: bool) -> None:
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="MySQL", username=st.user,
            value=f"MySQL login ({plugin})", plugin=self.name,
            risk="high" if empty else "medium",
            tags=self._tags(ctx, *(["empty-password"] if empty else [])),
            extra=self._extra(st, plugin),
        )  # fmt: skip

    def _emit_cleartext(self, ctx: Context, st: _State, password: bytes, plugin: str) -> None:
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.CREDENTIAL, protocol="MySQL", username=st.user,
            secret=text(password[:256]), plugin=self.name, risk="high",
            tags=self._tags(ctx, "cleartext-password"), extra=self._extra(st, plugin),
        )  # fmt: skip

    def _result(self, ctx: Context, st: _State, *, ok: bool, extra: dict[str, object]) -> None:
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="MySQL", reverse=True,
            username=st.user, value="login succeeded" if ok else "login failed",
            plugin=self.name, tags=self._tags(ctx), extra=extra,
        )  # fmt: skip
