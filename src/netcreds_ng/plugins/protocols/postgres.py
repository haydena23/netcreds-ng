"""PostgreSQL login exposure (StartupMessage, authentication requests, password messages).

Scope: cleartext passwords are reported in full as credentials. MD5 and SCRAM logins are
reported as metadata only; digests, salts, nonces and SASL payloads are never extracted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_MAX_BUFFER = 1024 * 1024
_MAX_MESSAGE = 64 * 1024
_MAX_STARTUP = 10 * 1024  # PostgreSQL's own limit for startup packets

_SSL_REQUEST = 80877103
_GSSENC_REQUEST = 80877104

_STARTUP, _AUTH = 0, 1


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    phase: int = _STARTUP
    pending_enc: bool = False  # SSLRequest / GSSENCRequest sent, waiting for the 1-byte answer
    started: bool = False
    params: dict[str, str] = field(default_factory=dict)
    method: str | None = None  # "cleartext" | "md5" | "sasl" | "other"
    reported: bool = False  # client's password/SASL message already reported
    password_seen: bool = False


class PostgresPlugin(ProtocolPlugin):
    name = "postgres"
    description = "PostgreSQL logins: cleartext passwords and login metadata (any port)"
    default_ports = frozenset({5432})
    priority = 91

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        st.bufs[direction].extend(data)
        self._pump(ctx, st)

    def _pump(self, ctx: Context, st: _State) -> None:
        # Client and server are processed in turn: the server's SSL answer unblocks the client.
        for _ in range(64):
            if ctx.detached:
                return
            progressed = self._server(ctx, st) | self._client(ctx, st)
            if not progressed:
                break
        for b in st.bufs:
            if len(b) > _MAX_BUFFER:
                ctx.detach()
                return

    # -- client ------------------------------------------------------------------------
    def _client(self, ctx: Context, st: _State) -> bool:
        buf = st.bufs[Direction.CLIENT_TO_SERVER]
        progressed = False
        while not ctx.detached and buf and not st.pending_enc:
            if st.phase == _STARTUP:
                if len(buf) < 8:
                    break
                length, code = struct.unpack_from("!II", buf, 0)
                if length < 8 or length > _MAX_STARTUP:
                    ctx.detach()
                    return True
                if len(buf) < length:
                    break
                body = bytes(buf[8:length])
                del buf[:length]
                progressed = True
                if code in (_SSL_REQUEST, _GSSENC_REQUEST):
                    st.pending_enc = True
                elif code >> 16 == 3:
                    st.params = self._params(body)
                    st.started = True
                    st.phase = _AUTH
                else:  # CancelRequest or unknown protocol
                    ctx.detach()
                    return True
            else:
                if len(buf) < 5:
                    break
                mtype = buf[0]
                length = struct.unpack_from("!I", buf, 1)[0]
                if length < 4 or length > _MAX_MESSAGE:
                    ctx.detach()
                    return True
                if len(buf) < 1 + length:
                    break
                body = bytes(buf[5 : 1 + length])
                del buf[: 1 + length]
                progressed = True
                if mtype == 0x70:  # 'p'
                    self._password_message(ctx, st, body)
                # Other client messages (Terminate, queries) are not parsed.
        return progressed

    @staticmethod
    def _params(body: bytes) -> dict[str, str]:
        parts = body.split(b"\x00")
        out: dict[str, str] = {}
        for i in range(0, len(parts) - 1, 2):
            key = parts[i]
            if not key:
                break
            out[text(key[:64])] = text(parts[i + 1][:256])
        return out

    def _password_message(self, ctx: Context, st: _State, body: bytes) -> None:
        if st.method is None or st.reported:
            return
        if st.method == "cleartext":
            st.reported = True
            st.password_seen = True
            end = body.find(b"\x00")
            pw = body if end < 0 else body[:end]
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.CREDENTIAL, protocol="PostgreSQL",
                username=st.params.get("user"), secret=text(pw[:256]), plugin=self.name,
                risk="high", tags=self._tags(ctx, "cleartext-password"), extra=self._extra(st),
            )  # fmt: skip
        elif st.method == "md5":
            st.reported = True
            st.password_seen = True
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="PostgreSQL",
                username=st.params.get("user"), value="PostgreSQL MD5 password authentication",
                plugin=self.name, risk="medium", tags=self._tags(ctx),
                extra={**self._extra(st), "method": "md5"},
            )  # fmt: skip
        elif st.method == "sasl":
            st.reported = True
            st.password_seen = True
            end = body.find(b"\x00")
            mech = text(body[: min(end, 64)]) if end > 0 else ""
            extra = {**self._extra(st), "method": "sasl"}
            if mech and mech.isprintable():
                extra["mechanism"] = mech
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="PostgreSQL",
                username=st.params.get("user"), value="PostgreSQL SCRAM authentication",
                plugin=self.name, risk="low", tags=self._tags(ctx), extra=extra,
            )  # fmt: skip

    # -- server ------------------------------------------------------------------------
    def _server(self, ctx: Context, st: _State) -> bool:
        buf = st.bufs[Direction.SERVER_TO_CLIENT]
        progressed = False
        while not ctx.detached and buf:
            if st.pending_enc:
                answer = buf[0]
                del buf[:1]
                progressed = True
                if answer == 0x4E:  # 'N': plaintext continues
                    st.pending_enc = False
                    continue
                ctx.detach()  # 'S' (encrypted) or anything unexpected
                return True
            if not st.started:
                ctx.detach()  # the server never speaks before the StartupMessage
                return True
            if len(buf) < 5:
                break
            mtype = buf[0]
            length = struct.unpack_from("!I", buf, 1)[0]
            if mtype not in (0x52, 0x45, 0x4E, 0x53, 0x4B, 0x5A) or length < 4 or length > _MAX_MESSAGE:
                ctx.detach()
                return True
            if len(buf) < 1 + length:
                break
            body = bytes(buf[5 : 1 + length])
            del buf[: 1 + length]
            progressed = True
            if mtype == 0x52:
                self._auth_request(ctx, st, body)
            elif mtype == 0x45:
                self._error(ctx, st, body)
                ctx.detach()
            elif mtype in (0x53, 0x4B, 0x5A):  # ParameterStatus / BackendKeyData / ReadyForQuery
                ctx.detach()
        return progressed

    def _auth_request(self, ctx: Context, st: _State, body: bytes) -> None:
        if len(body) < 4:
            return
        code = struct.unpack_from("!I", body, 0)[0]
        if code == 0:
            if st.method is None:
                ctx.emit(
                    Direction.SERVER_TO_CLIENT, Kind.AUTH_EVENT, protocol="PostgreSQL", reverse=True,
                    username=st.params.get("user"), value="PostgreSQL login without password (trust)",
                    plugin=self.name, risk="high", tags=self._tags(ctx, "no-authentication"),
                    extra=self._extra(st),
                )  # fmt: skip
            else:
                self._result(ctx, st, ok=True, extra={})
            ctx.detach()
        elif code == 3:
            st.method = "cleartext"
            st.reported = False
        elif code == 5:
            st.method = "md5"
            st.reported = False
        elif code == 10:
            st.method = "sasl"
            st.reported = False
        elif code in (11, 12):
            if st.method is None:
                st.method = "sasl"
                st.reported = True
        elif st.method is None:
            st.method = "other"

    def _error(self, ctx: Context, st: _State, body: bytes) -> None:
        sqlstate = ""
        for field_ in body.split(b"\x00"):
            if field_[:1] == b"C":
                sqlstate = text(field_[1:6])
                break
        if sqlstate.startswith("28"):  # 28P01 invalid_password, 28000 invalid_authorization_specification
            self._result(ctx, st, ok=False, extra={"sqlstate": sqlstate})

    # -- emission ----------------------------------------------------------------------
    def _tags(self, ctx: Context, *more: str) -> list[str]:
        tags = list(more)
        if ctx.flow.server.port != 5432:
            tags.append("nonstandard-port")
        return tags

    @staticmethod
    def _extra(st: _State) -> dict[str, object]:
        extra: dict[str, object] = {}
        for key in ("database", "application_name"):
            if key in st.params:
                extra[key] = st.params[key]
        return extra

    def _result(self, ctx: Context, st: _State, *, ok: bool, extra: dict[str, object]) -> None:
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="PostgreSQL", reverse=True,
            username=st.params.get("user"), value="login succeeded" if ok else "login failed",
            plugin=self.name, tags=self._tags(ctx), extra=extra,
        )  # fmt: skip
