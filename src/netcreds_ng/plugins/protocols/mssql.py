"""Microsoft SQL Server (TDS) login exposure: PRELOGIN encryption, LOGIN7, login results.

Scope: the LOGIN7 password field is only "obfuscated" with a fixed public transform
(nibble swap + XOR 0xA5), which is not encryption, so a LOGIN7 seen in cleartext exposes
the password and is reported as a credential. Windows (SSPI) logins are reported as
metadata only: the mechanism and, if an NTLM AUTHENTICATE message is present, the
user/domain names; tokens, challenges and responses are never extracted.

Encryption (MS-TDS 2.2.6.5): when PRELOGIN negotiates encryption the LOGIN7 travels inside
TLS. ``ENCRYPT_OFF`` on both sides still encrypts the login packet ("login only"), after
which the session continues in cleartext; ``ENCRYPT_NOT_SUP`` means nothing is encrypted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.proto import ntlm

_MAX_BUFFER = 256 * 1024
_MAX_MESSAGE = 256 * 1024  # login-phase messages (LOGIN7 + SSPI) are far smaller

# packet types
PRELOGIN = 0x12
LOGIN7 = 0x10
SSPI = 0x11
TABULAR = 0x04
_CLIENT_TYPES = frozenset({0x01, 0x03, 0x06, 0x07, 0x0E, LOGIN7, SSPI, PRELOGIN})
_SERVER_TYPES = frozenset({TABULAR, PRELOGIN})
EOM = 0x01

# PRELOGIN ENCRYPTION option values
ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ = 0, 1, 2, 3

# tokens
TOKEN_LOGINACK = 0xAD
TOKEN_ERROR = 0xAA
_LEN16_TOKENS = frozenset({0xA9, 0xAA, 0xAB, 0xAD, 0xE3, 0xED})
_DONE_TOKENS = frozenset({0xFD, 0xFE, 0xFF})

#: Login-phase error numbers that mean "the login was rejected".
LOGIN_FAILED_ERRORS = frozenset({18456, 18452, 18470, 18486, 18487, 18488})

_TLS_RECORD_TYPES = frozenset({0x14, 0x15, 0x16, 0x17})

_FIELDS = ("host", "user", "password", "app", "server", "extension", "library", "language", "database")


def deobfuscate_password(raw: bytes) -> bytes:
    """Undo the public LOGIN7 password transform (XOR 0xA5, then swap nibbles)."""
    out = bytearray()
    for b in raw:
        x = b ^ 0xA5
        out.append(((x << 4) & 0xF0) | (x >> 4))
    return bytes(out)


def _u16(raw: bytes) -> str:
    return raw.decode("utf-16-le", "backslashreplace")


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    msgs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    msg_type: list[int | None] = field(default_factory=lambda: [None, None])
    started: bool = False
    client_enc: int | None = None
    server_version: str | None = None
    tls: str | None = None  # None | "full" | "login-only"
    tls_reported: bool = False
    login_seen: bool = False
    user: str | None = None
    domain: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    pending_windows: dict[str, Any] | None = None


class MSSQLPlugin(ProtocolPlugin):
    name = "mssql"
    sets = ("databases",)
    description = "Microsoft SQL Server (TDS) logins: de-obfuscated LOGIN7 passwords, login metadata (any port)"
    default_ports = frozenset({1433})
    priority = 92

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    # -- stream plumbing ---------------------------------------------------------------
    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.bufs[direction]
        buf += data
        client = direction is Direction.CLIENT_TO_SERVER
        while not ctx.detached:
            if client and not st.started and buf[:1] == b"\x16" and buf[1:2] == b"\x03":
                self._strict_tls(ctx, st, buf)
                return
            if client and st.tls == "login-only" and len(buf) >= 5 and buf[0] in _TLS_RECORD_TYPES and buf[1] == 3:
                rec = 5 + struct.unpack_from("!H", buf, 3)[0]
                if len(buf) < rec:
                    break
                del buf[:rec]  # the TLS-wrapped LOGIN7 (and TLS alerts): opaque by design
                continue
            if len(buf) < 8:
                break
            ptype, status, length = buf[0], buf[1], struct.unpack_from("!H", buf, 2)[0]
            if not self._valid_header(st, client, ptype, status, length, buf[7]):
                ctx.detach()
                return
            if len(buf) < length:
                break
            payload = bytes(buf[8:length])
            del buf[:length]
            st.started = True
            self._packet(ctx, st, direction, ptype, status, payload)
        if len(buf) > _MAX_BUFFER:
            ctx.detach()

    @staticmethod
    def _valid_header(st: _State, client: bool, ptype: int, status: int, length: int, window: int) -> bool:
        if length < 8 or status & 0xE0 or window != 0:
            return False
        if client:
            if not st.started:
                return ptype in (PRELOGIN, LOGIN7)
            return ptype in _CLIENT_TYPES
        return st.started and ptype in _SERVER_TYPES

    def _strict_tls(self, ctx: Context, st: _State, buf: bytearray) -> None:
        # TDS 8.0 ("strict" encryption): TLS starts before any TDS packet; ALPN names tds/8.0.
        if b"tds/8.0" in buf:
            self._emit_tls(ctx, st, "strict")
            ctx.detach()
        elif len(buf) >= 5 and len(buf) >= 5 + struct.unpack_from("!H", buf, 3)[0]:
            ctx.detach()  # plain TLS of some other protocol
        elif len(buf) > 16 * 1024:
            ctx.detach()

    def _packet(self, ctx: Context, st: _State, direction: Direction, ptype: int, status: int, payload: bytes) -> None:
        msg = st.msgs[direction]
        if st.msg_type[direction] != ptype:
            msg.clear()
            st.msg_type[direction] = ptype
        msg += payload
        if len(msg) > _MAX_MESSAGE:
            ctx.detach()
            return
        if not status & EOM:
            return
        body = bytes(msg)
        msg.clear()
        st.msg_type[direction] = None
        if direction is Direction.CLIENT_TO_SERVER:
            self._client_message(ctx, st, ptype, body)
        else:
            self._server_message(ctx, st, ptype, body)

    # -- client ------------------------------------------------------------------------
    def _client_message(self, ctx: Context, st: _State, ptype: int, body: bytes) -> None:
        if ptype == PRELOGIN:
            if body[:1] == b"\x16" and body[1:2] == b"\x03":  # TLS handshake carried in PRELOGIN
                mode = st.tls or "full"
                self._emit_tls(ctx, st, mode)
                if mode == "full":
                    ctx.detach()
                return
            opts = _prelogin_options(body)
            enc = opts.get(0x01)
            if enc:
                st.client_enc = enc[0] & 0x0F
        elif ptype == LOGIN7:
            self._login7(ctx, st, body)
        elif ptype == SSPI and st.pending_windows is not None:
            for msg in ntlm.find_messages(body):
                auth = ntlm.parse_authenticate(msg)
                if auth is not None:
                    st.user = auth.user[:128] or None
                    st.domain = auth.domain[:128] or None
                    st.pending_windows["mechanism"] = "NTLM"
                    self._flush_windows(ctx, st)
                    break

    def _login7(self, ctx: Context, st: _State, p: bytes) -> None:
        if len(p) < 86:
            ctx.detach()
            return
        tds_version = struct.unpack_from("<I", p, 4)[0]
        flags2 = p[25]
        values: dict[str, bytes] = {}
        for i, name in enumerate(_FIELDS):
            ib, cch = struct.unpack_from("<HH", p, 36 + 4 * i)
            if name == "extension":
                continue
            if ib + 2 * cch > len(p):
                ctx.detach()
                return
            values[name] = p[ib : ib + 2 * cch]
        st.login_seen = True
        st.extra = {"tds_version": f"0x{tds_version:08x}"}
        for key, name in (
            ("database", "database"),
            ("app", "app_name"),
            ("host", "client_host"),
            ("server", "server_name"),
        ):
            if values[key]:
                st.extra[name] = _u16(values[key][:256])
        if st.server_version:
            st.extra["server_version"] = st.server_version
        if st.client_enc is not None:
            st.extra["encryption"] = "none"
        if flags2 & 0x80:  # fIntSecurity: Windows / SSPI authentication
            ib, cb = struct.unpack_from("<HH", p, 78)
            if cb == 0xFFFF and len(p) >= 94:
                cb = struct.unpack_from("<I", p, 90)[0]
            blob = p[ib : ib + cb] if ib + cb <= len(p) else b""
            if b"NTLMSSP\x00" in blob:
                mech = "NTLM"
            elif blob[:1] == b"\x60":
                mech = "Negotiate"
            else:
                mech = "SSPI"
            st.user = _u16(values["user"][:256]) or None
            st.pending_windows = {"mechanism": mech}
            return
        st.user = _u16(values["user"][:256])
        password = _u16(deobfuscate_password(values["password"][:512]))
        tags = self._tags(ctx, "cleartext-password", *(["empty-password"] if not password else []))
        self._emit_credential(ctx, st, password, tags)
        if len(p) >= 94 and tds_version >= 0x72000000 and (p[27] & 0x01):  # fChangePassword
            ib, cch = struct.unpack_from("<HH", p, 86)
            if 0 < cch and ib + 2 * cch <= len(p):
                new = _u16(deobfuscate_password(p[ib : ib + 2 * cch][:512]))
                self._emit_credential(ctx, st, new, self._tags(ctx, "cleartext-password", "password-change"))

    # -- server ------------------------------------------------------------------------
    def _server_message(self, ctx: Context, st: _State, ptype: int, body: bytes) -> None:
        if ptype != TABULAR:
            return  # server half of the TLS handshake (wrapped in PRELOGIN packets)
        if not st.login_seen and st.tls is None and not st.tls_reported and st.client_enc is not None:
            self._prelogin_response(ctx, st, body)
            return
        if st.login_seen or st.tls == "login-only":
            self._tokens(ctx, st, body)

    def _prelogin_response(self, ctx: Context, st: _State, body: bytes) -> None:
        opts = _prelogin_options(body)
        ver = opts.get(0x00)
        if ver is not None and len(ver) >= 6:
            st.server_version = f"{ver[0]}.{ver[1]}.{struct.unpack_from('!H', ver, 2)[0]}"
        enc = opts.get(0x01)
        if not enc or st.client_enc is None:
            return
        c, s = st.client_enc, enc[0] & 0x0F
        if ENCRYPT_NOT_SUP in (c, s):
            if c in (ENCRYPT_ON, ENCRYPT_REQ) or s in (ENCRYPT_ON, ENCRYPT_REQ):
                ctx.detach()  # incompatible settings: the connection is terminated
            return  # nothing is encrypted: a cleartext LOGIN7 follows
        mode = "login-only" if (c, s) == (ENCRYPT_OFF, ENCRYPT_OFF) else "full"
        st.tls = mode
        self._emit_tls(ctx, st, mode)
        if mode == "full":
            ctx.detach()

    def _tokens(self, ctx: Context, st: _State, p: bytes) -> None:
        pos = 0
        while pos < len(p):
            tok = p[pos]
            if tok in _LEN16_TOKENS:
                if pos + 3 > len(p):
                    return
                ln = struct.unpack_from("<H", p, pos + 1)[0]
                body = p[pos + 3 : pos + 3 + ln]
                if len(body) < ln:
                    return
                if tok == TOKEN_LOGINACK:
                    self._loginack(ctx, st, body)
                    return
                if tok == TOKEN_ERROR and self._error(ctx, st, body):
                    return
                pos += 3 + ln
            elif tok == 0xAE:  # FEATUREEXTACK
                pos += 1
                while pos < len(p) and p[pos] != 0xFF:
                    if pos + 5 > len(p):
                        return
                    pos += 5 + struct.unpack_from("<I", p, pos + 1)[0]
                pos += 1
            elif tok == 0xEE:  # FEDAUTHINFO
                if pos + 5 > len(p):
                    return
                pos += 5 + struct.unpack_from("<I", p, pos + 1)[0]
            else:
                return  # DONE or a token we do not walk: end of the login response

    def _loginack(self, ctx: Context, st: _State, body: bytes) -> None:
        extra: dict[str, Any] = {}
        if len(body) >= 6:
            extra["tds_version"] = f"0x{struct.unpack_from('!I', body, 1)[0]:08x}"
            n = body[5]
            if 6 + 2 * n <= len(body):
                extra["server_program"] = _u16(body[6 : 6 + 2 * n][:128])
        self._result(ctx, st, ok=True, extra=extra)
        ctx.detach()

    def _error(self, ctx: Context, st: _State, body: bytes) -> bool:
        if len(body) < 8:
            return False
        number = struct.unpack_from("<i", body, 0)[0]
        if number not in LOGIN_FAILED_ERRORS:
            return False
        n = struct.unpack_from("<H", body, 6)[0]
        msg = _u16(body[8 : 8 + 2 * n])[:120]
        self._result(ctx, st, ok=False, extra={"error_code": number, "message": msg})
        ctx.detach()
        return True

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        if st is not None and st.pending_windows is not None:
            self._flush_windows(ctx, st)

    # -- emission ----------------------------------------------------------------------
    def _tags(self, ctx: Context, *more: str) -> list[str]:
        tags = list(more)
        if ctx.flow.server.port != 1433:
            tags.append("nonstandard-port")
        return tags

    def _emit_tls(self, ctx: Context, st: _State, mode: str) -> None:
        if st.tls_reported:
            return
        st.tls_reported = True
        label = {"full": "TLS", "login-only": "TLS, login packet only", "strict": "TLS, TDS 8 strict"}[mode]
        extra: dict[str, Any] = {"encryption": mode}
        if st.server_version:
            extra["server_version"] = st.server_version
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="MSSQL", value=f"MSSQL login ({label})",
            plugin=self.name, risk="info", tags=self._tags(ctx, "encrypted"), extra=extra,
        )  # fmt: skip

    def _emit_credential(self, ctx: Context, st: _State, password: str, tags: list[str]) -> None:
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.CREDENTIAL, protocol="MSSQL", username=st.user,
            secret=password, plugin=self.name, risk="high", tags=tags, extra=dict(st.extra),
        )  # fmt: skip

    def _flush_windows(self, ctx: Context, st: _State) -> None:
        pending, st.pending_windows = st.pending_windows, None
        if pending is None:
            return
        mech = pending["mechanism"]
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="MSSQL", username=st.user,
            domain=st.domain, value="MSSQL Windows authentication", plugin=self.name,
            risk="medium" if mech == "NTLM" else "low", tags=self._tags(ctx),
            extra={**st.extra, "mechanism": mech},
        )  # fmt: skip

    def _result(self, ctx: Context, st: _State, *, ok: bool, extra: dict[str, Any]) -> None:
        self._flush_windows(ctx, st)
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="MSSQL", reverse=True,
            username=st.user, domain=st.domain, value="login succeeded" if ok else "login failed",
            plugin=self.name, tags=self._tags(ctx), extra=extra,
        )  # fmt: skip


def _prelogin_options(body: bytes) -> dict[int, bytes]:
    """PRELOGIN option table: token(1) offset(2 BE) length(2 BE) ... 0xFF."""
    out: dict[int, bytes] = {}
    pos = 0
    while pos < len(body) and len(out) < 32:
        tok = body[pos]
        if tok == 0xFF:
            break
        if pos + 5 > len(body):
            break
        off, ln = struct.unpack_from("!HH", body, pos + 1)
        if off + ln <= len(body):
            out[tok] = body[off : off + ln]
        pos += 5
    return out
