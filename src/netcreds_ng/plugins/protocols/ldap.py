"""LDAP simple binds (cleartext), SASL bind metadata, and bind results.

Scope: simple-bind passwords are reported in full (that is the exposure). SASL binds are
reported as metadata only (mechanism name), except SASL PLAIN, whose credentials are the
cleartext password by definition. Challenge/response material is never extracted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import sasl_plain, text
from netcreds_ng.proto.der import DERError, read_tlv

_MAX_MESSAGE = 64 * 1024  # larger messages are skipped, not buffered
_STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"
_STANDARD_PORTS = (389, 3268)

_TAG_SEQUENCE = 0x30
_TAG_INTEGER = 0x02
_TAG_OCTETS = 0x04
_TAG_ENUM = 0x0A
_OP_BIND_REQUEST = 0x60
_OP_BIND_RESPONSE = 0x61
_OP_EXT_REQUEST = 0x77
_OP_EXT_RESPONSE = 0x78
_AUTH_SIMPLE = 0x80
_AUTH_SASL = 0xA3
_RC_SUCCESS = 0
_RC_SASL_IN_PROGRESS = 14


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    skip: list[int] = field(default_factory=lambda: [0, 0])
    started: list[bool] = field(default_factory=lambda: [False, False])
    pending_binds: dict[int, str | None] = field(default_factory=dict)  # messageID -> bind DN
    starttls_ids: set[int] = field(default_factory=set)


def _frame(buf: bytearray) -> tuple[int, int] | None:
    """(header_len, total_len) of the BER element at the start of ``buf``; None if incomplete."""
    if len(buf) < 2:
        return None
    first = buf[1]
    if first < 0x80:
        return 2, 2 + first
    if first == 0x80:
        raise ValueError("indefinite length")
    n = first & 0x7F
    if n > 4:
        raise ValueError("length too large")
    if len(buf) < 2 + n:
        return None
    return 2 + n, 2 + n + int.from_bytes(buf[2 : 2 + n], "big")


class LDAPPlugin(ProtocolPlugin):
    name = "ldap"
    description = "LDAP simple binds, SASL bind mechanisms and bind results (any port)"
    default_ports = frozenset({389, 3268})
    priority = 90

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        d = int(direction)
        if st.skip[d]:
            n = min(st.skip[d], len(data))
            st.skip[d] -= n
            data = data[n:]
        if not data:
            return
        buf = st.bufs[d]
        buf += data
        try:
            self._drain(ctx, st, direction, buf)
        except (ValueError, IndexError):  # DERError is a ValueError
            ctx.detach()

    def _drain(self, ctx: Context, st: _State, direction: Direction, buf: bytearray) -> None:
        d = int(direction)
        while buf and not ctx.detached and not st.skip[d]:
            if buf[0] != _TAG_SEQUENCE:
                ctx.detach()
                return
            frame = _frame(buf)
            if frame is None:
                return
            hlen, total = frame
            if not st.started[d] and len(buf) >= hlen + 2:
                # messageID must be a short INTEGER right after the SEQUENCE header.
                if buf[hlen] != _TAG_INTEGER or not 1 <= buf[hlen + 1] <= 4:
                    ctx.detach()
                    return
            if total > _MAX_MESSAGE:
                if not st.started[d] and len(buf) < hlen + 2:
                    return
                st.started[d] = True
                dropped = min(len(buf), total)
                del buf[:dropped]
                st.skip[d] = total - dropped
                continue
            if len(buf) < total:
                return
            msg = bytes(buf[:total])
            del buf[:total]
            st.started[d] = True
            self._message(ctx, st, direction, msg)
        if ctx.detached:
            buf.clear()

    def _message(self, ctx: Context, st: _State, direction: Direction, msg: bytes) -> None:
        kids = read_tlv(msg).children()
        if len(kids) < 2 or kids[0].tag != _TAG_INTEGER:
            raise DERError("not an LDAPMessage")
        msgid = kids[0].as_int()
        op = kids[1]
        if direction is Direction.CLIENT_TO_SERVER:
            if op.tag == _OP_BIND_REQUEST:
                self._bind_request(ctx, st, msgid, op.children())
            elif op.tag == _OP_EXT_REQUEST:
                for c in op.children():
                    if c.tag == _AUTH_SIMPLE and c.value == _STARTTLS_OID:
                        st.starttls_ids.add(msgid)
        elif op.tag == _OP_BIND_RESPONSE:
            self._bind_response(ctx, st, msgid, op.children())
        elif op.tag == _OP_EXT_RESPONSE and msgid in st.starttls_ids:
            parts = op.children()
            if parts and parts[0].tag == _TAG_ENUM and parts[0].as_int() == _RC_SUCCESS:
                ctx.detach()  # the rest of the stream is TLS

    def _bind_request(self, ctx: Context, st: _State, msgid: int, parts: list) -> None:
        if len(parts) < 3 or parts[0].tag != _TAG_INTEGER or parts[1].tag != _TAG_OCTETS:
            raise DERError("malformed BindRequest")
        dn_raw = parts[1].value
        dn = text(dn_raw) if dn_raw else None
        auth = parts[2]
        tags = [] if ctx.flow.server.port in _STANDARD_PORTS else ["nonstandard-port"]
        version = parts[0].as_int()
        if auth.tag == _AUTH_SIMPLE:
            pw = auth.value
            if not dn_raw and not pw:
                return  # anonymous bind
            if not pw:
                ctx.emit(
                    Direction.CLIENT_TO_SERVER, Kind.USERNAME, protocol="LDAP", plugin=self.name,
                    username=dn, risk="medium", tags=[*tags, "unauthenticated-bind"],
                    extra={"ldap_version": version},
                )  # fmt: skip
                return
            kind = Kind.CREDENTIAL if dn else Kind.PASSWORD
            ctx.emit(
                Direction.CLIENT_TO_SERVER, kind, protocol="LDAP", plugin=self.name,
                username=dn, secret=text(pw), risk="high", tags=tags,
                extra={"mechanism": "simple", "ldap_version": version},
            )  # fmt: skip
            st.pending_binds[msgid] = dn
        elif auth.tag == _AUTH_SASL:
            sasl = auth.children()
            if not sasl or sasl[0].tag != _TAG_OCTETS:
                raise DERError("malformed SASL credentials")
            mech = text(sasl[0].value)
            if mech.upper() == "PLAIN" and len(sasl) > 1:
                triple = sasl_plain(sasl[1].value)
                if triple is not None:
                    _authzid, authcid, password = triple
                    ctx.emit(
                        Direction.CLIENT_TO_SERVER, Kind.CREDENTIAL, protocol="LDAP", plugin=self.name,
                        username=authcid, secret=password, risk="high", tags=tags,
                        extra={"mechanism": "SASL PLAIN", "bind_dn": dn or ""},
                    )  # fmt: skip
                    st.pending_binds[msgid] = authcid
                    return
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="LDAP", plugin=self.name,
                username=dn, value=f"LDAP SASL bind ({mech})", risk="low", tags=tags,
                extra={"mechanism": mech},
            )  # fmt: skip
            st.pending_binds[msgid] = dn
        else:
            raise DERError("unknown authentication choice")

    def _bind_response(self, ctx: Context, st: _State, msgid: int, parts: list) -> None:
        if msgid not in st.pending_binds or not parts or parts[0].tag != _TAG_ENUM:
            return
        code = parts[0].as_int()
        if code == _RC_SASL_IN_PROGRESS:
            return  # multi-step SASL exchange continues
        user = st.pending_binds.pop(msgid)
        ok = code == _RC_SUCCESS
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="LDAP", reverse=True, plugin=self.name,
            username=user, value="login succeeded" if ok else "login failed",
            extra={"result_code": code},
        )  # fmt: skip
