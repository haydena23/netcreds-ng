"""Kerberos authentication hygiene (UDP and TCP).

Reports principals and realms, the encryption type used for pre-authentication
(flagging DES and RC4), accounts that receive an AS-REP without
pre-authentication, pre-auth failures, unknown principals, and service tickets
issued with weak encryption. Only metadata is reported; encrypted parts are
never extracted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport
from netcreds_ng.proto.der import TLV, DERError, read_tlv

ETYPES = {
    1: "des-cbc-crc", 3: "des-cbc-md5", 17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
    19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192", 23: "rc4-hmac", 24: "rc4-hmac-exp",
}  # fmt: skip
WEAK = {1: "high", 3: "high", 23: "medium", 24: "high"}
APP_TAGS = {0x6A: "AS-REQ", 0x6B: "AS-REP", 0x6C: "TGS-REQ", 0x6D: "TGS-REP", 0x7E: "KRB-ERROR"}
PA_ENC_TIMESTAMP = 2
ERR_PREAUTH_FAILED = 24
ERR_PREAUTH_REQUIRED = 25
ERR_C_PRINCIPAL_UNKNOWN = 6
ERR_NAME_EXP = 1  # client's entry expired (RFC 4120 7.5.9)
ERR_CLIENT_REVOKED = 18  # credentials revoked: account disabled or locked out
ERR_KEY_EXPIRED = 23  # password expired


def etype_name(e: int) -> str:
    return ETYPES.get(e, f"etype-{e}")


def _principal(tlv: TLV | None) -> str | None:
    """PrincipalName ::= SEQUENCE { name-type [0], name-string [1] SEQUENCE OF KerberosString }"""
    if tlv is None:
        return None
    seq = tlv.inner()
    names = seq.child(1)
    if names is None:
        return None
    return "/".join(n.as_str() for n in names.inner().children())


def _int(tlv: TLV | None) -> int | None:
    return tlv.inner().as_int() if tlv is not None else None


def _str(tlv: TLV | None) -> str | None:
    return tlv.inner().as_str() if tlv is not None else None


@dataclass
class _State:
    tcp_bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    pending_no_preauth: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)
    last_principal: tuple[str | None, str | None] = (None, None)


class KerberosPlugin(ProtocolPlugin):
    name = "kerberos"
    description = "Kerberos principals, pre-auth encryption types, no-preauth accounts, failures (UDP/TCP)"
    transports = frozenset({Transport.UDP, Transport.TCP})
    default_ports = frozenset({88})
    priority = 70

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_datagram(self, ctx: Context, direction: Direction, data: bytes) -> None:
        if data[:1] and data[0] in APP_TAGS:
            self._message(ctx, direction, data)

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.tcp_bufs[direction]
        buf += data
        while len(buf) >= 4:
            (length,) = struct.unpack("!I", buf[:4])
            if length & 0x80000000 or length > 1 << 20 or (len(buf) > 4 and buf[4] not in APP_TAGS):
                ctx.detach()  # not Kerberos record framing
                return
            if len(buf) < 4 + length:
                return
            record = bytes(buf[4 : 4 + length])
            del buf[: 4 + length]
            self._message(ctx, direction, record)

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.state.tcp_bufs[direction].clear()

    # message handling ------------------------------------------------------

    def _message(self, ctx: Context, direction: Direction, data: bytes) -> None:
        try:
            app = read_tlv(data)
        except DERError:
            return
        kind = APP_TAGS.get(app.tag)
        if kind is None:
            return
        try:
            body = app.inner()
            if kind in ("AS-REQ", "TGS-REQ"):
                self._kdc_req(ctx, direction, kind, body)
            elif kind in ("AS-REP", "TGS-REP"):
                self._kdc_rep(ctx, direction, kind, body)
            else:
                self._error(ctx, direction, body)
        except (DERError, IndexError, ValueError):
            return

    def _emit(self, ctx: Context, direction: Direction, kind: Kind, **kw: object) -> None:
        ctx.emit(direction, kind, protocol="Kerberos", plugin=self.name, **kw)  # type: ignore[arg-type]

    def _kdc_req(self, ctx: Context, direction: Direction, kind: str, body: TLV) -> None:
        st: _State = ctx.state
        req_body_w = body.child(4)
        if req_body_w is None:
            return
        req_body = req_body_w.inner()
        cname = _principal(req_body.child(1))
        realm = _str(req_body.child(2))
        sname = _principal(req_body.child(3))
        etype_w = req_body.child(8)
        offered = [e.as_int() for e in etype_w.inner().children()] if etype_w is not None else []
        if kind == "TGS-REQ":
            return  # service ticket requests are reported via the TGS-REP encryption type
        st.last_principal = (cname, realm)
        preauth_etype = None
        padata_w = body.child(3)
        if padata_w is not None:
            for pa in padata_w.inner().children():
                ptype = _int(pa.child(1))
                if ptype == PA_ENC_TIMESTAMP:
                    value = pa.child(2)
                    if value is not None:
                        enc = read_tlv(value.inner().value)
                        preauth_etype = _int(enc.child(0))
        weak_offered = sorted({etype_name(e) for e in offered if e in WEAK})
        extra = {"realm": realm, "service": sname, "offered_etypes": [etype_name(e) for e in offered]}
        tags = ["weak-etype-offered"] if weak_offered else []
        if preauth_etype is None:
            st.pending_no_preauth[f"{cname}@{realm}"] = (cname, realm)
            return
        self._emit(
            ctx, direction, Kind.AUTH_EVENT, username=cname, domain=realm,
            value=f"Kerberos pre-authentication ({etype_name(preauth_etype)})",
            risk=WEAK.get(preauth_etype, "low"),
            tags=tags + ([f"weak-preauth-{etype_name(preauth_etype)}"] if preauth_etype in WEAK else []),
            extra={**extra, "preauth_etype": etype_name(preauth_etype)},
        )  # fmt: skip

    def _kdc_rep(self, ctx: Context, direction: Direction, kind: str, body: TLV) -> None:
        st: _State = ctx.state
        crealm = _str(body.child(3))
        cname = _principal(body.child(4))
        ticket_w = body.child(5)
        sname = None
        tkt_etype = None
        if ticket_w is not None:
            ticket = ticket_w.inner().inner()  # [APPLICATION 1] Ticket -> SEQUENCE
            sname = _principal(ticket.child(2))
            enc = ticket.child(3)
            if enc is not None:
                tkt_etype = _int(enc.inner().child(0))
        if kind == "AS-REP":
            key = f"{cname}@{crealm}"
            if key in st.pending_no_preauth:
                del st.pending_no_preauth[key]
                self._emit(
                    ctx, direction, Kind.AUTH_EVENT, reverse=True, username=cname, domain=crealm,
                    value="AS-REP issued without pre-authentication", risk="high", tags=["no-preauth"],
                    extra={"realm": crealm},
                )  # fmt: skip
        elif kind == "TGS-REP" and tkt_etype in WEAK:
            self._emit(
                ctx, direction, Kind.AUTH_EVENT, reverse=True, username=cname, domain=crealm,
                value=f"service ticket for {sname} issued with {etype_name(tkt_etype)}",
                risk=WEAK[tkt_etype], tags=["weak-service-ticket"],
                extra={"realm": crealm, "service": sname, "ticket_etype": etype_name(tkt_etype)},
            )  # fmt: skip

    def _error(self, ctx: Context, direction: Direction, body: TLV) -> None:
        st: _State = ctx.state
        code = _int(body.child(6))
        cname = _principal(body.child(8)) or st.last_principal[0]
        realm = _str(body.child(9)) or st.last_principal[1]
        if code == ERR_PREAUTH_REQUIRED:
            st.pending_no_preauth.pop(f"{cname}@{realm}", None)
            return
        verdict = {ERR_PREAUTH_FAILED: "pre-authentication failed (wrong password)",
                   ERR_C_PRINCIPAL_UNKNOWN: "unknown principal",
                   ERR_NAME_EXP: "login failed: account expired",
                   ERR_CLIENT_REVOKED: "login failed: account disabled or locked out",
                   ERR_KEY_EXPIRED: "login failed: password expired"}.get(code or -1)  # fmt: skip
        if verdict:
            self._emit(ctx, direction, Kind.AUTH_RESULT, reverse=True, username=cname, domain=realm, value=verdict,
                       extra={"error_code": code, "outcome": "failure"})  # fmt: skip
