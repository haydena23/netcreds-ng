"""RDP: connection-negotiation security level and routing-cookie usernames.

Parses only the cleartext start of an RDP connection (MS-RDPBCGR 2.2.1.1 and
2.2.1.2): the client's TPKT + X.224 Connection Request, which may carry a
``Cookie: mstshash=<username>`` routing cookie and an RDP_NEG_REQ with the
requested security protocols, and the server's Connection Confirm with an
RDP_NEG_RSP (selected protocol) or RDP_NEG_FAILURE.

Everything after negotiation is TLS / CredSSP, or legacy RDP security with its
own RC4 encryption, so the plugin detaches once the confirm has been read.
CredSSP (NTLM / Kerberos inside TLS) is not visible and is not attempted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_MAX_TPKT = 4096  # a Connection Request / Confirm is small; anything larger is not ours
_MAX_COOKIE = 256

PROTOCOL_RDP = 0x00
PROTOCOL_SSL = 0x01
PROTOCOL_HYBRID = 0x02
PROTOCOL_RDSTLS = 0x04
PROTOCOL_HYBRID_EX = 0x08
PROTOCOL_RDSAAD = 0x10

_PROTOCOL_NAMES = {
    PROTOCOL_SSL: "TLS", PROTOCOL_HYBRID: "CredSSP", PROTOCOL_RDSTLS: "RDSTLS",
    PROTOCOL_HYBRID_EX: "CredSSP-EX", PROTOCOL_RDSAAD: "RDS-AAD",
}  # fmt: skip

FAILURE_CODES = {
    1: "SSL_REQUIRED_BY_SERVER", 2: "SSL_NOT_ALLOWED_BY_SERVER", 3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS", 5: "HYBRID_REQUIRED_BY_SERVER", 6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}  # fmt: skip

_C, _S = int(Direction.CLIENT_TO_SERVER), int(Direction.SERVER_TO_CLIENT)


def protocol_names(mask: int) -> list[str]:
    """Names of the protocol flags in ``mask``; an empty mask is standard RDP security."""
    if mask == PROTOCOL_RDP:
        return ["RDP"]
    names = [name for bit, name in _PROTOCOL_NAMES.items() if mask & bit]
    unknown = mask & ~sum(_PROTOCOL_NAMES)
    if unknown:
        names.append(f"0x{unknown:x}")
    return names


def _tpdu(buf: bytearray, code: int) -> bytes | bool | None:
    """Pop one TPKT-framed X.224 TPDU with ``code`` from ``buf``.

    Returns the variable part, ``None`` if more bytes are needed, or ``False``
    if the bytes are not a TPKT/X.224 TPDU of that type.
    """
    if buf[:1] not in (b"", b"\x03") or buf[1:2] not in (b"", b"\x00"):
        return False
    if len(buf) < 4:
        return None
    (length,) = struct.unpack_from("!H", buf, 2)
    if length < 11 or length > _MAX_TPKT:
        return False
    if len(buf) < length:
        return None
    pdu = bytes(buf[4:length])
    del buf[:length]
    li = pdu[0]
    if li != len(pdu) - 1 or li < 6 or pdu[1] & 0xF0 != code:
        return False
    return pdu[7:]


def _parse_cookie(variable: bytes) -> tuple[bytes | None, bytes]:
    """Split an optional ``Cookie: ...\\r\\n`` (or routing token) from the CR variable part."""
    if not variable.startswith(b"Cookie: "):
        return None, variable
    end = variable.find(b"\r\n")
    if end < 0:
        return None, b""  # unterminated cookie: no negotiation request can follow
    return variable[:end], variable[end + 2 :]


def _neg(data: bytes, expected: tuple[int, ...]) -> tuple[int, int] | None:
    """(type, value) of an 8-byte RDP_NEG_* structure, or None."""
    if len(data) < 8:
        return None
    typ, _flags, length, value = struct.unpack_from("<BBHI", data)
    if typ not in expected or length != 8:
        return None
    return typ, value


@dataclass
class _State:
    buf: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    stage: str = "cr"  # cr -> cc -> done
    requested: int | None = None  # None: no RDP_NEG_REQ (standard RDP security only)
    username: str | None = None
    domain: str | None = None
    routing_token: bool = False
    reported: bool = False
    evidence: bool = False  # an mstshash cookie or RDP negotiation PDU was seen (not just TPKT/X.224)


class RDPPlugin(ProtocolPlugin):
    name = "rdp"
    description = "RDP security negotiation (standard RDP security / TLS without NLA / NLA) and mstshash usernames"
    default_ports = frozenset({3389})
    priority = 96

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        st.buf[direction].extend(data)
        if len(st.buf[direction]) > _MAX_TPKT:
            ctx.detach()  # a negotiation PDU never gets this large
            return
        if st.stage == "cr":
            if st.buf[_S]:
                ctx.detach()  # RDP: the client speaks first
                return
            res = _tpdu(st.buf[_C], 0xE0)
            if res is None:
                return
            if not isinstance(res, bytes) or not self._request(ctx, st, res):
                ctx.detach()
                return
            st.stage = "cc"
        if st.stage == "cc":
            res = _tpdu(st.buf[_S], 0xD0)
            if res is None:
                return
            if isinstance(res, bytes):
                self._confirm(ctx, st, res)
            st.stage = "done"
            ctx.detach()  # TLS / CredSSP / RDP-encrypted from here on (or not a confirm)

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        if st.stage == "cc" and not st.reported and self._is_rdp(ctx, st):
            # Request seen, confirm never arrived (a scanner, or a filtered server): report what the
            # client offered, at low risk, since no server ever agreed to it.
            if st.requested is None or st.requested == PROTOCOL_RDP:
                self._event(ctx, st, None, "RDP client offered only standard RDP security (no NLA, no TLS)",
                            "low", ["no-nla", "no-response"], {})  # fmt: skip
            else:
                self._event(ctx, st, None, "RDP negotiation incomplete (no server response)",
                            "info", ["no-response"], {})  # fmt: skip

    # -- messages -----------------------------------------------------------

    def _is_rdp(self, ctx: Context, st: _State) -> bool:
        """TPKT + X.224 is shared with ISO-TSAP (S7comm, MMS, ...): require RDP-specific evidence
        or the RDP port before reporting anything."""
        return st.evidence or ctx.flow.server.port in self.default_ports

    def _request(self, ctx: Context, st: _State, variable: bytes) -> bool:
        cookie, rest = _parse_cookie(variable)
        if cookie is not None:
            st.evidence = True
            if cookie.startswith(b"Cookie: mstshash="):
                # Clients pad short names with spaces (seen in real captures: "JOHN-PC  ").
                raw = cookie[len(b"Cookie: mstshash=") :][:_MAX_COOKIE].strip(b" ")
                if raw:
                    domain, sep, user = raw.rpartition(b"\\")
                    st.username = text(user if sep else raw)
                    st.domain = text(domain) if sep and domain else None
                    ctx.emit(Direction.CLIENT_TO_SERVER, Kind.USERNAME, protocol="RDP", plugin=self.name,
                             username=st.username, domain=st.domain, risk="low", tags=["rdp-cookie"],
                             extra={"source": "mstshash cookie"})  # fmt: skip
            else:
                st.routing_token = True  # load-balancer routing token (msts=...): not a username
        if rest:
            neg = _neg(rest, (0x01,))
            if neg is None:
                # Not an RDP_NEG_REQ: other TPKT protocols (ISO-TSAP/S7comm) carry parameters here.
                # Tolerate it only after a cookie or on the RDP port.
                return self._is_rdp(ctx, st)
            st.requested = neg[1]
            st.evidence = True
        return self._is_rdp(ctx, st) or not variable

    def _confirm(self, ctx: Context, st: _State, variable: bytes) -> None:
        extra: dict[str, object] = {}
        neg = _neg(variable, (0x02, 0x03)) if variable else None
        if neg is None and not self._is_rdp(ctx, st):
            return  # a bare X.224 confirm off the RDP port is no evidence of RDP
        if neg is not None and neg[0] == 0x03:
            name = FAILURE_CODES.get(neg[1], f"code {neg[1]}")
            extra["failure"] = name
            self._event(ctx, st, None, f"RDP negotiation failed ({name})", "info", ["negotiation-failed"], extra)
            return
        selected = neg[1] if neg is not None else PROTOCOL_RDP
        if selected & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX):
            value, risk, tags = "RDP with Network Level Authentication (CredSSP)", "low", ["nla"]
        elif selected & (PROTOCOL_RDSTLS | PROTOCOL_RDSAAD):
            value, risk, tags = f"RDP with {protocol_names(selected)[0]} authentication over TLS", "low", ["tls"]
        elif selected & PROTOCOL_SSL:
            value, risk, tags = "RDP over TLS without Network Level Authentication", "medium", ["no-nla", "tls"]
        elif selected == PROTOCOL_RDP:
            value = "RDP standard security (no NLA, legacy RC4 encryption, MITM-able)"
            risk, tags = "high", ["no-nla", "standard-rdp-security"]
        else:
            value, risk, tags = f"RDP with unknown security protocol 0x{selected:x}", "info", []
        self._event(ctx, st, selected, value, risk, tags, extra)

    def _event(self, ctx: Context, st: _State, selected: int | None, value: str, risk: str,
               tags: list[str], extra: dict[str, object]) -> None:  # fmt: skip
        st.reported = True
        info: dict[str, object] = {
            "requested": protocol_names(st.requested) if st.requested is not None else ["RDP"],
            "negotiation_request": st.requested is not None,
        }
        if selected is not None:
            info["selected"] = protocol_names(selected)[0] if selected == PROTOCOL_RDP else "+".join(protocol_names(selected))
        if st.routing_token:
            info["routing_token"] = True
        info.update(extra)
        ctx.emit(Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="RDP", plugin=self.name,
                 username=st.username, domain=st.domain, value=value, risk=risk, tags=tags, extra=info)  # fmt: skip
