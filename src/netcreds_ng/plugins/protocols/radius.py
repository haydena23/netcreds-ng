"""RADIUS (RFC 2865/2866/3579): login method exposure and access results.

Scope: RADIUS hides ``User-Password`` (PAP) with an MD5 keystream derived from the shared
secret and the request authenticator. The secret is unknown to us and is never guessed or
derived; the obfuscated bytes are never extracted. PAP, CHAP, MS-CHAP and EAP logins are
reported as ``AUTH_EVENT`` metadata (user, mechanism). The cleartext EAP-Response/Identity
is reported as a ``USERNAME``. Access-Accept / Access-Reject become ``AUTH_RESULT``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport
from netcreds_ng.plugins.protocols._util import text

STANDARD_PORTS = frozenset({1812, 1645, 1813, 1646})
_MIN_LEN, _MAX_LEN = 20, 4096

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
ACCOUNTING_REQUEST, ACCESS_CHALLENGE = 4, 11
CODES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
    5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client",
    40: "Disconnect-Request", 41: "Disconnect-ACK", 42: "Disconnect-NAK",
    43: "CoA-Request", 44: "CoA-ACK", 45: "CoA-NAK",
}  # fmt: skip

USER_NAME, USER_PASSWORD, CHAP_PASSWORD, NAS_IP = 1, 2, 3, 4
REPLY_MESSAGE, VENDOR_SPECIFIC = 18, 26
CALLED_STATION, CALLING_STATION, NAS_IDENTIFIER = 30, 31, 32
ACCT_STATUS_TYPE, EAP_MESSAGE, NAS_IPV6 = 40, 79, 95
MICROSOFT = 311
MS_CHAP_RESPONSE, MS_CHAP2_RESPONSE = 1, 25

ACCT_STATUS = {1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off"}
EAP_TYPES = {
    1: "Identity", 2: "Notification", 3: "Nak", 4: "EAP-MD5", 5: "EAP-OTP", 6: "EAP-GTC",
    13: "EAP-TLS", 17: "LEAP", 18: "EAP-SIM", 21: "EAP-TTLS", 23: "EAP-AKA", 25: "PEAP",
    26: "EAP-MSCHAPv2", 43: "EAP-FAST", 47: "EAP-PSK", 50: "EAP-AKA'", 52: "EAP-pwd",
    53: "EAP-EKE", 55: "TEAP", 254: "Expanded",
}  # fmt: skip
#: Methods whose credentials travel inside a TLS tunnel.
TUNNELED = {"EAP-TLS", "EAP-TTLS", "PEAP", "EAP-FAST", "TEAP"}
_EAP_RESPONSE = 2
_MAX_SEEN = 512


@dataclass
class _Pending:
    username: str | None
    mechanism: str | None


@dataclass
class _State:
    pending: dict[int, _Pending] = field(default_factory=dict)  # by RADIUS identifier (0-255)
    seen: set[tuple[int, bytes]] = field(default_factory=set)  # (id, authenticator) of handled requests
    answered: set[int] = field(default_factory=set)  # ids whose Accept/Reject was already reported
    reported: set[tuple[str | None, str]] = field(default_factory=set)  # (user, mechanism) events
    recognised: bool = False  # at least one valid RADIUS datagram seen on this flow


def parse(data: bytes, strict: bool) -> tuple[int, int, bytes, list[tuple[int, bytes]]] | None:
    """(code, identifier, authenticator, attributes) or None when ``data`` is not RADIUS-shaped.

    Octets past the Length field are padding (RFC 2865 section 3); ``strict`` refuses them.
    """
    if len(data) < _MIN_LEN:
        return None
    code, ident, length = data[0], data[1], int.from_bytes(data[2:4], "big")
    if code not in CODES or not _MIN_LEN <= length <= _MAX_LEN or length > len(data):
        return None
    if strict and length != len(data):
        return None
    attrs: list[tuple[int, bytes]] = []
    pos = _MIN_LEN
    while pos < length:
        if pos + 2 > length:
            return None
        atype, alen = data[pos], data[pos + 1]
        if alen < 2 or pos + alen > length:
            return None
        attrs.append((atype, data[pos + 2 : pos + alen]))
        pos += alen
    return code, ident, data[4:20], attrs


def _first(attrs: list[tuple[int, bytes]], atype: int) -> bytes | None:
    for t, v in attrs:
        if t == atype:
            return v
    return None


def _ms_chap(attrs: list[tuple[int, bytes]]) -> str | None:
    for t, v in attrs:
        if t != VENDOR_SPECIFIC or len(v) < 6 or int.from_bytes(v[:4], "big") != MICROSOFT:
            continue
        pos = 4
        while pos + 2 <= len(v):
            sub, slen = v[pos], v[pos + 1]
            if slen < 2:
                break
            if sub == MS_CHAP2_RESPONSE:
                return "MS-CHAPv2"
            if sub == MS_CHAP_RESPONSE:
                return "MS-CHAP"
            pos += slen
    return None


def _eap(attrs: list[tuple[int, bytes]]) -> tuple[int, int | None, bytes] | None:
    """(EAP code, EAP type, type data) from the concatenated EAP-Message attributes."""
    raw = b"".join(v for t, v in attrs if t == EAP_MESSAGE)
    if len(raw) < 4:
        return None
    length = int.from_bytes(raw[2:4], "big")
    if length < 4 or length > len(raw):
        return None
    if length == 4:
        return raw[0], None, b""
    return raw[0], raw[4], raw[5:length]


def _extra(attrs: list[tuple[int, bytes]]) -> dict[str, object]:
    extra: dict[str, object] = {}
    nas_ip = _first(attrs, NAS_IP)
    if nas_ip is not None and len(nas_ip) == 4:
        extra["nas_ip"] = str(ipaddress.IPv4Address(nas_ip))
    nas_ip6 = _first(attrs, NAS_IPV6)
    if nas_ip6 is not None and len(nas_ip6) == 16:
        extra["nas_ipv6"] = str(ipaddress.IPv6Address(nas_ip6))
    for atype, key in ((NAS_IDENTIFIER, "nas_identifier"), (CALLED_STATION, "called_station_id"),
                       (CALLING_STATION, "calling_station_id")):  # fmt: skip
        val = _first(attrs, atype)
        if val is not None:
            extra[key] = text(val[:128])
    return extra


class RadiusPlugin(ProtocolPlugin):
    name = "radius"
    description = "RADIUS: PAP/CHAP/MS-CHAP/EAP login metadata, EAP identities, access results"
    transports = frozenset({Transport.UDP})
    default_ports = STANDARD_PORTS
    priority = 80

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_datagram(self, ctx: Context, direction: Direction, data: bytes) -> None:
        standard = ctx.flow.server.port in STANDARD_PORTS or ctx.flow.client.port in STANDARD_PORTS
        parsed = parse(data, strict=not standard)
        if parsed is None:
            st0: _State = ctx.state
            if not st0.recognised:
                ctx.detach()  # not RADIUS
            return  # one malformed datagram on a known RADIUS flow does not end it (review L6)
        code, ident, authenticator, attrs = parsed
        st: _State = ctx.state
        st.recognised = True
        tags = [] if standard else ["nonstandard-port"]
        if code == ACCESS_REQUEST:
            key = (ident, authenticator)
            if key in st.seen:
                return  # retransmission
            if len(st.seen) >= _MAX_SEEN:
                st.seen.clear()
            st.seen.add(key)
            st.answered.discard(ident)
            self._access_request(ctx, st, direction, ident, attrs, tags)
        elif code in (ACCESS_ACCEPT, ACCESS_REJECT):
            self._result(ctx, st, direction, ident, attrs, ok=code == ACCESS_ACCEPT, tags=tags)
        elif code == ACCOUNTING_REQUEST:
            self._accounting(ctx, direction, attrs, tags)

    # -- requests ----------------------------------------------------------------------
    def _access_request(
        self, ctx: Context, st: _State, direction: Direction, ident: int,
        attrs: list[tuple[int, bytes]], tags: list[str],
    ) -> None:  # fmt: skip
        raw_user = _first(attrs, USER_NAME)
        user = text(raw_user[:256]) if raw_user is not None else None
        extra = _extra(attrs)
        mechanism: str | None = None
        risk = "medium"
        more: list[str] = []
        if _first(attrs, USER_PASSWORD) is not None:
            mechanism, more = "PAP", ["pap"]
        elif _first(attrs, CHAP_PASSWORD) is not None:
            mechanism, more = "CHAP", ["chap"]
        elif (ms := _ms_chap(attrs)) is not None:
            mechanism, more = ms, [ms.lower()]
        elif (eap := _eap(attrs)) is not None:
            eap_code, eap_type, eap_data = eap
            if eap_code != _EAP_RESPONSE or eap_type is None:
                mechanism = "EAP"
            elif eap_type == 1:
                identity = text(eap_data[:256])
                if identity:
                    ctx.emit(
                        direction, Kind.USERNAME, protocol="RADIUS", username=identity,
                        value="EAP-Response/Identity", plugin=self.name, risk="low",
                        tags=["eap-identity", *tags], extra=extra,
                    )  # fmt: skip
                st.pending[ident] = _Pending(user or identity or None, "EAP")
                return
            elif eap_type in (2, 3):
                mechanism = "EAP"  # Notification / Nak: no method chosen by this message
            else:
                method = EAP_TYPES.get(eap_type, f"EAP type {eap_type}")
                mechanism = f"EAP ({method})"
                if method in TUNNELED:
                    risk = "info"
            more = ["eap"]
        st.pending[ident] = _Pending(user, mechanism)
        if mechanism is None and user is None:
            return
        if mechanism == "EAP":
            return  # EAP round without an identifiable method; reported once the method appears
        label = mechanism or "unknown method"
        if (user, label) in st.reported:
            return  # further rounds of the same login (EAP) or a repeated login on this flow
        if len(st.reported) >= _MAX_SEEN:
            st.reported.clear()
        st.reported.add((user, label))
        if mechanism is None:
            risk = "info"
        extra = {"mechanism": label, **extra}
        ctx.emit(
            direction, Kind.AUTH_EVENT, protocol="RADIUS", username=user,
            value=f"RADIUS {label} login" if mechanism else "RADIUS login (unknown method)",
            plugin=self.name, risk=risk, tags=[*more, *tags], extra=extra,
        )  # fmt: skip

    def _accounting(self, ctx: Context, direction: Direction, attrs: list[tuple[int, bytes]], tags: list[str]) -> None:
        raw_user = _first(attrs, USER_NAME)
        status = _first(attrs, ACCT_STATUS_TYPE)
        if raw_user is None or status is None or len(status) != 4:
            return
        name = ACCT_STATUS.get(int.from_bytes(status, "big"))
        if name not in ("Start", "Stop"):
            return
        ctx.emit(
            direction, Kind.INFO, protocol="RADIUS", username=text(raw_user[:256]),
            value=f"RADIUS accounting {name}", plugin=self.name, risk="info", tags=list(tags),
            extra={"acct_status": name, **_extra(attrs)},
        )  # fmt: skip

    # -- responses ---------------------------------------------------------------------
    def _result(
        self, ctx: Context, st: _State, direction: Direction, ident: int,
        attrs: list[tuple[int, bytes]], *, ok: bool, tags: list[str],
    ) -> None:  # fmt: skip
        pending = st.pending.pop(ident, None)
        if pending is None and ident in st.answered:
            return  # retransmitted response to a request already answered
        st.answered.add(ident)
        extra: dict[str, object] = {}
        if pending is not None and pending.mechanism:
            extra["mechanism"] = pending.mechanism
        msg = _first(attrs, REPLY_MESSAGE)
        if msg is not None:
            extra["message"] = text(msg[:120])
        ctx.emit(
            direction, Kind.AUTH_RESULT, protocol="RADIUS", reverse=True,
            username=pending.username if pending else None,
            value="login succeeded" if ok else "login failed", plugin=self.name,
            tags=list(tags), extra=extra,
        )  # fmt: skip
