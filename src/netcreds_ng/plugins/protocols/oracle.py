"""Oracle Net (TNS) login exposure: CONNECT descriptor metadata, O5LOGON user names, results.

Scope: Oracle's O5LOGON authentication is a challenge/response protocol. This plugin reports
metadata only: the connect descriptor (service, client program/host/OS user), the database
user name and allow-listed client attributes of the TTI AUTH request, and the login result.
AUTH_SESSKEY, AUTH_PASSWORD, AUTH_VFR_DATA and every other AUTH_* value outside the
allow-list are never read into a finding.

Parsing of the TTI layer is heuristic (its encoding varies between client libraries): the
user name is the length-prefixed string immediately preceding the first AUTH_* key.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_MAX_BUFFER = 1024 * 1024
_MAX_PACKET = 1024 * 1024
_MAX_DATA_PACKETS = 256  # stop looking for the AUTH exchange after this many DATA packets
_MAX_TURN = 64 * 1024  # client DATA bytes kept per turn while looking for the AUTH request

CONNECT, ACCEPT, ACK, REFUSE, REDIRECT, DATA = 1, 2, 3, 4, 5, 6
RESEND, MARKER, ATTENTION, CONTROL = 11, 12, 13, 14
_VALID_TYPES = frozenset({1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 13, 14, 15})

_ANO_MAGIC = b"\xde\xad\xbe\xef"
_ANO_ENCRYPTION = 2

#: TTI AUTH keys whose values are harmless client attributes (never challenge/response material).
_ALLOWED_KEYS = {
    b"AUTH_TERMINAL": "terminal",
    b"AUTH_PROGRAM_NM": "program",
    b"AUTH_MACHINE": "machine",
    b"AUTH_PID": "pid",
    b"AUTH_SID": "os_user",
}
_AUTH_KEY = re.compile(rb"AUTH_[A-Z0-9_]+")
_ORA = re.compile(rb"ORA-(\d{5}): ?([^\n\x00]*)")
_LOGIN_FAILED_ORA = frozenset({1004, 1005, 1017, 1045, 28000, 28001, 28040})
_SUCCESS_MARKERS = (b"AUTH_SESSION_ID", b"AUTH_VERSION_STRING")
_ERR = re.compile(r"\(\s*ERR\s*=\s*(\d+)\s*\)", re.IGNORECASE)


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    started: bool = False
    pending_connect: int = 0  # connect data announced but sent after the CONNECT packet
    connect_reported: bool = False
    version: int | None = None
    descriptor: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    auth_reported: bool = False
    user: str | None = None
    data_packets: int = 0
    #: Client DATA payloads since the server last sent DATA. TTI messages have no length of their
    #: own, so a request split over several DATA packets is scanned as one turn (E-9).
    turn: bytearray = field(default_factory=bytearray)
    turn_at: tuple[int, float] = (0, 0.0)  # frame and timestamp of the turn's last client packet
    turn_full: bool = False  # the turn exceeded _MAX_TURN: only its first, contiguous part is scanned


def descriptor_pairs(desc: str, limit: int = 256) -> list[tuple[tuple[str, ...], str]]:
    """Leaf (path, value) pairs of an Oracle Net connect descriptor, keys upper-cased."""
    out: list[tuple[tuple[str, ...], str]] = []
    stack: list[str] = []
    i, n = 0, len(desc)
    while i < n and len(out) < limit and len(stack) < 32:
        ch = desc[i]
        if ch == "(":
            eq = desc.find("=", i + 1)
            if eq < 0:
                break
            stack.append(desc[i + 1 : eq].strip().upper())
            i = eq + 1
            while i < n and desc[i] == " ":
                i += 1
            if i < n and desc[i] != "(":
                close = desc.find(")", i)
                if close < 0:
                    break
                out.append((tuple(stack), desc[i:close].strip()))
                stack.pop()
                i = close + 1
        elif ch == ")":
            if stack:
                stack.pop()
            i += 1
        else:
            i += 1
    return out


_DESC_KEYS: dict[tuple[str, ...], str] = {
    ("CONNECT_DATA", "SERVICE_NAME"): "service_name",
    ("CONNECT_DATA", "SID"): "sid",
    ("CONNECT_DATA", "INSTANCE_NAME"): "instance_name",
    ("CID", "PROGRAM"): "program",
    ("CID", "HOST"): "client_host",
    ("CID", "USER"): "os_user",
    ("ADDRESS", "PROTOCOL"): "protocol",
}


def _summarise(desc: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for path, value in descriptor_pairs(desc):
        key = _DESC_KEYS.get(path[-2:])
        if key and key not in found and value:
            found[key] = value[:128]
    return found


def _printable(raw: bytes, *, space: bool) -> bool:
    lo = 0x20 if space else 0x21
    return all(lo <= b <= 0x7E for b in raw)


def _value_after(buf: bytes, q: int) -> bytes | None:
    """A length-prefixed TTC value starting at ``q`` (thin, OCI and raw encodings)."""
    if q + 3 <= len(buf) and buf[q] == 1 and buf[q + 2] == buf[q + 1]:  # ub4 (1-byte) + len + bytes
        start, ln = q + 3, buf[q + 1]
    elif q + 5 <= len(buf) and buf[q + 1 : q + 4] == b"\x00\x00\x00" and buf[q + 4] == buf[q]:
        start, ln = q + 5, buf[q]  # 4-byte LE length + len + bytes
    elif q < len(buf):
        start, ln = q + 1, buf[q]
    else:
        return None
    value = buf[start : start + ln]
    if len(value) < ln or not _printable(value, space=True):
        return None
    return value


def _user_before(buf: bytes, k: int, klen: int) -> bytes | None:
    """The length-prefixed user name ending right before the first key's length encoding."""
    if k < 1 or buf[k - 1] != klen:
        return None
    for gap in (bytes([1, klen]), bytes([klen, 0, 0, 0]), bytes([0, 0, 0, klen]), bytes([klen]), b""):
        e = k - 1 - len(gap)
        if e < 2 or buf[e : k - 1] != gap:
            continue
        for ln in range(1, min(128, e - 1) + 1):
            if buf[e - ln - 1] == ln and _printable(buf[e - ln : e], space=False):
                return buf[e - ln : e]
    return None


class OraclePlugin(ProtocolPlugin):
    name = "oracle"
    sets = ("databases",)
    description = "Oracle Net (TNS) logins: connect descriptor and O5LOGON metadata (any port)"
    default_ports = frozenset({1521})
    priority = 93

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.bufs[direction]
        buf += data
        client = direction is Direction.CLIENT_TO_SERVER
        while not ctx.detached:
            if client and st.pending_connect and buf[:1] == b"(":
                if len(buf) < st.pending_connect:
                    break
                raw = bytes(buf[: st.pending_connect])
                del buf[: st.pending_connect]
                st.pending_connect = 0
                self._descriptor(ctx, st, raw)
                continue
            if len(buf) < 8:
                break
            length = struct.unpack_from("!H", buf, 0)[0]
            if length == 0:  # large-SDU framing (TNS >= 315): 32-bit length
                length = struct.unpack_from("!I", buf, 0)[0]
            ptype = buf[4]
            if length < 8 or length > _MAX_PACKET or ptype not in _VALID_TYPES:
                ctx.detach()
                return
            if not st.started and (not client or ptype != CONNECT):
                ctx.detach()
                return
            if len(buf) < length:
                break
            pkt = bytes(buf[:length])
            del buf[:length]
            st.started = True
            if client:
                self._client_packet(ctx, st, ptype, pkt)
            else:
                self._server_packet(ctx, st, ptype, pkt)
        if len(buf) > _MAX_BUFFER:
            ctx.detach()

    # -- client ------------------------------------------------------------------------
    def _client_packet(self, ctx: Context, st: _State, ptype: int, pkt: bytes) -> None:
        if ptype == CONNECT:
            self._connect(ctx, st, pkt)
        elif ptype == DATA:
            payload = pkt[10:]
            if st.pending_connect and payload[:1] == b"(":
                st.pending_connect = 0
                self._descriptor(ctx, st, payload)
                return
            self._count_data(ctx, st)
            if st.auth_reported or st.turn_full:
                return
            if len(st.turn) + len(payload) > _MAX_TURN:
                st.turn_full = True  # stop collecting: a later packet must not be joined across a hole
                return
            st.turn += payload
            st.turn_at = (ctx.frame, ctx.timestamp)

    def _end_turn(self, ctx: Context, st: _State) -> None:
        """The client's turn is over (the server answers, or the flow ends): scan its request."""
        if st.turn:
            if not st.auth_reported and b"AUTH_" in st.turn:
                now = ctx.frame, ctx.timestamp
                ctx.frame, ctx.timestamp = st.turn_at  # the finding points at the request, not the reply
                try:
                    self._auth_request(ctx, st, bytes(st.turn))
                finally:
                    ctx.frame, ctx.timestamp = now
            st.turn.clear()
        st.turn_full = False

    def on_close(self, ctx: Context) -> None:
        if not ctx.detached:
            self._end_turn(ctx, ctx.state)

    def _connect(self, ctx: Context, st: _State, pkt: bytes) -> None:
        if len(pkt) < 34:
            ctx.detach()
            return
        version = struct.unpack_from("!H", pkt, 8)[0]
        if not 300 <= version <= 400:
            ctx.detach()
            return
        st.version = version
        cd_len, cd_off = struct.unpack_from("!HH", pkt, 24)
        if cd_len == 0:
            return
        if cd_off + cd_len <= len(pkt):
            self._descriptor(ctx, st, pkt[cd_off : cd_off + cd_len])
        elif cd_off >= len(pkt):
            st.pending_connect = cd_len  # long descriptors follow the CONNECT packet
        else:
            ctx.detach()

    def _descriptor(self, ctx: Context, st: _State, raw: bytes) -> None:
        desc = text(raw[:4096]).strip()
        if not desc.startswith("("):
            ctx.detach()
            return
        if st.connect_reported:  # RESEND: the client repeats its CONNECT
            return
        st.connect_reported = True
        st.descriptor = _summarise(desc)
        if st.descriptor.get("protocol", "").upper() == "TCPS":
            st.tags.append("tcps")
        target = st.descriptor.get("service_name")
        label = f"service {target}" if target else (f"SID {st.descriptor['sid']}" if "sid" in st.descriptor else "")
        value = f"Oracle TNS connect ({label})" if label else "Oracle TNS connect"
        extra: dict[str, Any] = dict(st.descriptor)
        extra.pop("protocol", None)
        if st.version is not None:
            extra["tns_version"] = st.version
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.INFO, protocol="Oracle", value=value, plugin=self.name,
            risk="low", tags=self._tags(ctx), extra=extra,
        )  # fmt: skip

    def _auth_request(self, ctx: Context, st: _State, payload: bytes) -> None:
        first = _AUTH_KEY.search(payload)
        if first is None:
            return
        klen = len(first.group(0))
        user = _user_before(payload, first.start(), klen)
        attrs: dict[str, str] = {}
        for key, name in _ALLOWED_KEYS.items():
            pos = payload.find(bytes([len(key)]) + key)
            while pos >= 0:
                end = pos + 1 + len(key)
                if end >= len(payload) or not (payload[end] in b"_" or 0x41 <= payload[end] <= 0x5A):
                    value = _value_after(payload, end)
                    if value:
                        attrs[name] = text(value[:128])
                    break
                pos = payload.find(bytes([len(key)]) + key, pos + 1)
        if user is None and not attrs:
            return  # not an AUTH request we understand (e.g. a server key list echoed in data)
        st.auth_reported = True
        st.user = text(user) if user else None
        extra: dict[str, Any] = {}
        for dkey in ("service_name", "sid"):
            if dkey in st.descriptor:
                extra[dkey] = st.descriptor[dkey]
        extra.update(attrs)
        if payload[:1] == b"\x03" and len(payload) > 1:
            extra["phase"] = {0x76: "auth-phase-one", 0x73: "auth-phase-two"}.get(payload[1], f"0x{payload[1]:02x}")
        ctx.emit(
            Direction.CLIENT_TO_SERVER, Kind.AUTH_EVENT, protocol="Oracle", username=st.user,
            value="Oracle O5LOGON login", plugin=self.name, risk="medium", tags=self._tags(ctx),
            extra=extra,
        )  # fmt: skip

    # -- server ------------------------------------------------------------------------
    def _server_packet(self, ctx: Context, st: _State, ptype: int, pkt: bytes) -> None:
        if ptype == ACCEPT:
            if len(pkt) >= 10:
                st.version = struct.unpack_from("!H", pkt, 8)[0]
        elif ptype == REFUSE:
            self._refuse(ctx, st, pkt)
        elif ptype == DATA:
            payload = pkt[10:]
            self._end_turn(ctx, st)
            self._count_data(ctx, st)
            if payload[:4] == _ANO_MAGIC:
                self._ano_response(ctx, st, payload)
            elif st.auth_reported:
                self._auth_response(ctx, st, payload)

    def _refuse(self, ctx: Context, st: _State, pkt: bytes) -> None:
        extra: dict[str, Any] = {}
        if len(pkt) >= 12:
            extra["user_reason"], extra["system_reason"] = pkt[8], pkt[9]
            ln = struct.unpack_from("!H", pkt, 10)[0]
            data = text(pkt[12 : 12 + min(ln, 2048)])
            m = _ERR.search(data)
            if m:
                extra["error_code"] = int(m.group(1))
        code = extra.get("error_code")
        value = f"Oracle TNS connect refused (ORA-{code:05d})" if code is not None else "Oracle TNS connect refused"
        for key in ("service_name", "sid"):
            if key in st.descriptor:
                extra[key] = st.descriptor[key]
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.INFO, protocol="Oracle", reverse=True, value=value,
            plugin=self.name, risk="info", tags=self._tags(ctx), extra=extra,
        )  # fmt: skip
        ctx.detach()

    def _ano_response(self, ctx: Context, st: _State, payload: bytes) -> None:
        # header: magic(4) length(2) version(4) services(2) flags(1); service: id(2) count(2) error(4);
        # sub-packet: length(2) type(2) value. The server answers service 2 with the chosen algorithm.
        if len(payload) < 13:
            return
        services = struct.unpack_from("!H", payload, 10)[0]
        pos = 13
        for _ in range(min(services, 8)):
            if pos + 8 > len(payload):
                return
            sid, count = struct.unpack_from("!HH", payload, pos)
            pos += 8
            for _ in range(min(count, 16)):
                if pos + 4 > len(payload):
                    return
                ln, stype = struct.unpack_from("!HH", payload, pos)
                value = payload[pos + 4 : pos + 4 + ln]
                pos += 4 + ln
                if sid == _ANO_ENCRYPTION and stype == 2 and len(value) == 1 and value[0] != 0:
                    st.tags.append("ano-encryption")
                    ctx.emit(
                        Direction.SERVER_TO_CLIENT, Kind.AUTH_EVENT, protocol="Oracle", reverse=True,
                        value="Oracle login (native network encryption)", plugin=self.name, risk="info",
                        tags=self._tags(ctx, "encrypted"), extra={"ano_algorithm_id": value[0]},
                    )  # fmt: skip
                    ctx.detach()
                    return

    def _auth_response(self, ctx: Context, st: _State, payload: bytes) -> None:
        if any(m in payload for m in _SUCCESS_MARKERS):
            self._result(ctx, st, ok=True, extra={})
            return
        m = _ORA.search(payload)
        if m and int(m.group(1)) in _LOGIN_FAILED_ORA:
            msg = text(m.group(0)[:120])
            self._result(ctx, st, ok=False, extra={"error_code": f"ORA-{m.group(1).decode()}", "message": msg})

    def _count_data(self, ctx: Context, st: _State) -> None:
        st.data_packets += 1
        if st.data_packets > _MAX_DATA_PACKETS:
            ctx.detach()

    # -- emission ----------------------------------------------------------------------
    def _tags(self, ctx: Context, *more: str) -> list[str]:
        tags = list(more)
        tags.extend(t for t in ctx.state.tags if t not in tags)
        if ctx.flow.server.port != 1521:
            tags.append("nonstandard-port")
        return tags

    def _result(self, ctx: Context, st: _State, *, ok: bool, extra: dict[str, Any]) -> None:
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="Oracle", reverse=True,
            username=st.user, value="login succeeded" if ok else "login failed",
            plugin=self.name, tags=self._tags(ctx), extra=extra,
        )  # fmt: skip
        ctx.detach()
