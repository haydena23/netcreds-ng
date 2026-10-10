"""VNC / RFB: security-type exposure (no authentication, unencrypted DES challenge-response).

Scope: VNC Authentication is reported as metadata only. The 16-byte challenge
and response are consumed to keep the stream aligned and are never retained or
emitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_VERSION = re.compile(rb"^RFB (\d{3})\.(\d{3})\n$")
_MAX_REASON = 1024
_MAX_BUFFER = 4096

SECURITY_TYPES = {
    1: "None", 2: "VNC Authentication", 5: "RA2", 6: "RA2ne", 16: "Tight", 17: "Ultra",
    18: "TLS", 19: "VeNCrypt", 20: "SASL", 21: "MD5 hash authentication", 22: "xvp",
    30: "Apple Remote Desktop",
}  # fmt: skip

_S, _C = int(Direction.SERVER_TO_CLIENT), int(Direction.CLIENT_TO_SERVER)


@dataclass
class _State:
    buf: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    stage: str = "ver_s"
    server_ver: tuple[int, int] = (0, 0)
    minor: int = 0  # protocol minor version in use: 3, 7 or 8
    offered: tuple[int, ...] = ()
    sec_type: int = 0
    failed_pending: bool = False  # 3.8 failure result waiting for its reason string


def _effective_minor(minor: int) -> int:
    """Map the advertised minor version to the handshake variant (3.3 / 3.7 / 3.8)."""
    if minor >= 8:
        return 8
    if minor == 7:
        return 7
    return 3  # 3.3 and the non-standard 3.4-3.6 / 3.889 variants use the 3.3 handshake


class VNCPlugin(ProtocolPlugin):
    name = "vnc"
    sets = ("remote-access",)
    description = "VNC/RFB security type, unauthenticated sessions and auth results (any port)"
    default_ports = frozenset(range(5900, 5907))
    priority = 94

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        st.buf[direction].extend(data)
        try:
            self._pump(ctx, st)
        finally:
            if not ctx.detached and (len(st.buf[0]) > _MAX_BUFFER or len(st.buf[1]) > _MAX_BUFFER):
                ctx.detach()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.detach()  # fixed-size framing cannot be resynchronised

    def on_close(self, ctx: Context) -> None:
        st: _State = ctx.state
        if st.failed_pending:
            st.failed_pending = False
            self._result(ctx, st, False, None)

    # -- state machine ------------------------------------------------------

    @staticmethod
    def _take(st: _State, side: int, n: int) -> bytes | None:
        buf = st.buf[side]
        if len(buf) < n:
            return None
        out = bytes(buf[:n])
        del buf[:n]
        return out

    def _pump(self, ctx: Context, st: _State) -> None:
        while not ctx.detached:
            stage = st.stage
            if stage == "ver_s":
                srv = st.buf[_S]
                if srv and not b"RFB ".startswith(bytes(srv[:4])) and not srv.startswith(b"RFB "):
                    ctx.detach()
                    return
                raw = self._take(st, _S, 12)
                if raw is None:
                    return
                m = _VERSION.match(raw)
                if not m:
                    ctx.detach()
                    return
                st.server_ver = (int(m.group(1)), int(m.group(2)))
                st.stage = "ver_c"
            elif stage == "ver_c":
                raw = self._take(st, _C, 12)
                if raw is None:
                    return
                m = _VERSION.match(raw)
                if not m or int(m.group(1)) != 3:
                    ctx.detach()
                    return
                st.minor = _effective_minor(int(m.group(2)))
                st.stage = "sec_s"
            elif stage == "sec_s":
                if st.minor == 3:
                    raw = self._take(st, _S, 4)
                    if raw is None:
                        return
                    value = int.from_bytes(raw, "big")
                    if value == 0 or value > 255:
                        ctx.detach()  # connection failed (reason follows) or not RFB
                        return
                    self._chosen(ctx, st, value, forced=True)
                else:
                    buf = st.buf[_S]
                    if not buf:
                        return
                    count = buf[0]
                    if count == 0:
                        ctx.detach()  # failure reason string follows; nothing to report
                        return
                    raw = self._take(st, _S, 1 + count)
                    if raw is None:
                        return
                    st.offered = tuple(raw[1:])
                    st.stage = "sec_c"
            elif stage == "sec_c":
                raw = self._take(st, _C, 1)
                if raw is None:
                    return
                if raw[0] not in st.offered:
                    ctx.detach()
                    return
                self._chosen(ctx, st, raw[0], forced=False)
            elif stage == "chal_s":
                if self._take(st, _S, 16) is None:  # challenge: consumed, never retained
                    return
                st.stage = "resp_c"
            elif stage == "resp_c":
                if self._take(st, _C, 16) is None:  # response: consumed, never retained
                    return
                st.stage = "result_s"
            elif stage == "result_s":
                raw = self._take(st, _S, 4)
                if raw is None:
                    return
                value = int.from_bytes(raw, "big")
                if value == 0:
                    self._result(ctx, st, True, None)
                    ctx.detach()
                elif value in (1, 2):  # 2 = too many attempts (some servers)
                    if st.minor == 8:
                        st.failed_pending = True
                        st.stage = "reason_s"
                    else:
                        self._result(ctx, st, False, None)
                        ctx.detach()
                else:
                    ctx.detach()
            elif stage == "reason_s":
                buf = st.buf[_S]
                if len(buf) < 4:
                    return
                n = int.from_bytes(buf[:4], "big")
                if n > _MAX_REASON:
                    ctx.detach()  # on_close reports the failure without a reason
                    return
                raw = self._take(st, _S, 4 + n)
                if raw is None:
                    return
                st.failed_pending = False
                self._result(ctx, st, False, text(raw[4:]))
                ctx.detach()
            else:
                ctx.detach()
                return

    def _chosen(self, ctx: Context, st: _State, sec_type: int, forced: bool) -> None:
        st.sec_type = sec_type
        name = SECURITY_TYPES.get(sec_type, f"type {sec_type}")
        version = f"3.{st.minor}"
        extra = {"version": version, "security_type": str(sec_type), "security_type_name": name,
                 "selected_by": "server" if forced else "client"}  # fmt: skip
        if sec_type == 1:
            value, risk, tags = "VNC session without authentication", "high", ["no-authentication"]
        elif sec_type == 2:
            value = "VNC password authentication (DES challenge-response, unencrypted session)"
            risk, tags = "medium", ["challenge-response", "unencrypted-session"]
        else:
            value, risk, tags = f"VNC security type {name}", "low", ["non-vnc-auth"]
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_EVENT, protocol="VNC", reverse=True,
            value=value, risk=risk, plugin=self.name, extra=extra,
            tags=tags + ([] if ctx.flow.server.port in self.default_ports else ["nonstandard-port"]),
        )  # fmt: skip
        if sec_type == 1:
            if st.minor == 8:
                st.stage = "result_s"
            else:
                ctx.detach()  # 3.3 / 3.7: no SecurityResult for None
        elif sec_type == 2:
            st.stage = "chal_s"
        else:
            ctx.detach()  # encrypted or unknown handshake follows

    def _result(self, ctx: Context, st: _State, ok: bool, reason: str | None) -> None:
        extra = {"security_type": str(st.sec_type)}
        if reason:
            extra["reason"] = reason
        ctx.emit(
            Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="VNC", reverse=True,
            value="VNC authentication succeeded" if ok else "VNC authentication failed",
            plugin=self.name, extra=extra,
        )  # fmt: skip
