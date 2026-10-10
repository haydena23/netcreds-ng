"""NTLM authentication events in any binary TCP carrier (SMB, LDAP, MSSQL, DCE-RPC, ...).

Reports who authenticated, from which workstation, to which server, with which
NTLM version. Evidence is the frame number plus an event id derived from metadata only;
the challenge/response material is never extracted or hashed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.proto import ntlm

_WINDOW = 64 * 1024


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    seen: set[str] = field(default_factory=set)
    target: str = ""


class NTLMPlugin(ProtocolPlugin):
    name = "ntlm"
    wants_encrypted = False
    sets = ("directory", "legacy")
    description = "NTLM authentications (user, domain, workstation, NTLMv1/v2) in any TCP carrier"
    default_ports = frozenset({139, 445, 389, 1433, 135, 593, 3268})
    priority = 60

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        ctx.state.bufs[direction].clear()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        buf = st.bufs[direction]
        buf += data
        keep_from = max(0, len(buf) - (len(ntlm.SIGNATURE) - 1))
        pos = buf.find(ntlm.SIGNATURE)
        while pos != -1:
            msg = bytes(buf[pos:])
            mtype = ntlm.message_type(msg)
            if mtype is None:  # signature at the very end; wait for more bytes
                keep_from = min(keep_from, pos)
                break
            if mtype == 2:
                chal = ntlm.parse_challenge(msg)
                if chal is not None:
                    st.target = chal.target_name
            elif mtype == 3:
                auth = ntlm.parse_authenticate(msg)
                if auth is None:
                    keep_from = min(keep_from, pos)  # incomplete: retry once more data arrives
                    break
                self._report(ctx, st, direction, auth)
            pos = buf.find(ntlm.SIGNATURE, pos + 8)
        del buf[:keep_from]
        if len(buf) > _WINDOW:
            del buf[: len(buf) - _WINDOW]

    def _report(self, ctx: Context, st: _State, direction: Direction, auth: ntlm.Authenticate) -> None:
        identity = f"{auth.domain}|{auth.user}|{auth.workstation}|{auth.version}"
        if identity in st.seen or auth.version == "anonymous":
            return
        st.seen.add(identity)
        # Event id from non-secret metadata only. Hashing the message itself would include the
        # NT response, which is testable against candidate passwords: never derive from it.
        # Endpoints + capture time + frame (not the per-process flow id) keep it stable under -j.
        flow = ctx.flow
        event_id = hashlib.sha256(
            f"{flow.client}|{flow.server}|{ctx.timestamp:.6f}|{ctx.frame}|{identity}".encode()
        ).hexdigest()[:16]
        risk = "high" if auth.version == "NTLMv1" else "medium"
        ctx.emit(
            direction, Kind.AUTH_EVENT, protocol="NTLM", username=auth.user, domain=auth.domain or None,
            value=f"{auth.version} authentication", risk=risk, plugin=self.name,
            tags=["ntlmv1"] if auth.version == "NTLMv1" else [],
            extra={"workstation": auth.workstation, "ntlm_version": auth.version, "target": st.target,
                   "event_id": event_id, "server_port": ctx.flow.server.port},
        )  # fmt: skip
