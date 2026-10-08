"""Example third-party netcreds-ng plugin: BSD rexec (TCP 512) cleartext logins."""

from __future__ import annotations

from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_MAX = 2048


@dataclass
class _State:
    buf: bytearray = field(default_factory=bytearray)
    done: bool = False


class RexecPlugin(ProtocolPlugin):
    """rexec client request: ``<stderr-port>\\0<user>\\0<password>\\0<command>\\0`` (all cleartext)."""

    name = "rexec"
    description = "BSD rexec cleartext logins (example third-party plugin)"
    default_ports = frozenset({512})
    ports_only = True  # the request format is too generic to detect on arbitrary ports
    priority = 150

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        if direction is Direction.SERVER_TO_CLIENT:
            if st.done and data[:1] in (b"\x00", b"\x01"):
                ok = data[:1] == b"\x00"
                ctx.emit(direction, Kind.AUTH_RESULT, protocol="rexec", reverse=True, plugin=self.name,
                         value="login succeeded" if ok else "login failed")  # fmt: skip
                ctx.detach()
            return
        if st.done:
            return
        st.buf += data
        parts = bytes(st.buf).split(b"\x00")
        if len(parts) >= 5:  # four NUL-terminated fields received
            port, user, password, command = parts[:4]
            if not port.isdigit() and port != b"":
                ctx.detach()
                return
            st.done = True
            ctx.emit(direction, Kind.CREDENTIAL, protocol="rexec", plugin=self.name, username=text(user),
                     secret=text(password), risk="high", extra={"command": text(command[:200])})  # fmt: skip
        elif len(st.buf) > _MAX:
            ctx.detach()
