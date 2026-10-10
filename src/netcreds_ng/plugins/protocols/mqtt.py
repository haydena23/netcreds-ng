"""MQTT CONNECT username/password (levels 3, 4, 5) and CONNACK result tracking."""

from __future__ import annotations

from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin
from netcreds_ng.plugins.protocols._util import text

_MAX_PACKET = 64 * 1024  # a CONNECT larger than this is not credible
_CONNECT = 0x10
_CONNACK = 0x20
_NAMES = (b"MQTT", b"MQIsdp")
# Failed-login return codes: v3.1/3.1.1 4 bad credentials, 5 not authorised;
# v5 0x86 bad user name or password, 0x87 not authorised.
_FAILED_V4 = frozenset({4, 5})
_FAILED_V5 = frozenset({0x86, 0x87})


class _Malformed(ValueError):
    pass


@dataclass
class _State:
    bufs: tuple[bytearray, bytearray] = field(default_factory=lambda: (bytearray(), bytearray()))
    level: int = 4
    username: str | None = None
    awaiting_connack: bool = False
    client_done: bool = False


def _remaining_length(buf: bytearray) -> tuple[int, int] | None:
    """(remaining length, bytes used by the varint after the first byte); None if incomplete."""
    value = 0
    for i in range(4):
        if 1 + i >= len(buf):
            return None
        b = buf[1 + i]
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return value, i + 1
    raise _Malformed("remaining length too long")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise _Malformed("truncated field")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def string(self) -> bytes:
        return self.take(self.u16())

    def varint(self) -> int:
        value = 0
        for i in range(4):
            b = self.u8()
            value |= (b & 0x7F) << (7 * i)
            if not b & 0x80:
                return value
        raise _Malformed("varint too long")

    def skip_properties(self) -> None:
        self.take(self.varint())


class MQTTPlugin(ProtocolPlugin):
    name = "mqtt"
    wants_encrypted = False
    sets = ("iot",)
    description = "MQTT CONNECT username/password and CONNACK result (any port)"
    default_ports = frozenset({1883})
    priority = 91

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        st: _State = ctx.state
        if direction is Direction.CLIENT_TO_SERVER and st.client_done:
            return  # E-5: client data after the CONNECT is not read, so the CONNACK still counts
        ctx.detach()  # the CONNECT or the CONNACK (the first packet each way) was lost

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        st: _State = ctx.state
        if direction is Direction.CLIENT_TO_SERVER and st.client_done:
            return
        buf = st.bufs[int(direction)]
        buf += data
        try:
            if direction is Direction.CLIENT_TO_SERVER:
                self._client(ctx, st, buf)
            else:
                self._server(ctx, st, buf)
        except _Malformed:
            ctx.detach()
        if ctx.detached:
            buf.clear()

    def _client(self, ctx: Context, st: _State, buf: bytearray) -> None:
        if not buf:
            return
        if buf[0] != _CONNECT:
            ctx.detach()
            return
        rl = _remaining_length(buf)
        if rl is None:
            return
        length, used = rl
        if length > _MAX_PACKET or length < 10:
            raise _Malformed("implausible CONNECT length")
        total = 1 + used + length
        if len(buf) < total:
            return
        body = bytes(buf[1 + used : total])
        buf.clear()
        st.client_done = True
        self._connect(ctx, st, body)

    def _connect(self, ctx: Context, st: _State, body: bytes) -> None:
        r = _Reader(body)
        if r.string() not in _NAMES:
            raise _Malformed("not an MQTT CONNECT")
        level = r.u8()
        if level not in (3, 4, 5):
            raise _Malformed("unsupported protocol level")
        flags = r.u8()
        r.take(2)  # keep alive
        if level == 5:
            r.skip_properties()
        client_id = r.string()
        if flags & 0x04:  # will
            if level == 5:
                r.skip_properties()
            r.string()  # will topic
            r.string()  # will payload
        user = r.string() if flags & 0x80 else None
        password = r.string() if flags & 0x40 else None
        st.level = level
        if user is None and password is None:
            ctx.detach()
            return
        tags = [] if ctx.flow.server.port == 1883 else ["nonstandard-port"]
        username = text(user) if user is not None else None
        extra = {"client_id": text(client_id), "protocol_level": level}
        if password is not None:
            kind = Kind.CREDENTIAL if username is not None else Kind.PASSWORD
            ctx.emit(
                Direction.CLIENT_TO_SERVER, kind, protocol="MQTT", plugin=self.name,
                username=username, secret=text(password), risk="high", tags=tags, extra=extra,
            )  # fmt: skip
        else:
            ctx.emit(
                Direction.CLIENT_TO_SERVER, Kind.USERNAME, protocol="MQTT", plugin=self.name,
                username=username, tags=tags, extra=extra,
            )  # fmt: skip
        st.username = username
        st.awaiting_connack = True

    def _server(self, ctx: Context, st: _State, buf: bytearray) -> None:
        if not st.awaiting_connack:
            # CONNACK is the first server packet; wait for the client's CONNECT first.
            if st.client_done:
                ctx.detach()
            else:
                buf.clear()  # server data before CONNECT: not our conversation shape
                ctx.detach()
            return
        if not buf:
            return
        if buf[0] != _CONNACK:
            ctx.detach()
            return
        rl = _remaining_length(buf)
        if rl is None:
            return
        length, used = rl
        if length < 2 or length > _MAX_PACKET:
            raise _Malformed("implausible CONNACK length")
        total = 1 + used + length
        if len(buf) < total:
            return
        code = buf[1 + used + 1]
        st.awaiting_connack = False
        failed = _FAILED_V5 if st.level == 5 else _FAILED_V4
        if code == 0 or code in failed:
            ctx.emit(
                Direction.SERVER_TO_CLIENT, Kind.AUTH_RESULT, protocol="MQTT", reverse=True, plugin=self.name,
                username=st.username, value="login succeeded" if code == 0 else "login failed",
                extra={"return_code": code},
            )  # fmt: skip
        ctx.detach()
