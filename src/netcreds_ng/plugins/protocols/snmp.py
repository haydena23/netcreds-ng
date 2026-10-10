"""SNMP: v1/v2c community strings and v3 user/security-level exposure."""

from __future__ import annotations

from dataclasses import dataclass, field

from netcreds_ng.model import Kind
from netcreds_ng.plugins.api import Context, Direction, FlowInfo, ProtocolPlugin, Transport
from netcreds_ng.plugins.protocols._util import printable_ascii, text
from netcreds_ng.proto.der import DERError, read_tlv

VERSIONS = {0: "v1", 1: "v2c", 3: "v3"}
REQUEST_PDUS = {0xA0: "GetRequest", 0xA1: "GetNextRequest", 0xA3: "SetRequest", 0xA4: "Trap",
                0xA5: "GetBulkRequest", 0xA6: "InformRequest", 0xA7: "SNMPv2-Trap"}  # fmt: skip
ALL_PDUS = set(REQUEST_PDUS) | {0xA2, 0xA8}
DEFAULT_COMMUNITIES = {"public", "private", "community", "admin", "cisco", "manager", "snmp"}
SEC_LEVEL = {0: ("noAuthNoPriv", "high"), 1: ("authNoPriv", "medium"), 3: ("authPriv", "info")}


@dataclass
class _State:
    reported: set[tuple[object, ...]] = field(default_factory=set)


class SNMPPlugin(ProtocolPlugin):
    name = "snmp"
    sets = ("network", "legacy")
    description = "SNMP v1/v2c community strings; SNMPv3 users and security level"
    transports = frozenset({Transport.UDP})
    default_ports = frozenset({161, 162})
    priority = 80

    def new_state(self, flow: FlowInfo) -> _State:
        return _State()

    def on_datagram(self, ctx: Context, direction: Direction, data: bytes) -> None:
        try:
            msg = read_tlv(data)
            if msg.tag != 0x30 or msg.end != len(data):
                return
            parts = msg.children()
            if len(parts) < 3 or parts[0].tag != 0x02:
                return
            version = parts[0].as_int()
        except DERError:
            return
        try:
            if version in (0, 1):
                self._community(ctx, direction, version, parts)
            elif version == 3:
                self._v3(ctx, direction, parts)
        except (DERError, IndexError):
            return

    def _community(self, ctx: Context, direction: Direction, version: int, parts: list) -> None:  # type: ignore[type-arg]
        community, pdu = parts[1], parts[2]
        if community.tag != 0x04 or pdu.tag not in ALL_PDUS:
            return
        if pdu.tag not in REQUEST_PDUS:
            return  # responses repeat the request's community
        raw = community.value
        if not printable_ascii(raw) and ctx.flow.server.port not in self.default_ports:
            return  # strictness on non-standard ports
        value = text(raw)
        st: _State = ctx.state
        key = (value, version, pdu.tag)
        if key in st.reported:
            return
        st.reported.add(key)
        tags = []
        if pdu.tag == 0xA3:
            tags.append("write-access")
        if value.lower() in DEFAULT_COMMUNITIES:
            tags.append("default-community")
        ctx.emit(
            direction, Kind.COMMUNITY, protocol="SNMP", secret=value, plugin=self.name, risk="high", tags=tags,
            extra={"version": VERSIONS.get(version, str(version)), "pdu": REQUEST_PDUS[pdu.tag]},
        )  # fmt: skip

    def _v3(self, ctx: Context, direction: Direction, parts: list) -> None:  # type: ignore[type-arg]
        global_data, sec_params = parts[1], parts[2]
        gd = global_data.children()
        if len(gd) < 4 or sec_params.tag != 0x04:
            return
        flags = gd[2].value[0] if gd[2].value else 0
        usm = read_tlv(sec_params.value)
        fields = usm.children()
        if len(fields) < 6:
            return
        user = text(fields[3].value)
        if not user:
            return  # engine discovery
        level, risk = SEC_LEVEL.get(flags & 0x03, ("invalid", "medium"))
        st: _State = ctx.state
        key = ("v3", user, level)
        if key in st.reported:
            return
        st.reported.add(key)
        ctx.emit(
            direction, Kind.AUTH_EVENT, protocol="SNMP", username=user, value=f"SNMPv3 {level}", risk=risk,
            plugin=self.name, tags=[] if level == "authPriv" else [f"snmpv3-{level}"],
            extra={"version": "v3", "security_level": level, "engine_id": fields[0].value.hex()},
        )  # fmt: skip
