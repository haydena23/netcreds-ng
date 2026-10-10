"""Public plugin API (version 1).

Third-party packages register plugins through the ``netcreds_ng.plugins``
entry-point group; each entry point must resolve to a plugin *class*.

Plugin kinds
------------
* :class:`ProtocolPlugin` - inspects reassembled TCP streams and UDP datagrams
  and emits :class:`~netcreds_ng.model.Finding` objects.
* :class:`EnricherPlugin` - inspects/annotates findings before they reach sinks.
* :class:`SinkPlugin` - consumes findings (files, databases, notifications).

Protocol plugins never see other plugins' state. Exceptions raised by a plugin
are caught by the engine, counted per plugin, and reported - they never abort
the run, and they are never silently ignored.
"""

from __future__ import annotations

import enum
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, ClassVar

from netcreds_ng.model import Endpoint, Finding, Kind, RunStats

PLUGIN_API = 1


class Direction(enum.IntEnum):
    CLIENT_TO_SERVER = 0
    SERVER_TO_CLIENT = 1

    @property
    def other(self) -> Direction:
        return Direction(1 - self)


class Transport(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class FlowInfo:
    flow_id: int
    transport: Transport
    client: Endpoint
    server: Endpoint

    def endpoints(self, direction: Direction) -> tuple[Endpoint, Endpoint]:
        """(source, destination) for data travelling in ``direction``."""
        if direction is Direction.CLIENT_TO_SERVER:
            return self.client, self.server
        return self.server, self.client


class Context:
    """Per-(flow, plugin) handle passed to protocol plugin callbacks."""

    __slots__ = ("_detached", "_emit", "flow", "frame", "options", "state", "timestamp", "tls_decryption")

    def __init__(self, flow: FlowInfo, emit: Any, options: dict[str, Any]) -> None:
        self.flow = flow
        self.state: Any = None
        self._emit = emit
        self._detached = False
        self.timestamp = 0.0
        self.frame = 0
        self.options = options
        #: True when the engine decrypts TLS with a key log. After STARTTLS (or an SSLRequest) the
        #: plugin then receives the decrypted plaintext, or nothing, but never ciphertext, so it can
        #: keep parsing instead of detaching.
        self.tls_decryption = False

    def emit(
        self,
        direction: Direction,
        kind: Kind,
        *,
        protocol: str,
        reverse: bool = False,
        **fields: Any,
    ) -> Finding:
        """Create and publish a finding for data seen in ``direction``.

        ``reverse=True`` swaps source/destination (e.g. a server reply that
        reports on the client's login).
        """
        src, dst = self.flow.endpoints(direction.other if reverse else direction)
        finding = Finding(
            protocol=protocol,
            kind=kind,
            src=src,
            dst=dst,
            timestamp=self.timestamp,
            frame=self.frame,
            **fields,
        )
        self._emit(finding)
        return finding

    def detach(self) -> None:
        """Stop receiving data for this flow (the plugin has decided it is not interested)."""
        self._detached = True

    @property
    def detached(self) -> bool:
        return self._detached


class ProtocolPlugin:
    """Base class for protocol plugins.

    Subclasses set the class attributes and override the callbacks they need.
    One plugin instance serves every flow; per-flow state lives in
    ``ctx.state`` (initialised from :meth:`new_state`).
    """

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    version: ClassVar[str] = "1.0"
    api_version: ClassVar[int] = PLUGIN_API
    transports: ClassVar[frozenset[Transport]] = frozenset({Transport.TCP})
    #: Port hints. Plugins still see traffic on any port unless ``ports_only``.
    default_ports: ClassVar[frozenset[int]] = frozenset()
    ports_only: ClassVar[bool] = False
    #: Opt-in plugins are disabled unless enabled explicitly.
    opt_in: ClassVar[bool] = False
    #: Named sets this plugin belongs to (``--plugins databases``). A plugin may join the
    #: built-in sets or name new ones; set names must not clash with plugin names.
    sets: ClassVar[tuple[str, ...]] = ()
    priority: ClassVar[int] = 100

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}

    def new_state(self, flow: FlowInfo) -> Any:
        return None

    def on_data(self, ctx: Context, direction: Direction, data: bytes) -> None:
        """Called with in-order TCP stream bytes."""

    def on_gap(self, ctx: Context, direction: Direction, size: int) -> None:
        """Called when ``size`` stream bytes are missing before the next ``on_data``.

        The default detaches the plugin from the flow: continuing would splice
        bytes from both sides of the hole and could report a wrong credential
        as fact. Plugins that can resynchronise (e.g. line protocols discarding
        the partial line) override this.
        """
        ctx.detach()

    def on_datagram(self, ctx: Context, direction: Direction, data: bytes) -> None:
        """Called with each UDP payload."""

    def on_close(self, ctx: Context) -> None:
        """Called once when the flow ends or is evicted."""


class EnricherPlugin:
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    version: ClassVar[str] = "1.0"
    api_version: ClassVar[int] = PLUGIN_API
    opt_in: ClassVar[bool] = False
    priority: ClassVar[int] = 100

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = options or {}

    def enrich(self, finding: Finding) -> Iterator[Finding]:
        """Annotate ``finding`` in place (e.g. add tags). May yield additional findings."""
        return iter(())


@dataclass
class SinkContext:
    stats: RunStats
    options: dict[str, Any] = field(default_factory=dict)


class SinkPlugin:
    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    version: ClassVar[str] = "1.0"
    api_version: ClassVar[int] = PLUGIN_API

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        self.target = target
        self.options = options or {}

    def open(self, ctx: SinkContext) -> None:
        """Called before the first finding."""

    def write(self, finding: Finding) -> None:
        raise NotImplementedError

    def close(self, stats: RunStats) -> None:
        """Called once at the end of the run."""
