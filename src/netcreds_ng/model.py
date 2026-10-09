"""Core data model: endpoints, findings, and run statistics."""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any


class Kind(str, enum.Enum):
    """What a finding represents."""

    CREDENTIAL = "credential"  # username and secret together
    USERNAME = "username"
    PASSWORD = "password"
    AUTH_EVENT = "auth_event"  # challenge/response authentication observed (NTLM, Kerberos, ...)
    TOKEN = "token"  # bearer tokens, JWTs
    API_KEY = "api_key"
    COOKIE = "cookie"
    COMMUNITY = "community"  # SNMP community string
    AUTH_RESULT = "auth_result"  # login success / failure observed
    URL = "url"
    POST = "post"
    SEARCH = "search"
    INFO = "info"
    ALERT = "alert"  # behavioural detection (brute force, spraying, ...) raised by an enricher

    @property
    def is_secret(self) -> bool:
        return self in _SECRET_KINDS


_SECRET_KINDS = frozenset(
    {Kind.CREDENTIAL, Kind.PASSWORD, Kind.TOKEN, Kind.API_KEY, Kind.COOKIE, Kind.COMMUNITY}
)


@dataclass(frozen=True, order=True)
class Endpoint:
    ip: str
    port: int

    def __str__(self) -> str:
        if self.port == 0:  # host-level (e.g. an alert spanning many connections)
            return self.ip
        if ":" in self.ip:
            return f"[{self.ip}]:{self.port}"
        return f"{self.ip}:{self.port}"


@dataclass
class Finding:
    """A single extracted item. The one currency shared by plugins, enrichers and sinks."""

    protocol: str
    kind: Kind
    src: Endpoint
    dst: Endpoint
    timestamp: float = 0.0
    frame: int = 0
    username: str | None = None
    secret: str | None = None
    domain: str | None = None
    value: str | None = None  # display value for non-credential kinds (URL, auth summary, ...)
    risk: str = "info"  # info / low / medium / high
    plugin: str = ""
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def display(self) -> str:
        """Human readable primary value."""
        if self.kind is Kind.CREDENTIAL:
            user = self.username or ""
            if self.domain:
                user = f"{self.domain}\\{user}"
            return f"{user}:{self.secret or ''}"
        if self.kind is Kind.USERNAME:
            return self.username or self.value or ""
        if self.kind is Kind.PASSWORD:
            return self.secret or self.value or ""
        if self.value is not None:
            return self.value
        return self.secret or self.username or ""

    @property
    def outcome(self) -> str | None:
        """For AUTH_RESULT findings: ``"success"``, ``"failure"`` or None if unknown.

        Plugins may set ``extra["outcome"]`` explicitly; otherwise the conventional
        wording of ``value`` ("login failed", "... succeeded", "reject", "accept") is used.
        """
        if self.kind is not Kind.AUTH_RESULT:
            return None
        explicit = self.extra.get("outcome")
        if explicit in ("success", "failure"):
            return str(explicit)
        v = (self.value or "").lower()
        if "fail" in v or "reject" in v or "denied" in v:
            return "failure"
        if "succe" in v or "accept" in v or v.endswith(" ok"):
            return "success"
        return None

    def dedup_key(self) -> tuple[Any, ...]:
        # Every login attempt result is its own event (repeated failures can mean brute forcing).
        attempt = self.frame if self.kind is Kind.AUTH_RESULT else None
        return (
            attempt,
            self.protocol,
            self.kind.value,
            self.src.ip,
            self.dst.ip,
            self.dst.port,
            self.username,
            self.secret,
            self.domain,
            self.value,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["src"] = str(self.src)
        data["dst"] = str(self.dst)
        data["display"] = self.display
        return {k: v for k, v in data.items() if v not in (None, [], {})}


@dataclass
class RunStats:
    """Counters surfaced in summaries; nothing is dropped silently."""

    frames: int = 0
    decoded: int = 0
    undecodable: int = 0
    truncated_frames: int = 0
    filtered: int = 0
    tcp_flows: int = 0
    udp_flows: int = 0
    ip_fragments: int = 0
    ip_reassembled: int = 0
    ip_fragments_expired: int = 0  # incomplete datagrams dropped (timeout, table full, end of input)
    ip_fragment_duplicates: int = 0  # late copies of fragments of already reassembled datagrams
    tcp_gaps: int = 0
    tcp_gap_bytes: int = 0
    tcp_retransmitted_bytes: int = 0
    # capture health (see netcreds_ng.health)
    tcp_data_segments: int = 0
    tcp_payload_bytes: int = 0
    tcp_duplicate_segments: int = 0  # data segments captured twice within a few ms (SPAN copying both ways)
    tcp_one_sided_flows: int = 0  # only one direction captured, although it shows the other one answered
    tcp_unanswered_syn_flows: int = 0  # bare SYNs with no reply (connection attempts, not a capture problem)
    tcp_no_handshake_flows: int = 0  # picked up mid-stream: no SYN seen
    dropped_packets: int = 0  # live capture: packets lost because analysis fell behind
    evicted_flows: int = 0
    ambiguous_flows: int = 0  # client/server roles unknown: plugins were offered both orientations
    orientation_resolved: int = 0  # ambiguous (flow, plugin) pairs settled by a finding
    tls_sessions: int = 0  # TLS connections seen while a key log was loaded
    tls_decrypted: int = 0
    tls_no_key: int = 0
    tls_unsupported: int = 0
    tls_failed: int = 0
    findings: int = 0
    duplicates: int = 0
    plugin_errors: Counter[str] = field(default_factory=Counter)
    # errors in a guessed orientation of an ambiguous flow (reported as plugin errors if unresolved)
    suppressed_orientation_errors: Counter[str] = field(default_factory=Counter)
    source_errors: list[str] = field(default_factory=list)
    by_protocol: Counter[str] = field(default_factory=Counter)
    by_kind: Counter[str] = field(default_factory=Counter)
    first_ts: float | None = None
    last_ts: float | None = None

    @property
    def total_plugin_errors(self) -> int:
        return sum(self.plugin_errors.values())

    #: Counters owned by the findings pipeline; a worker's values are not merged (the main
    #: process re-counts when it publishes the worker's findings).
    PIPELINE_FIELDS = frozenset({"findings", "duplicates", "by_protocol", "by_kind"})

    def snapshot(self) -> dict[str, Any]:
        """Plain JSON-able copy of every counter (raw timestamps); :meth:`from_snapshot` reverses it."""
        return {name: dict(v) if isinstance(v, Counter) else list(v) if isinstance(v, list) else v
                for name, v in vars(self).items()}  # fmt: skip

    @classmethod
    def from_snapshot(cls, data: dict[str, Any]) -> RunStats:
        """Rebuild stats from :meth:`snapshot` output; unknown keys are ignored, missing ones stay zero."""
        stats = cls()
        for name, default in vars(cls()).items():
            if name not in data or data[name] is None:
                continue
            value = data[name]
            if isinstance(default, Counter):
                setattr(stats, name, Counter({str(k): int(v) for k, v in dict(value).items()}))
            elif isinstance(default, list):
                setattr(stats, name, [str(v) for v in value])
            elif name in ("first_ts", "last_ts"):
                setattr(stats, name, float(value))
            else:
                setattr(stats, name, int(value))
        return stats

    def merge(self, other: RunStats) -> None:
        """Add another run's engine counters (e.g. from a worker process) into this one."""
        for name, value in vars(other).items():
            if name in self.PIPELINE_FIELDS:
                continue
            mine = getattr(self, name)
            if name == "first_ts":
                if value is not None and (mine is None or value < mine):
                    self.first_ts = value
            elif name == "last_ts":
                if value is not None and (mine is None or value > mine):
                    self.last_ts = value
            elif isinstance(mine, Counter):
                mine.update(value)
            elif isinstance(mine, list):
                mine.extend(value)
            elif isinstance(mine, int):
                setattr(self, name, mine + value)
