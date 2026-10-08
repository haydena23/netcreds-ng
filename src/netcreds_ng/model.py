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
    tcp_gaps: int = 0
    tcp_gap_bytes: int = 0
    tcp_retransmitted_bytes: int = 0
    evicted_flows: int = 0
    findings: int = 0
    duplicates: int = 0
    plugin_errors: Counter[str] = field(default_factory=Counter)
    source_errors: list[str] = field(default_factory=list)
    by_protocol: Counter[str] = field(default_factory=Counter)
    by_kind: Counter[str] = field(default_factory=Counter)
    first_ts: float | None = None
    last_ts: float | None = None

    @property
    def total_plugin_errors(self) -> int:
        return sum(self.plugin_errors.values())
