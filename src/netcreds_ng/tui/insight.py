"""Dashboard analytics over a list of findings: related findings, accounts, timeline, reasons.

Pure functions (no Textual), so they are unit-tested directly. :class:`Tally` rebuilds the
run summary (hosts, services, scores, alerts) from stored findings for ``--attach``, using
the same enricher code as a live session.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.explain import tag_info
from netcreds_ng.model import Finding, Kind
from netcreds_ng.plugins.enrichers.analytics import AnalyticsEnricher
from netcreds_ng.plugins.enrichers.detection import DetectionEnricher
from netcreds_ng.session import combine_summary

RISKS = ("info", "low", "medium", "high")
BROWSING = (Kind.URL, Kind.POST, Kind.SEARCH)
MAX_RELATED = 200


def account_of(f: Finding) -> str:
    user = f.username or ""
    return f"{f.domain}\\{user}" if f.domain and user else user


def _same_account(name: str) -> str:
    return name.rpartition("\\")[2].lower()


def _pair(f: Finding) -> frozenset[tuple[str, int]]:
    return frozenset({(f.src.ip, f.src.port), (f.dst.ip, f.dst.port)})


def _attempt_of(g: Finding, alert: Finding) -> bool:
    """Whether login result ``g`` is one of the attempts an alert counted.

    Frame numbers restart in every capture file, so the frame must also come from one of the
    alert's clients, on the alert's service, no later than the alert.
    """
    if g.kind is not Kind.AUTH_RESULT or g.frame not in (alert.extra.get("frames") or ()):
        return False
    clients = alert.extra.get("clients") or [alert.src.ip]
    return (g.dst == alert.dst and g.protocol == alert.protocol and g.src.ip in clients
            and g.timestamp <= alert.timestamp)  # fmt: skip


def related(findings: Sequence[Finding], idx: int) -> list[tuple[str, int]]:
    """Findings related to ``findings[idx]``, as ``(relation, index)`` pairs, strongest relation first.

    Relations: the alert's attempts (for an alert), alerts this finding contributed to, the
    same connection, the same secret (by fingerprint), and the same account elsewhere. Each
    finding is listed once, under its strongest relation; at most ``MAX_RELATED`` are returned.
    """
    f = findings[idx]
    seen = {idx}
    out: list[tuple[str, int]] = []

    def add(label: str, j: int) -> None:
        if j not in seen and len(out) < MAX_RELATED:
            seen.add(j)
            out.append((label, j))

    if f.kind is Kind.ALERT:
        for j, g in enumerate(findings):
            if _attempt_of(g, f):
                add("alert attempt", j)
    else:
        for j, g in enumerate(findings):
            if g.kind is Kind.ALERT and _attempt_of(f, g):
                add("alert", j)
        pair = _pair(f)
        for j, g in enumerate(findings):
            if g.kind is not Kind.ALERT and _pair(g) == pair:
                add("same connection", j)
    fp = f.extra.get("secret_fingerprint")
    if fp:
        for j, g in enumerate(findings):
            if g.extra.get("secret_fingerprint") == fp:
                add("same secret", j)
    account = _same_account(account_of(f))
    if account:
        for j, g in enumerate(findings):
            if g.kind is not Kind.ALERT and _same_account(account_of(g)) == account:
                add("same account", j)
    return out


@dataclass
class AccountRow:
    account: str
    services: set[str] = field(default_factory=set)
    clients: set[str] = field(default_factory=set)
    findings: int = 0
    max_risk: str = "info"
    secret_seen: bool = False
    cleartext: bool = False
    weak: bool = False
    reused: bool = False
    failures: int = 0
    successes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


def accounts(findings: Sequence[Finding]) -> list[AccountRow]:
    """One row per account (case-insensitive, domain kept for display), riskiest first."""
    rows: dict[str, AccountRow] = {}
    for f in findings:
        name = account_of(f)
        if not name or f.kind in BROWSING or f.kind is Kind.ALERT:
            continue
        row = rows.get(name.lower())
        if row is None:
            row = rows[name.lower()] = AccountRow(name, first_ts=f.timestamp, last_ts=f.timestamp)
        row.findings += 1
        row.services.add(f"{f.protocol}@{f.dst}")
        row.clients.add(f.src.ip)
        if f.timestamp:
            row.first_ts = min(row.first_ts or f.timestamp, f.timestamp)
            row.last_ts = max(row.last_ts, f.timestamp)
        if RISKS.index(f.risk) > RISKS.index(row.max_risk):
            row.max_risk = f.risk
        if f.kind.is_secret:
            row.secret_seen = True
            if "cleartext" in f.tags:
                row.cleartext = True
        row.weak |= "weak-password" in f.tags
        row.reused |= "password-reuse" in f.tags
        if f.outcome == "failure":
            row.failures += 1
        elif f.outcome == "success":
            row.successes += 1
    return sorted(rows.values(), key=lambda r: (-RISKS.index(r.max_risk), not r.cleartext, -r.findings,
                                                 r.account.lower()))  # fmt: skip


def reason_counts(findings: Sequence[Finding]) -> list[tuple[str, str, int]]:
    """``(tag, title, count)`` for every tag seen, most frequent first: the exposure reasons."""
    counts: Counter[str] = Counter(t for f in findings if f.kind not in BROWSING for t in f.tags)
    out = []
    for tag, n in counts.most_common():
        info = tag_info(tag)
        out.append((tag, info.title if info else tag, n))
    return out


@dataclass
class Timeline:
    start: float
    end: float
    buckets: dict[str, list[int]]  # risk -> counts per bucket

    @property
    def width(self) -> int:
        return len(next(iter(self.buckets.values()), []))


def timeline(findings: Sequence[Finding], width: int = 60) -> Timeline | None:
    """Findings per time bucket and risk, over capture time; None without timestamps."""
    times = [f.timestamp for f in findings if f.timestamp and f.kind not in BROWSING]
    if not times or width < 1:
        return None
    start, end = min(times), max(times)
    span = max(end - start, 1e-9)
    buckets = {r: [0] * width for r in RISKS}
    for f in findings:
        if not f.timestamp or f.kind in BROWSING:
            continue
        i = min(int((f.timestamp - start) / span * width), width - 1)
        buckets.get(f.risk, buckets["info"])[i] += 1
    return Timeline(start, end, buckets)


BLOCKS = " ▁▂▃▄▅▆▇█"


def spark(values: Sequence[int], peak: int | None = None) -> str:
    """One character per value, scaled to ``peak`` (default: the largest value); 0 is a space."""
    top = peak if peak is not None else max(values, default=0)
    if top <= 0:
        return " " * len(values)
    return "".join(BLOCKS[0] if v <= 0 else BLOCKS[max(1, round(v / top * (len(BLOCKS) - 1)))] for v in values)


def bar(value: int, peak: int, width: int = 24) -> str:
    if peak <= 0 or value <= 0:
        return ""
    return "█" * max(1, round(value / peak * width))


class Tally:
    """Rebuilds the run summary from stored findings (already enriched) for ``--attach``."""

    def __init__(self, detection_options: dict[str, Any] | None = None) -> None:
        self.analytics = AnalyticsEnricher()
        self.detection = DetectionEnricher(detection_options)

    def observe(self, finding: Finding) -> None:
        self.analytics.observe(finding)
        self.detection.observe(finding)

    def summary(self) -> dict[str, Any]:
        return combine_summary(self.analytics, self.detection)
