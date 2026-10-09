"""Capture health: how much of the traffic the capture really saw.

The engine counts the raw signals (:class:`~netcreds_ng.model.RunStats`); this module turns
them into rates, a list of issues and a plain-language verdict. Every rate is computed only
when its denominator is large enough to mean something (``MIN_FLOWS``, ``MIN_SEGMENTS``,
``MIN_FRAMES``), so a tiny capture is never called broken because of one odd flow.

Signals:

- **one-sided TCP flows**: only one direction was captured, although that direction shows
  the other one answered (it sends ACKs or data). Typical of asymmetric routing, or a SPAN
  port or tap that sees one direction only. Bare SYNs with no reply are connection attempts,
  not a capture problem, and are left out of the denominator.
- **gap rate**: TCP stream bytes the capture never saw, as a share of all stream bytes.
- **duplicate rate**: data segments captured twice within a few milliseconds (a SPAN port
  copying both ingress and egress, or merged taps). Findings are unaffected.
- **truncation**: frames cut by the snapshot length.
- **no handshake**: flows picked up mid-stream. Normal for short captures, so informational.
- **dropped packets**: live capture only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from netcreds_ng.model import RunStats

MIN_FLOWS = 20
MIN_SEGMENTS = 100
MIN_FRAMES = 100

# (warning, poor) thresholds
ONE_SIDED = (0.10, 0.30)
GAP_BYTES = (0.01, 0.05)
DUPLICATES = 0.05  # reported as information only: duplicates never lose data
TRUNCATED = (0.01, 0.10)
NO_HANDSHAKE_INFO = 0.50
SMALL_ONE_SIDED = 0.50  # below MIN_FLOWS, warn only when at least this share of flows is one-sided

SEVERITY_ORDER = ("info", "warning", "poor")


@dataclass(frozen=True)
class Issue:
    code: str
    severity: str  # info / warning / poor
    rate: float
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "rate": round(self.rate, 4), "message": self.message}


def _pct(rate: float) -> str:
    if 0 < rate < 0.01:
        return "<1%"
    return f"{rate * 100:.0f}%"


def _grade(rate: float, thresholds: tuple[float, float]) -> str | None:
    warn, poor = thresholds
    if rate >= poor:
        return "poor"
    if rate >= warn:
        return "warning"
    return None


def assess(stats: RunStats) -> dict[str, Any]:
    """Capture-health metrics, issues (worst first) and a one-line verdict for ``stats``."""
    issues: list[Issue] = []
    answered = stats.tcp_flows - stats.tcp_unanswered_syn_flows
    one_sided_rate = stats.tcp_one_sided_flows / answered if answered > 0 else 0.0
    stream_bytes = stats.tcp_payload_bytes + stats.tcp_gap_bytes
    gap_rate = stats.tcp_gap_bytes / stream_bytes if stream_bytes else 0.0
    dup_rate = stats.tcp_duplicate_segments / stats.tcp_data_segments if stats.tcp_data_segments else 0.0
    trunc_rate = stats.truncated_frames / stats.frames if stats.frames else 0.0
    nohs_rate = stats.tcp_no_handshake_flows / stats.tcp_flows if stats.tcp_flows else 0.0

    sev = _grade(one_sided_rate, ONE_SIDED) if answered >= MIN_FLOWS else None
    if answered < MIN_FLOWS and stats.tcp_one_sided_flows and one_sided_rate >= SMALL_ONE_SIDED:
        sev = "warning"  # few flows, but most of them one-sided: still worth saying
    if sev:
        issues.append(Issue("one-sided", sev, one_sided_rate,
            f"the capture misses the return path for {_pct(one_sided_rate)} of TCP flows "
            f"({stats.tcp_one_sided_flows:,} of {answered:,}): asymmetric routing, or a SPAN port or tap that "
            "sees only one direction. Logins may be seen without their result."))  # fmt: skip
    if stats.tcp_gap_bytes:
        if stats.tcp_data_segments >= MIN_SEGMENTS:
            sev = _grade(gap_rate, GAP_BYTES) or "info"
        else:  # little evidence: only a large share of missing bytes is more than a note
            sev = "warning" if gap_rate >= GAP_BYTES[1] else "info"
        issues.append(Issue("gaps", sev, gap_rate,
            f"{_pct(gap_rate)} of TCP stream bytes are missing from the capture ({stats.tcp_gap_bytes:,} B in "
            f"{stats.tcp_gaps:,} gaps): packets were dropped (an overloaded SPAN port or capture host) or never "
            "reached the capture point. Credentials inside the gaps are lost."))  # fmt: skip
    if stats.tcp_data_segments >= MIN_SEGMENTS and dup_rate >= DUPLICATES:
        # Informational: duplicates are recognised and never hide or distort findings.
        issues.append(Issue("duplicates", "info", dup_rate,
            f"{_pct(dup_rate)} of TCP data segments were captured twice: the SPAN port copies both ingress and "
            "egress, or several taps are merged. Findings are unaffected, but the capture is larger than needed."))
    if stats.frames >= MIN_FRAMES and (sev := _grade(trunc_rate, TRUNCATED)):
        issues.append(Issue("truncated", sev, trunc_rate,
            f"{_pct(trunc_rate)} of frames were cut short by the capture's snapshot length, so their payload is "
            "partly lost. Capture with a full snapshot length (tcpdump -s 0)."))  # fmt: skip
    if stats.dropped_packets:
        drop_rate = stats.dropped_packets / (stats.frames + stats.dropped_packets)
        issues.append(Issue("dropped", "poor" if drop_rate >= GAP_BYTES[1] else "warning", drop_rate,
            f"{stats.dropped_packets:,} packets ({_pct(drop_rate)}) were dropped during live capture because "
            "analysis fell behind. Capture to a file and analyse it with -p instead."))  # fmt: skip
    if stats.tcp_flows >= MIN_FLOWS and nohs_rate >= NO_HANDSHAKE_INFO:
        issues.append(Issue("no-handshake", "info", nohs_rate,
            f"{_pct(nohs_rate)} of TCP flows started before the capture did (no handshake seen). This is normal "
            "for short captures; logins made before the capture started are not visible."))  # fmt: skip

    issues.sort(key=lambda i: (-SEVERITY_ORDER.index(i.severity), -i.rate))
    worst = issues[0].severity if issues else "info"
    status = {"poor": "poor", "warning": "degraded"}.get(worst, "good")
    if status == "good" and issues:
        verdict = f"good, with notes: {issues[0].message}"
    elif status == "good":
        verdict = "good: no capture problems detected"
        if stats.tcp_flows < MIN_FLOWS and stats.frames < MIN_FRAMES:
            verdict = "good: no capture problems detected (small capture, little evidence either way)"
    else:
        verdict = f"{status}: {issues[0].message}"
    return {
        "status": status,
        "verdict": verdict,
        "issues": [i.to_dict() for i in issues],
        "metrics": {
            "tcp_flows": stats.tcp_flows,
            "tcp_one_sided_flows": stats.tcp_one_sided_flows,
            "tcp_unanswered_syn_flows": stats.tcp_unanswered_syn_flows,
            "one_sided_rate": round(one_sided_rate, 4),
            "tcp_no_handshake_flows": stats.tcp_no_handshake_flows,
            "no_handshake_rate": round(nohs_rate, 4),
            "tcp_payload_bytes": stats.tcp_payload_bytes,
            "tcp_gap_bytes": stats.tcp_gap_bytes,
            "gap_byte_rate": round(gap_rate, 4),
            "tcp_data_segments": stats.tcp_data_segments,
            "tcp_duplicate_segments": stats.tcp_duplicate_segments,
            "duplicate_rate": round(dup_rate, 4),
            "frames": stats.frames,
            "truncated_frames": stats.truncated_frames,
            "truncated_rate": round(trunc_rate, 4),
            "dropped_packets": stats.dropped_packets,
        },
    }
