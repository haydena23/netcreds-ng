"""Wire formats for SIEM and chat integrations: ArcSight CEF, RFC 5424 syslog, chat text."""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from typing import Any

from netcreds_ng import __version__
from netcreds_ng.model import Finding

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
CEF_SEVERITY = {"info": 1, "low": 3, "medium": 6, "high": 9}
SYSLOG_SEVERITY = {"info": 6, "low": 5, "medium": 4, "high": 2}  # informational/notice/warning/critical
FACILITY_LOCAL0 = 16


def _cef_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(value: object) -> str:
    text = str(value)
    return (
        text.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")
    )


def cef_line(f: Finding) -> str:
    """One ArcSight CEF:0 event."""
    name = f"{f.protocol} {f.kind.value.replace('_', ' ')}"
    ext: list[tuple[str, object]] = [
        ("rt", int(f.timestamp * 1000)),
        ("src", f.src.ip),
        ("spt", f.src.port),
        ("dst", f.dst.ip),
        ("dpt", f.dst.port),
        ("app", f.protocol),
    ]
    if f.username:
        ext.append(("suser", f"{f.domain}\\{f.username}" if f.domain else f.username))
    ext += [
        ("msg", f.display[:1023]),
        ("cs1Label", "tags"),
        ("cs1", ",".join(f.tags)),
        ("cs2Label", "plugin"),
        ("cs2", f.plugin),
        ("cn1Label", "frame"),
        ("cn1", f.frame),
    ]
    header = "|".join(
        _cef_header(x)
        for x in ("CEF:0", "netcreds-ng", "netcreds-ng", __version__, f.kind.value, name, str(CEF_SEVERITY.get(f.risk, 1)))
    )
    return header + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext if v not in (None, ""))


def json_event(f: Finding) -> str:
    data = f.to_dict()
    data["timestamp"] = datetime.fromtimestamp(f.timestamp, tz=UTC).isoformat() if f.timestamp else ""
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def syslog_message(f: Finding, body: str, hostname: str | None = None) -> str:
    """RFC 5424 message (local0); the timestamp is when the traffic was seen."""
    pri = FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY.get(f.risk, 6)
    ts = datetime.fromtimestamp(f.timestamp, tz=UTC).isoformat(timespec="milliseconds") if f.timestamp else "-"
    host = (hostname or socket.gethostname() or "-").replace(" ", "_")[:255]
    return f"<{pri}>1 {ts} {host} netcreds-ng - {f.kind.value} - {body}"


def chat_line(f: Finding) -> str:
    route = f"{f.src} → {f.dst}"
    return f"[{f.risk.upper()}] {f.protocol} {f.kind.value.replace('_', ' ')} {route}: {f.display[:300]}"


def chat_payload(style: str, findings: list[dict[str, Any]], lines: list[str]) -> dict[str, Any]:
    """Body for a chat webhook. ``style`` is generic, slack, teams or discord."""
    if style == "generic":
        return {"source": "netcreds-ng", "findings": findings}
    title = f"netcreds-ng: {len(lines)} new finding{'s' if len(lines) != 1 else ''}"
    text = "\n".join(lines)
    if style == "slack":
        return {"text": f"*{title}*\n```{text[:3500]}```"}
    if style == "discord":
        return {"content": f"**{title}**\n```{text[:1800]}```"}
    if style == "teams":
        return {"text": f"**{title}**\n\n" + "\n\n".join(lines)[:20000]}
    raise ValueError(f"unknown webhook format {style!r} (generic, slack, teams, discord)")
