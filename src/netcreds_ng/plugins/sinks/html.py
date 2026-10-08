"""Self-contained HTML audit report written at the end of the run."""

from __future__ import annotations

import html
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from netcreds_ng import __version__
from netcreds_ng.model import Finding, Kind, RunStats
from netcreds_ng.output.masking import masked
from netcreds_ng.plugins.api import SinkContext, SinkPlugin
from netcreds_ng.plugins.sinks.files import iso

_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#6b6b66;--card:#fff;--line:#e4e3de;--high:#b42318;--medium:#b54708;
--low:#175cd3;--info:#475467}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--muted:#a3a29c;--card:#1d1d1b;--line:#33332f;
--high:#f97066;--medium:#fdb022;--low:#84adff;--info:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:32px 16px}h1{font-size:26px;margin:0 0 4px}
h2{font-size:18px;margin:32px 0 12px}.muted{color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:26px}table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13.5px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;background:color-mix(in srgb,var(--line) 40%,transparent)}
td.v{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
.r{font-weight:600;text-transform:uppercase;font-size:12px}.r.high{color:var(--high)}.r.medium{color:var(--medium)}
.r.low{color:var(--low)}.r.info{color:var(--info)}.tag{display:inline-block;border:1px solid var(--line);
border-radius:999px;padding:0 7px;margin:1px;font-size:12px;color:var(--muted)}.wrap{overflow-x:auto}
"""


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value))


class HtmlReportSink(SinkPlugin):
    name = "html"
    description = "Self-contained HTML audit report (secrets masked unless include_secrets)"

    def __init__(self, target: str | None = None, options: dict[str, Any] | None = None) -> None:
        super().__init__(target, options)
        self.findings: list[Finding] = []

    def open(self, ctx: SinkContext) -> None:
        if not self.target:
            raise ValueError("html output needs a file path")

    def write(self, finding: Finding) -> None:
        if finding.kind in (Kind.URL, Kind.SEARCH, Kind.POST) and not self.options.get("include_browsing"):
            return
        self.findings.append(finding if self.options.get("include_secrets") else masked(finding))

    def close(self, stats: RunStats) -> None:
        assert self.target is not None
        summary_fn = self.options.get("summary")
        summary: dict[str, Any] = summary_fn() if callable(summary_fn) else {}
        risk = Counter(f.risk for f in self.findings)
        protos = Counter(f.protocol for f in self.findings)
        rows = sorted(self.findings, key=lambda f: (_RISK_ORDER.get(f.risk, 9), f.timestamp))
        generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        span = ""
        if stats.first_ts and stats.last_ts:
            span = f"{iso(stats.first_ts)[:19]} to {iso(stats.last_ts)[:19]} UTC"
        out: list[str] = [
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width,initial-scale=1'>",
            f"<title>Credential Exposure Report</title><style>{CSS}</style></head><body><main>",
            "<h1>Credential exposure report</h1>",
            f"<div class='muted'>netcreds-ng {_e(__version__)} · generated {_e(generated)}"
            f"{' · traffic ' + _e(span) if span else ''}"
            f"{' · source ' + _e(self.options.get('source_label')) if self.options.get('source_label') else ''}</div>",
            "<div class='cards'>",
        ]
        for label, value in (
            ("High risk", risk.get("high", 0)),
            ("Medium risk", risk.get("medium", 0)),
            ("Findings", len(self.findings)),
            ("Weak passwords", summary.get("weak_passwords", 0)),
            ("Reused secrets", summary.get("reused_secrets", 0)),
            ("Frames analysed", stats.frames),
        ):
            out.append(f"<div class='card'><span class='muted'>{_e(label)}</span><b>{_e(value)}</b></div>")
        out.append("</div>")
        if protos:
            out.append("<h2>By protocol</h2><div class='wrap'><table><tr><th>Protocol</th><th>Findings</th></tr>")
            for p, n in protos.most_common():
                out.append(f"<tr><td>{_e(p)}</td><td>{n}</td></tr>")
            out.append("</table></div>")
        hosts = summary.get("hosts") or []
        if hosts:
            out.append("<h2>Host exposure</h2><div class='wrap'><table><tr><th>Host</th><th>Risk</th>"
                       "<th>As client</th><th>As server</th><th>Protocols</th><th>Accounts</th></tr>")  # fmt: skip
            for h in hosts[:200]:
                out.append(
                    f"<tr><td class='v'>{_e(h['ip'])}</td><td class='r {_e(h['max_risk'])}'>{_e(h['max_risk'])}</td>"
                    f"<td>{h['as_client']}</td><td>{h['as_server']}</td><td>{_e(', '.join(h['protocols']))}</td>"
                    f"<td>{_e(', '.join(h['accounts'][:10]))}</td></tr>"
                )
            out.append("</table></div>")
        out.append("<h2>Findings</h2><div class='wrap'><table><tr><th>Risk</th><th>Time (UTC)</th><th>Protocol</th>"
                   "<th>What</th><th>Source → destination</th><th>Detail</th><th>Tags</th><th>Frame</th></tr>")  # fmt: skip
        for f in rows:
            tags = "".join(f"<span class='tag'>{_e(t)}</span>" for t in f.tags)
            out.append(
                f"<tr><td class='r {_e(f.risk)}'>{_e(f.risk)}</td><td>{_e(iso(f.timestamp)[:19])}</td>"
                f"<td>{_e(f.protocol)}</td><td>{_e(f.kind.value.replace('_', ' '))}</td>"
                f"<td class='v'>{_e(f.src)} → {_e(f.dst)}</td><td class='v'>{_e(f.display)}</td>"
                f"<td>{tags}</td><td>{f.frame}</td></tr>"
            )
        out.append("</table></div>")
        if stats.total_plugin_errors or stats.source_errors:
            out.append("<h2>Analysis warnings</h2><ul>")
            for name, n in stats.plugin_errors.items():
                out.append(f"<li>{_e(name)}: {n} error(s)</li>")
            for err in stats.source_errors:
                out.append(f"<li>{_e(err)}</li>")
            out.append("</ul>")
        out.append("</main></body></html>")
        with open(self.target, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out))
