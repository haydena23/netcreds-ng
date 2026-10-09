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
:root{--series-1:#2a78d6}@media (prefers-color-scheme:dark){:root{--series-1:#3987e5}}
.summary{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-top:20px}
.summary p{margin:0 0 6px}.summary p:last-child{margin:0}
figure{margin:0;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
figure svg{display:block;width:100%;height:auto}figure .bar{fill:var(--series-1)}figure .bar:hover{opacity:.75}
figure .axis{stroke:var(--line)}figure text{fill:var(--muted);font-size:11px}
figcaption{color:var(--muted);font-size:12.5px;margin-top:6px}
.yes{color:var(--high);font-weight:600}
@media print{body{background:#fff;color:#000}main{max-width:none;padding:0}.wrap{overflow:visible}
table,figure,.card,.summary{break-inside:avoid}}
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
            ("Alerts", len(summary.get("alerts") or [])),
            ("Cleartext services", sum(1 for x in summary.get("services") or [] if x.get("cleartext"))),
            ("Weak passwords", summary.get("weak_passwords", 0)),
            ("Reused secrets", summary.get("reused_secrets", 0)),
            ("Frames analysed", stats.frames),
        ):
            out.append(f"<div class='card'><span class='muted'>{_e(label)}</span><b>{_e(value)}</b></div>")
        out.append("</div>")
        out.extend(_executive_summary(self.findings, summary, stats))
        out.extend(_timeline(self.findings))
        alerts = summary.get("alerts") or []
        if alerts:
            out.append("<h2>Alerts</h2><div class='wrap'><table><tr><th>Detection</th><th>Protocol</th>"
                       "<th>Source → destination</th><th>Detail</th><th>Attempts</th><th>Frame</th></tr>")  # fmt: skip
            for a in alerts:
                out.append(
                    f"<tr><td class='r high'>{_e(a['detection'])}</td><td>{_e(a['protocol'])}</td>"
                    f"<td class='v'>{_e(a['src'])} → {_e(a['dst'])}</td><td>{_e(a['value'])}</td>"
                    f"<td>{_e(a['attempts'])}</td><td>{_e(a['frame'])}</td></tr>"
                )
            out.append("</table></div>")
        services = summary.get("services") or []
        if services:
            out.append("<h2>Service inventory</h2><div class='wrap'><table><tr><th>Server</th><th>Protocol</th>"
                       "<th>Cleartext secrets</th><th>Findings</th><th>Clients</th><th>Logins ok / failed</th>"
                       "<th>Accounts</th></tr>")  # fmt: skip
            for x in services[:300]:
                clear = "<span class='yes'>yes</span>" if x["cleartext"] else "no"
                out.append(
                    f"<tr><td class='v'>{_e(x['server'])}</td><td>{_e(x['protocol'])}</td><td>{clear}</td>"
                    f"<td>{_e(x['findings'])}</td><td>{_e(x['clients'])}</td>"
                    f"<td>{_e(x['successes'])} / {_e(x['failures'])}</td>"
                    f"<td>{_e(', '.join(x['accounts'][:10]))}</td></tr>"
                )
            out.append("</table></div>")
        shared = summary.get("shared_accounts") or []
        if shared:
            out.append("<h2>Accounts seen on several services</h2><div class='wrap'><table><tr><th>Account</th>"
                       "<th>Services</th></tr>")  # fmt: skip
            for x in shared[:200]:
                out.append(f"<tr><td class='v'>{_e(x['account'])}</td>"
                           f"<td class='v'>{_e(', '.join(x['services']))}</td></tr>")  # fmt: skip
            out.append("</table></div>")
        if protos:
            out.append("<h2>By protocol</h2><div class='wrap'><table><tr><th>Protocol</th><th>Findings</th></tr>")
            for p, n in protos.most_common():
                out.append(f"<tr><td>{_e(p)}</td><td>{n}</td></tr>")
            out.append("</table></div>")
        hosts = summary.get("hosts") or []
        if hosts:
            out.append("<h2>Host exposure</h2><div class='wrap'><table><tr><th>Host</th><th>Risk</th><th>Score</th>"
                       "<th>As client</th><th>As server</th><th>Protocols</th><th>Accounts</th></tr>")  # fmt: skip
            for h in sorted(hosts, key=lambda h: -int(h.get("score", 0)))[:200]:
                out.append(
                    f"<tr><td class='v'>{_e(h['ip'])}</td><td class='r {_e(h['max_risk'])}'>{_e(h['max_risk'])}</td>"
                    f"<td>{_e(h.get('score', ''))}</td>"
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


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _executive_summary(findings: list[Finding], summary: dict[str, Any], stats: RunStats) -> list[str]:
    """A few plain sentences for a non-technical reader; every number comes from the tables below."""
    secrets = [f for f in findings if f.kind.is_secret]
    cleartext = [f for f in secrets if "tls-decrypted" not in f.tags
                 and ("cleartext" in f.tags or f.kind in (Kind.CREDENTIAL, Kind.PASSWORD))]  # fmt: skip
    accounts = {(f.domain or "", f.username) for f in findings if f.username}
    services = [x for x in summary.get("services") or [] if x.get("cleartext")]
    alerts = summary.get("alerts") or []
    hosts = summary.get("hosts") or []
    weak = int(summary.get("weak_passwords", 0))
    lines: list[str] = []
    if not findings:
        lines.append("No credentials or authentication exposure were found in the analysed traffic.")
    else:
        where = f" on {_plural(len(services), 'service')}" if services else ""
        lines.append(
            f"The traffic exposed {_plural(len(cleartext), 'secret')} in cleartext{where}, "
            f"involving {_plural(len(accounts), 'account')} and {_plural(len(hosts), 'host')}."
        )
        protos = sorted({x["protocol"] for x in services})
        if protos:
            lines.append(f"Cleartext authentication was seen over {', '.join(protos)}; move these to encrypted"
                         " alternatives or disable them.")  # fmt: skip
        if weak:
            lines.append(f"{_plural(weak, 'password')} matched the weak-password list or had fewer than 6 characters.")
        if summary.get("reused_secrets"):
            lines.append(f"{_plural(int(summary['reused_secrets']), 'secret')} reused across accounts or services.")
    if alerts:
        kinds = sorted({a["detection"].replace("-", " ") for a in alerts})
        lines.append(f"{_plural(len(alerts), 'behavioural alert')} raised: {', '.join(kinds)}.")
    if stats.tcp_gaps or stats.total_plugin_errors or stats.source_errors:
        lines.append("Some traffic could not be fully analysed (capture gaps or warnings), so exposure may be"
                     " under-reported.")  # fmt: skip
    return ["<div class='summary'>", *(f"<p>{_e(x)}</p>" for x in lines), "</div>"]


_STEPS = (1, 5, 10, 30, 60, 300, 900, 3600, 6 * 3600, 86400, 7 * 86400)


def _unit(step: int) -> str:
    if step >= 86400:
        return f"{step // 86400} d"
    if step >= 3600:
        return f"{step // 3600} h"
    if step >= 60:
        return f"{step // 60} min"
    return f"{step} s"


def _timeline(findings: list[Finding], max_bars: int = 48) -> list[str]:
    """Findings per time bucket as an inline SVG column chart (hover a column for its count)."""
    times = sorted(f.timestamp for f in findings if f.timestamp and f.kind not in (Kind.URL, Kind.SEARCH, Kind.POST))
    if len(times) < 2 or times[-1] - times[0] < 1:
        return []
    span = times[-1] - times[0]
    step = next((s for s in _STEPS if span / s <= max_bars), _STEPS[-1])
    start = times[0] - times[0] % step
    counts = Counter(int((t - start) // step) for t in times)
    n = max(counts) + 1
    peak = max(counts.values())
    width, height, top, bottom, left = 720, 160, 12, 22, 34
    base = height - bottom
    plot_h = base - top
    slot = (width - left) / n
    bar_w = min(24.0, max(2.0, slot - 2))  # 2px surface gap between adjacent columns
    parts = [f"<svg viewBox='0 0 {width} {height}' role='img' "
             f"aria-label='Findings over time in {n} buckets of {_unit(step)}'>",
             f"<line class='axis' x1='{left}' y1='{base}' x2='{width}' y2='{base}'/>",
             f"<text x='{left - 6}' y='{top + 4}' text-anchor='end'>{peak}</text>",
             f"<text x='{left - 6}' y='{base}' text-anchor='end'>0</text>"]  # fmt: skip
    for i in range(n):
        c = counts.get(i, 0)
        if not c:
            continue
        h = max(2.0, plot_h * c / peak)
        x = left + i * slot + (slot - bar_w) / 2
        y = base - h
        r = min(4.0, bar_w / 2, h)
        label = f"{iso(start + i * step)[:19]} UTC: {_plural(c, 'finding')}"
        # rounded data end, square at the baseline
        path = (f"M{x:.1f},{base} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
                f"H{x + bar_w - r:.1f} Q{x + bar_w:.1f},{y:.1f} {x + bar_w:.1f},{y + r:.1f} V{base} Z")  # fmt: skip
        parts.append(f"<path class='bar' d='{path}'><title>{_e(label)}</title></path>")
    parts.append(f"<text x='{left}' y='{height - 6}' text-anchor='start'>{_e(iso(start)[11:19])}</text>")
    parts.append(f"<text x='{width}' y='{height - 6}' text-anchor='end'>{_e(iso(start + n * step)[11:19])}</text>")
    parts.append("</svg>")
    return ["<h2>Activity over time</h2><figure>", "".join(parts),
            f"<figcaption>Findings per {_unit(step)} (UTC), browsing excluded. Hover a column for its count; every"
            " finding is listed in the table below.</figcaption></figure>"]  # fmt: skip
