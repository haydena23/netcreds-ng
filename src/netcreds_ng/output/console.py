"""Rich console rendering of findings and run summaries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from netcreds_ng.model import Finding, Kind, RunStats
from netcreds_ng.output.masking import masked

RISK_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}
KIND_LABEL = {
    Kind.CREDENTIAL: "credential", Kind.USERNAME: "username", Kind.PASSWORD: "password",
    Kind.AUTH_EVENT: "auth", Kind.TOKEN: "token", Kind.API_KEY: "api key", Kind.COOKIE: "cookie",
    Kind.COMMUNITY: "community", Kind.AUTH_RESULT: "result", Kind.URL: "url", Kind.POST: "post",
    Kind.SEARCH: "search", Kind.INFO: "info", Kind.ALERT: "ALERT",
}  # fmt: skip
BROWSING = (Kind.URL, Kind.POST, Kind.SEARCH)


def _clip(value: str, limit: int | None) -> str:
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    if limit is not None and len(value) > limit:
        return value[: limit - 3] + "..."
    return value


class ConsoleRenderer:
    def __init__(
        self,
        console: Console | None = None,
        verbose: bool = False,
        mask: bool = False,
        browsing: bool = True,
        quiet: bool = False,
    ) -> None:
        self.console = console or Console(highlight=False)
        self.verbose = verbose
        self.mask = mask
        self.browsing = browsing
        self.quiet = quiet

    def finding(self, f: Finding) -> None:
        if self.quiet or (f.kind in BROWSING and not self.browsing):
            return
        if self.mask:
            f = masked(f)
        ts = datetime.fromtimestamp(f.timestamp).strftime("%H:%M:%S") if f.timestamp else "--:--:--"
        line = Text()
        line.append(f"{ts} ", style="dim")
        line.append(f"{f.risk.upper():<6} ", style=RISK_STYLE.get(f.risk, ""))
        line.append(f"{f.protocol:<9} ", style="bold")
        line.append(f"{KIND_LABEL.get(f.kind, f.kind.value):<10} ", style="magenta")
        if f.kind in BROWSING:
            line.append(f"{f.src.ip} ", style="dim")
        else:
            line.append(f"{f.src} > {f.dst} ", style="dim")
        line.append(_clip(f.display, None if self.verbose else 100))
        if f.tags:
            line.append("  " + " ".join(f"#{t}" for t in f.tags), style="dim cyan")
        self.console.print(line, soft_wrap=True)

    def summary(self, stats: RunStats, analytics: dict[str, Any] | None = None, errors: list[str] | None = None) -> None:
        if self.quiet:
            return
        c = self.console
        c.print()
        t = Table(title="Run summary", show_header=False, title_justify="left", box=None, padding=(0, 2))
        t.add_row("Frames", f"{stats.frames:,}", "Decoded", f"{stats.decoded:,}")
        t.add_row("TCP flows", f"{stats.tcp_flows:,}", "UDP flows", f"{stats.udp_flows:,}")
        t.add_row("Findings", f"{stats.findings:,}", "Duplicates suppressed", f"{stats.duplicates:,}")
        t.add_row("TCP gaps", f"{stats.tcp_gaps:,} ({stats.tcp_gap_bytes:,} B)", "Retransmitted", f"{stats.tcp_retransmitted_bytes:,} B")
        if stats.ip_fragments:
            lost = f" ({stats.ip_fragments_expired:,} incomplete dropped)" if stats.ip_fragments_expired else ""
            t.add_row("IP fragments", f"{stats.ip_fragments:,}", "Reassembled", f"{stats.ip_reassembled:,}{lost}")
        if stats.tls_sessions:
            t.add_row("TLS sessions", f"{stats.tls_sessions:,}", "Decrypted / no key",
                      f"{stats.tls_decrypted:,} / {stats.tls_no_key:,}"
                      + (f" ({stats.tls_unsupported + stats.tls_failed:,} other)"
                         if stats.tls_unsupported + stats.tls_failed else ""))  # fmt: skip
        if stats.ambiguous_flows:
            t.add_row("Ambiguous direction", f"{stats.ambiguous_flows:,} flows", "Resolved by findings",
                      f"{stats.orientation_resolved:,}")  # fmt: skip
        if stats.truncated_frames or stats.undecodable:
            t.add_row("Truncated frames", f"{stats.truncated_frames:,}", "Non-IP/undecodable", f"{stats.undecodable:,}")
        c.print(t)
        if stats.by_protocol:
            pt = Table(title="Findings by protocol", title_justify="left")
            pt.add_column("Protocol")
            pt.add_column("Findings", justify="right")
            for proto, n in stats.by_protocol.most_common():
                pt.add_row(proto, str(n))
            c.print(pt)
        if analytics:
            rc = analytics.get("risk_counts", {})
            c.print(
                Text.assemble(
                    ("Risk: ", "bold"),
                    (f"{rc.get('high', 0)} high", RISK_STYLE["high"]), "  ",
                    (f"{rc.get('medium', 0)} medium", RISK_STYLE["medium"]), "  ",
                    (f"{rc.get('low', 0)} low", RISK_STYLE["low"]), "   ",
                    (f"weak passwords: {analytics.get('weak_passwords', 0)}   ", ""),
                    (f"reused secrets: {analytics.get('reused_secrets', 0)}", ""),
                )
            )  # fmt: skip
            hosts = analytics.get("hosts") or []
            if hosts:
                ht = Table(title="Most exposed hosts", title_justify="left")
                for col in ("Host", "Risk", "As client", "As server", "Protocols", "Accounts"):
                    ht.add_column(col)
                for h in hosts[:10]:
                    ht.add_row(
                        h["ip"], Text(h["max_risk"], style=RISK_STYLE.get(h["max_risk"], "")), str(h["as_client"]),
                        str(h["as_server"]), ", ".join(h["protocols"]), _clip(", ".join(h["accounts"]), 60),
                    )  # fmt: skip
                c.print(ht)
            alerts = analytics.get("alerts") or []
            if alerts:
                at = Table(title="Alerts", title_justify="left")
                for col in ("Detection", "Protocol", "Source > destination", "Detail"):
                    at.add_column(col)
                for a in alerts[:20]:
                    at.add_row(Text(a["detection"], style=RISK_STYLE["high"]), a["protocol"],
                               f"{a['src']} > {a['dst']}", _clip(str(a["value"]), 80))  # fmt: skip
                c.print(at)
            clear = [s for s in analytics.get("services") or [] if s.get("cleartext")]
            if clear:
                st = Table(title="Services exposing cleartext secrets", title_justify="left")
                for col in ("Server", "Protocol", "Accounts", "Logins ok/failed"):
                    st.add_column(col)
                for s in clear[:15]:
                    st.add_row(s["server"], s["protocol"], _clip(", ".join(s["accounts"]), 50),
                               f"{s['successes']}/{s['failures']}")  # fmt: skip
                c.print(st)
        problems = list(stats.source_errors)
        for name, n in stats.plugin_errors.items():
            problems.append(f"{name}: {n} error(s)")
        if problems:
            c.print(Text("Warnings:", style="bold yellow"))
            for p in problems:
                c.print(f"  - {p}")
            for e in (errors or [])[:5]:
                c.print(Text(f"    {e}", style="dim"))
