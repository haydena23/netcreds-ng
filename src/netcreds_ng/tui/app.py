"""Interactive Textual dashboard for live capture and capture-file browsing."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Input, Static

from netcreds_ng.model import Finding, Kind
from netcreds_ng.output.console import BROWSING, KIND_LABEL, RISK_STYLE
from netcreds_ng.output.masking import masked
from netcreds_ng.plugins.sinks.files import iso
from netcreds_ng.session import Session, SessionConfig

RISKS = ("info", "low", "medium", "high")


class NetcredsApp(App[int]):
    TITLE = "netcreds-ng"
    CSS = """
    #status { height: 1; padding: 0 1; background: $boost; }
    #filter { display: none; }
    #filter.visible { display: block; }
    #body { height: 1fr; }
    #findings { width: 1fr; }
    #side { width: 44; display: none; border-left: solid $primary; padding: 0 1; }
    #side.visible { display: block; }
    #detail { height: 12; border-top: solid $primary; padding: 0 1; overflow-y: auto; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "pause", "Pause/Resume"),
        Binding("slash", "filter", "Filter"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
        Binding("r", "risk", "Min risk"),
        Binding("b", "browsing", "Browsing"),
        Binding("m", "mask", "Mask"),
        Binding("a", "analytics", "Analytics"),
        Binding("e", "export", "Export JSONL"),
        Binding("h", "report", "HTML report"),
    ]

    def __init__(
        self,
        registry: Any,
        config: SessionConfig,
        files: list[str] | None = None,
        interface: str | None = None,
        bpf: str | None = None,
        verbose: bool = False,
        mask: bool = False,
    ) -> None:
        super().__init__()
        self.registry = registry
        self.config = config
        self.files = files or []
        self.interface = interface
        self.bpf = bpf
        self.verbose = verbose
        self.mask = mask
        self.findings: list[Finding] = []
        self.filter_text = ""
        self.min_risk = 0
        self.show_browsing = True
        self.paused = threading.Event()
        self.stopping = threading.Event()
        self.state = "starting"
        self.capture: Any = None
        self.session: Session | None = None
        self._lock = threading.Lock()

    # layout ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="status")
        yield Input(placeholder="filter: text matches protocol, host, user, value, tags (Esc to clear)", id="filter")
        with Horizontal(id="body"):
            with Vertical(id="findings"):
                yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
                yield Static("Select a finding to see details.", id="detail")
            yield Static("", id="side")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_columns("Time", "Risk", "Protocol", "What", "Source → Destination", "Detail", "Tags")
        source = self.interface or ", ".join(self.files)
        self.sub_title = f"{'live: ' if self.interface else ''}{source}"
        self.session = Session(self.registry, self.config, listeners=[self._on_finding])
        self.session.open()
        self.run_worker(self._analyse, thread=True, exclusive=True, name="analysis")
        self.set_interval(0.5, self._refresh_status)
        self.query_one("#filter", Input).disabled = True  # hidden filter box must not swallow key bindings
        table.focus()

    # analysis worker ---------------------------------------------------------

    def _analyse(self) -> None:
        assert self.session is not None
        self.state = "running"
        try:
            if self.interface:
                from netcreds_ng.engine.sources import LiveCapture

                self.capture = LiveCapture(self.interface, self.bpf)
                self.capture.start()
                for frame in self.capture.frames():
                    while self.paused.is_set() and not self.stopping.is_set():
                        time.sleep(0.1)
                    if self.stopping.is_set():
                        break
                    self.session.engine.process_frame(frame)
            else:
                for path in self.files:
                    if self.stopping.is_set():
                        break
                    self.session.run_file(path, stop=self._should_stop)
        except Exception as exc:  # noqa: BLE001 - shown in the UI
            self.session.stats.source_errors.append(f"capture error: {exc}")
        finally:
            if self.capture is not None:
                self.capture.stop()
            self.session.close()
            self.state = "stopped" if self.stopping.is_set() else "done"
            self.call_from_thread(self._refresh_status)
            self.call_from_thread(self._refresh_side)

    def _should_stop(self) -> bool:
        while self.paused.is_set() and not self.stopping.is_set():
            time.sleep(0.1)
        return self.stopping.is_set()

    def _on_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
        self.call_from_thread(self._add_row, finding, len(self.findings) - 1)

    # rendering ---------------------------------------------------------------

    def _visible(self, f: Finding) -> bool:
        if RISKS.index(f.risk) < self.min_risk:
            return False
        if not self.show_browsing and f.kind in BROWSING:
            return False
        if self.filter_text:
            hay = " ".join(
                str(x) for x in (f.protocol, f.kind.value, f.src, f.dst, f.username, f.domain, f.display, *f.tags) if x
            ).lower()
            return all(term in hay for term in self.filter_text.lower().split())
        return True

    def _cells(self, f: Finding) -> tuple[Any, ...]:
        shown = masked(f) if self.mask else f
        detail = shown.display.replace("\n", "\\n").replace("\r", "\\r")
        if not self.verbose and len(detail) > 80:
            detail = detail[:77] + "..."
        ts = datetime.fromtimestamp(f.timestamp).strftime("%H:%M:%S") if f.timestamp else ""
        route = f"{f.src.ip}" if f.kind in BROWSING else f"{f.src} → {f.dst}"
        return (
            ts, Text(f.risk.upper(), style=RISK_STYLE.get(f.risk, "")), f.protocol,
            KIND_LABEL.get(f.kind, f.kind.value), route, detail, " ".join(f.tags),
        )  # fmt: skip

    def _add_row(self, f: Finding, idx: int) -> None:
        if self._visible(f):
            self.query_one("#table", DataTable).add_row(*self._cells(f), key=str(idx))

    def _rebuild(self) -> None:
        table = self.query_one("#table", DataTable)
        table.clear()
        with self._lock:
            items = list(enumerate(self.findings))
        for idx, f in items:
            if self._visible(f):
                table.add_row(*self._cells(f), key=str(idx))

    def _refresh_status(self) -> None:
        if self.session is None:
            return
        st = self.session.stats
        high = sum(1 for f in self.findings if f.risk == "high")
        state = "PAUSED" if self.paused.is_set() else self.state.upper()
        extra = ""
        if self.capture is not None and self.capture.dropped:
            extra = f"  dropped {self.capture.dropped:,}"
        warn = st.total_plugin_errors + len(st.source_errors)
        self.query_one("#status", Static).update(
            Text.assemble(
                (f" {state} ", "reverse bold"),
                f"  frames {st.frames:,}  flows {st.tcp_flows + st.udp_flows:,}  findings {st.findings:,}  ",
                (f"high {high}", RISK_STYLE["high"]),
                f"  dup {st.duplicates:,}  min-risk {RISKS[self.min_risk]}"
                f"{'  masked' if self.mask else ''}{'' if self.show_browsing else '  no-browsing'}",
                (f"  warnings {warn}" if warn else "", "yellow"),
                extra,
            )
        )
        if self.query_one("#side", Static).has_class("visible"):
            self._refresh_side()

    def _refresh_side(self) -> None:
        if self.session is None:
            return
        summary = self.session.summary()
        rc = summary.get("risk_counts", {})
        lines = Text()
        lines.append("Exposure analytics\n\n", style="bold")
        for r in ("high", "medium", "low", "info"):
            lines.append(f"{r:<7}", style=RISK_STYLE[r])
            lines.append(f"{rc.get(r, 0):>6}\n")
        lines.append(f"\nweak passwords {summary.get('weak_passwords', 0)}\n")
        lines.append(f"reused secrets {summary.get('reused_secrets', 0)}\n\n")
        lines.append("Most exposed hosts\n", style="bold")
        for h in (summary.get("hosts") or [])[:15]:
            lines.append(f"{h['ip']:<22}", style=RISK_STYLE.get(h["max_risk"], ""))
            lines.append(f" {', '.join(h['protocols'])[:18]}\n")
        st = self.session.stats
        if st.plugin_errors or st.source_errors:
            lines.append("\nWarnings\n", style="bold yellow")
            for name, n in st.plugin_errors.items():
                lines.append(f"{name}: {n}\n")
            for e in st.source_errors[:5]:
                lines.append(f"{e[:40]}\n")
        self.query_one("#side", Static).update(lines)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        f = self.findings[int(event.row_key.value)]
        shown = masked(f) if self.mask else f
        data = shown.to_dict()
        data["timestamp"] = iso(f.timestamp)
        body = Text()
        for key in ("timestamp", "protocol", "kind", "risk", "src", "dst", "username", "domain", "secret", "value",
                    "tags", "frame", "plugin", "confidence"):  # fmt: skip
            if key in data:
                body.append(f"{key:>11}: ", style="bold")
                body.append(f"{data[key]}\n")
        if data.get("extra"):
            body.append("      extra: ", style="bold")
            body.append(json.dumps(data["extra"], default=str) + "\n")
        self.query_one("#detail", Static).update(body)

    # actions -----------------------------------------------------------------

    def action_pause(self) -> None:
        if self.paused.is_set():
            self.paused.clear()
        else:
            self.paused.set()
        self._refresh_status()

    def action_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.disabled = False
        box.add_class("visible")
        box.focus()

    def action_clear_filter(self) -> None:
        box = self.query_one("#filter", Input)
        box.value = ""
        box.remove_class("visible")
        box.disabled = True
        self.filter_text = ""
        self._rebuild()
        self.query_one("#table", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self.filter_text = event.value
        self._rebuild()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.query_one("#table", DataTable).focus()

    def action_risk(self) -> None:
        self.min_risk = (self.min_risk + 1) % len(RISKS)
        self._rebuild()
        self._refresh_status()

    def action_browsing(self) -> None:
        self.show_browsing = not self.show_browsing
        self._rebuild()
        self._refresh_status()

    def action_mask(self) -> None:
        self.mask = not self.mask
        self._rebuild()
        self._refresh_status()

    def action_analytics(self) -> None:
        side = self.query_one("#side", Static)
        side.toggle_class("visible")
        self._refresh_side()

    def _stamp(self) -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    def action_export(self) -> None:
        path = f"netcreds-export-{self._stamp()}.jsonl"
        with self._lock:
            items = [f for f in self.findings if self._visible(f)]
        with open(path, "w", encoding="utf-8") as fh:
            for f in items:
                data = (masked(f) if self.mask else f).to_dict()
                data["timestamp"] = iso(f.timestamp)
                fh.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n")
        self.notify(f"Exported {len(items)} findings to {path}")

    def action_report(self) -> None:
        from netcreds_ng.plugins.sinks.html import HtmlReportSink

        if self.session is None:
            return
        path = f"netcreds-report-{self._stamp()}.html"
        sink = HtmlReportSink(path, {"summary": self.session.summary, "include_secrets": not self.mask,
                                     "source_label": self.sub_title})  # fmt: skip
        with self._lock:
            items = list(self.findings)
        for f in items:
            sink.write(f)
        sink.close(self.session.stats)
        self.notify(f"Report written to {path}")

    async def action_quit(self) -> None:
        self.stopping.set()
        self.paused.clear()
        if self.capture is not None:
            self.capture.stop()
        self.exit(0)


def run_tui(
    registry: Any,
    config: SessionConfig,
    files: list[str] | None = None,
    interface: str | None = None,
    bpf: str | None = None,
    verbose: bool = False,
    mask: bool = False,
) -> int:
    app = NetcredsApp(registry, config, files=files, interface=interface, bpf=bpf, verbose=verbose, mask=mask)
    result = app.run()
    return int(result or 0)


__all__ = ["Kind", "NetcredsApp", "run_tui"]
