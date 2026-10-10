"""Live findings table (``--tui``): what the console prints, as a table you can pause and filter."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header, Input, Static

from netcreds_ng.model import Finding
from netcreds_ng.output.console import BROWSING, KIND_LABEL, RISK_STYLE
from netcreds_ng.plugins.sinks.files import iso
from netcreds_ng.session import Session, SessionConfig
from netcreds_ng.tui.filters import FilterError, Predicate, parse_filter


class NetcredsApp(App[int]):
    TITLE = "netcreds-ng"
    CSS = """
    #status { height: 1; padding: 0 1; background: $boost; }
    #filter { display: none; }
    #filter.visible { display: block; }
    #table { height: 1fr; }
    #detail { height: 10; border-top: solid $primary; padding: 0 1; overflow-y: auto; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "pause", "Pause/Resume"),
        Binding("slash", "filter", "Filter"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
    ]

    def __init__(
        self,
        registry: Any,
        config: SessionConfig,
        files: list[str] | None = None,
        interface: str | None = None,
        bpf: str | None = None,
        verbose: bool = False,
    ) -> None:
        super().__init__()
        self.registry = registry
        self.config = config
        self.files = files or []
        self.interface = interface
        self.bpf = bpf
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.predicate: Predicate | None = None
        self.paused = threading.Event()
        self.stopping = threading.Event()
        self.state = "starting"
        self.capture: Any = None
        self.session: Session | None = None
        self._lock = threading.Lock()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="status")
        yield Input(placeholder="filter: text, or field:value (proto:ftp risk:high+ host:10.0.0.5); Esc clears",
                    id="filter")  # fmt: skip
        yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
        yield Static("Select a finding to see all of its fields.", id="detail")
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
        self.query_one("#filter", Input).disabled = True  # the hidden filter box must not swallow key bindings
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

    def _should_stop(self) -> bool:
        while self.paused.is_set() and not self.stopping.is_set():
            time.sleep(0.1)
        return self.stopping.is_set()

    def _on_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
            idx = len(self.findings) - 1
        self.call_from_thread(self._add_row, finding, idx)

    # rendering ---------------------------------------------------------------

    def _visible(self, f: Finding) -> bool:
        return self.predicate is None or self.predicate(f)

    def _cells(self, f: Finding) -> tuple[Any, ...]:
        detail = f.display.replace("\n", "\\n").replace("\r", "\\r")
        if not self.verbose and len(detail) > 80:
            detail = detail[:77] + "..."
        ts = datetime.fromtimestamp(f.timestamp).strftime("%H:%M:%S") if f.timestamp else ""
        route = f"{f.src.ip}" if f.kind in BROWSING else f"{f.src} → {f.dst}"
        return (
            ts, Text(f.risk.upper(), style=RISK_STYLE.get(f.risk, "")), f.protocol,
            KIND_LABEL.get(f.kind, f.kind.value), route, detail, " ".join(f.tags),
        )  # fmt: skip

    def _add_row(self, f: Finding, idx: int) -> None:
        if not self._visible(f):
            return
        table = self.query_one("#table", DataTable)
        at_end = table.row_count == 0 or table.cursor_row >= table.row_count - 1
        table.add_row(*self._cells(f), key=str(idx))
        if at_end:  # keep following new findings unless the user moved up to read
            table.move_cursor(row=table.row_count - 1, animate=False)

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
        state = "PAUSED" if self.paused.is_set() else self.state.upper()
        high = sum(1 for f in self.findings if f.risk == "high")
        dropped = f"  dropped {self.capture.dropped:,}" if self.capture is not None and self.capture.dropped else ""
        warn = st.total_plugin_errors + len(st.source_errors)
        self.query_one("#status", Static).update(
            Text.assemble(
                (f" {state} ", "reverse bold"),
                f"  frames {st.frames:,}  flows {st.tcp_flows + st.udp_flows:,}  findings {st.findings:,}  ",
                (f"high {high}", RISK_STYLE["high"]),
                f"  plugins {len(self.session.protocols)}",
                (f"  warnings {warn}" if warn else "", "yellow"),
                dropped,
            )
        )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        f = self.findings[int(event.row_key.value)]
        data = f.to_dict()
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
        self._set_filter("")
        self.query_one("#table", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self._set_filter(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.query_one("#table", DataTable).focus()

    def _set_filter(self, text: str) -> None:
        box = self.query_one("#filter", Input)
        try:
            self.predicate = parse_filter(text) if text.strip() else None
        except FilterError as exc:
            box.border_subtitle = str(exc)
            return
        box.border_subtitle = ""
        self._rebuild()

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
) -> int:
    app = NetcredsApp(registry, config, files=files, interface=interface, bpf=bpf, verbose=verbose)
    result = app.run()
    return int(result or 0)


__all__ = ["NetcredsApp", "run_tui"]
