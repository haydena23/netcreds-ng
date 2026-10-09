"""Interactive Textual dashboard for live capture, capture files and attached findings databases."""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import DataTable, Footer, Header, Input, Sparkline, Static, TabbedContent, TabPane

from netcreds_ng.explain import headline
from netcreds_ng.health import assess
from netcreds_ng.model import Finding, Kind, RunStats
from netcreds_ng.output.console import BROWSING, KIND_LABEL, RISK_STYLE
from netcreds_ng.output.masking import masked
from netcreds_ng.plugins.sinks.files import iso
from netcreds_ng.session import Session, SessionConfig
from netcreds_ng.tui.filters import FilterError, Predicate, parse_filter
from netcreds_ng.tui.insight import (
    Tally,
    account_of,
    accounts,
    bar,
    reason_counts,
    spark,
    timeline,
)
from netcreds_ng.tui.inspector import FindingScreen, NoteScreen, clock

RISKS = ("info", "low", "medium", "high")
RATE_SAMPLES = 120
POLL_SECONDS = 0.5
TABS = ("findings", "overview", "alerts", "hosts", "services", "accounts", "bookmarks", "health")
W = TypeVar("W", bound=Widget)


def default_filters_path() -> Path:
    from netcreds_ng.config import user_config_path

    return user_config_path().parent / "filters.json"


class NetcredsApp(App[int]):
    TITLE = "netcreds-ng"
    CSS = """
    #status { height: 1; padding: 0 1; background: $boost; }
    #rate { height: 2; margin: 0 1; }
    #scope { height: 1; padding: 0 1; color: $warning; display: none; }
    #scope.visible { display: block; }
    #filter { display: none; }
    #filter.visible { display: block; }
    #tabs { height: 1fr; }
    #body { height: 1fr; }
    #findings { width: 1fr; }
    #side { width: 44; display: none; border-left: solid $primary; padding: 0 1; }
    #side.visible { display: block; }
    #detail { height: 12; border-top: solid $primary; padding: 0 1; overflow-y: auto; }
    .page { padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("question_mark", "keys", "Keys"),
        Binding("p", "pause", "Pause/Resume", show=False),
        Binding("slash", "filter", "Filter"),
        Binding("escape", "clear_filter", "Clear filter/scope", show=False),
        Binding("s", "session", "Session"),
        Binding("o", "host('src')", "Src host", show=False),
        Binding("d", "host('dst')", "Dst host", show=False),
        Binding("ctrl+s", "save_filter", "Save filter", show=False),
        Binding("f", "next_filter", "Saved filters", show=False),
        Binding("r", "risk", "Min risk", show=False),
        Binding("b", "browsing", "Browsing", show=False),
        Binding("m", "mask", "Mask"),
        Binding("a", "analytics", "Analytics", show=False),
        Binding("t", "follow", "Follow"),
        Binding("space", "freeze", "Freeze"),
        Binding("asterisk", "bookmark", "Bookmark"),
        Binding("n", "note", "Note"),
        Binding("e", "export", "Export JSONL"),
        Binding("h", "report", "HTML report", show=False),
        *(Binding(str(i), f"tab('{name}')", name.capitalize(), show=False) for i, name in enumerate(TABS, 1)),
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
        filters_path: Path | None = None,
        attach: str | None = None,
    ) -> None:
        super().__init__()
        self.filters_path = filters_path or default_filters_path()
        self.saved_filters: list[str] = self._load_filters()
        self._saved_index = -1
        self.predicate: Predicate | None = None
        self.scope: tuple[str, Predicate] | None = None
        self.rates: deque[float] = deque([0.0] * RATE_SAMPLES, maxlen=RATE_SAMPLES)
        self._last_frames = 0
        self._last_tick = time.monotonic()
        self.alerts: list[Finding] = []
        self.registry = registry
        self.config = config
        self.files = files or []
        self.interface = interface
        self.bpf = bpf
        self.attach = attach
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
        self.store: Any = None  # FindingStore in --attach mode
        self.tally: Tally | None = None
        self._lock = threading.Lock()
        # bookmarks: finding index -> note ("" for a bookmark without a note)
        self.marks: dict[int, str] = {}
        # live view: follow moves the cursor to each new finding; freeze stops updating the table
        self.follow = bool(interface or attach)
        self.frozen = False
        self.pending = 0
        self._version = 0  # bumped on every finding; tabs re-render only when it moved
        self._rendered: dict[str, int] = {}
        self._drill_from: str | None = None
        self._summary_cache: dict[str, Any] = {}
        self._weak: frozenset[str] | None = None
        self._main: Screen[Any] | None = None

    # layout ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="status")
        yield Sparkline(list(self.rates), id="rate", summary_function=max)
        yield Static("", id="scope")
        yield Input(placeholder="filter: text matches protocol, host, user, value, tags (Esc to clear)", id="filter")
        with TabbedContent(id="tabs", initial="tab-findings"):
            with TabPane("1 Findings", id="tab-findings"), Horizontal(id="body"):
                with Vertical(id="findings"):
                    yield DataTable(id="table", zebra_stripes=True, cursor_type="row")
                    yield Static("Select a finding to see details; Enter opens the inspector.", id="detail")
                yield Static("", id="side")
            with TabPane("2 Overview", id="tab-overview"), VerticalScroll(classes="page"):
                yield Static("", id="overview")
            with TabPane("3 Alerts", id="tab-alerts"):
                yield DataTable(id="alerts-table", zebra_stripes=True, cursor_type="row")
            with TabPane("4 Hosts", id="tab-hosts"):
                yield DataTable(id="hosts-table", zebra_stripes=True, cursor_type="row")
            with TabPane("5 Services", id="tab-services"):
                yield DataTable(id="services-table", zebra_stripes=True, cursor_type="row")
            with TabPane("6 Accounts", id="tab-accounts"):
                yield DataTable(id="accounts-table", zebra_stripes=True, cursor_type="row")
            with TabPane("7 Bookmarks", id="tab-bookmarks"):
                yield DataTable(id="bookmarks-table", zebra_stripes=True, cursor_type="row")
            with TabPane("8 Health", id="tab-health"), VerticalScroll(classes="page"):
                yield Static("", id="health")
        yield Footer()

    def q(self, selector: str, kind: type[W]) -> W:
        """Query the main screen, whichever screen is showing."""
        return (self._main or self.screen).query_one(selector, kind)

    def on_mount(self) -> None:
        self._main = self.screen
        table = self.q("#table", DataTable)
        self._cols = table.add_columns("★", "Time", "Risk", "Protocol", "What", "Source → Destination", "Detail", "Tags")
        self.q("#alerts-table", DataTable).add_columns("Time", "Detection", "Source", "Target", "Protocol",
                                                       "Attempts", "Summary")  # fmt: skip
        self.q("#hosts-table", DataTable).add_columns("Host", "Score", "Max risk", "As client", "As server",
                                                      "Protocols", "Accounts")  # fmt: skip
        self.q("#services-table", DataTable).add_columns("Server", "Protocol", "Cleartext", "Findings", "Clients",
                                                         "Accounts", "Failed", "OK")  # fmt: skip
        self.q("#accounts-table", DataTable).add_columns("Account", "Max risk", "Secret", "Weak", "Reused",
                                                         "Services", "Clients", "Failed", "OK", "Last seen")  # fmt: skip
        self.q("#bookmarks-table", DataTable).add_columns("Time", "Risk", "Protocol", "What",
                                                          "Source → Destination", "Note")  # fmt: skip
        if self.attach:
            from netcreds_ng.tui.store import FindingStore

            self.sub_title = f"attached: {self.attach}"
            self.store = FindingStore(self.attach)
            self.tally = Tally(self.config.plugin_options.get("detection"))
            self.run_worker(self._follow_store, thread=True, exclusive=True, name="attach")
        else:
            source = self.interface or ", ".join(self.files)
            self.sub_title = f"{'live: ' if self.interface else ''}{source}"
            self.session = Session(self.registry, self.config, listeners=[self._on_finding])
            self.session.open()
            self.run_worker(self._analyse, thread=True, exclusive=True, name="analysis")
        self.set_interval(0.5, self._refresh_status)
        self.set_interval(1.0, self._refresh_active_tab)
        self.q("#filter", Input).disabled = True  # hidden filter box must not swallow key bindings
        table.focus()

    # data sources ------------------------------------------------------------

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

    def _follow_store(self) -> None:
        """--attach: load the database, then poll it for findings a running netcreds-ng adds."""
        assert self.store is not None
        self.state = "loading"
        try:
            while not self.stopping.is_set():
                if self.paused.is_set():
                    time.sleep(0.1)
                    continue
                batch = self.store.poll()
                for f in batch:
                    self._on_finding(f)
                if not batch:
                    self.state = "following" if any(r.in_progress for r in self.store.runs()) else "attached"
                    time.sleep(POLL_SECONDS)
        except Exception as exc:  # noqa: BLE001 - shown in the UI
            self.state = "error"
            if not self.stopping.is_set():
                self.call_from_thread(self.notify, f"cannot read {self.attach}: {exc}", severity="error", timeout=15)
        finally:
            if self.stopping.is_set():
                self.store.close()

    def _should_stop(self) -> bool:
        while self.paused.is_set() and not self.stopping.is_set():
            time.sleep(0.1)
        return self.stopping.is_set()

    def _on_finding(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
            if self.tally is not None:
                self.tally.observe(finding)
            if finding.kind is Kind.ALERT:
                self.alerts.append(finding)
            self._version += 1
        self.call_from_thread(self._add_row, finding, len(self.findings) - 1)
        if finding.kind is Kind.ALERT:
            self.call_from_thread(self.notify, finding.value or "alert", title="Alert", severity="warning", timeout=8)

    @property
    def stats(self) -> RunStats:
        if self.session is not None:
            return self.session.stats
        if self.store is not None:
            try:
                return self.store.stats()  # type: ignore[no-any-return]
            except Exception:  # noqa: BLE001 - database busy or gone; the status bar keeps old values
                pass
        return RunStats(findings=len(self.findings))

    def summary(self) -> dict[str, Any]:
        """Run analytics (hosts, services, alerts, scores). Computed by the session, or rebuilt from the
        attached database; the last good value is kept if the analysis thread changes it mid-read."""
        try:
            if self.session is not None:
                self._summary_cache = self.session.summary()
            elif self.tally is not None:
                with self._lock:
                    self._summary_cache = self.tally.summary()
        except RuntimeError:  # "dictionary changed size during iteration": try again next refresh
            pass
        return self._summary_cache

    def weak_list(self) -> frozenset[str]:
        if self._weak is None:
            from netcreds_ng.plugins.enrichers.analytics import load_weak_passwords

            self._weak = load_weak_passwords()
        return self._weak

    def detection_options(self) -> dict[str, Any]:
        det = self.session.detection if self.session is not None else self.tally.detection if self.tally else None
        if det is None:
            return {}
        return {"window": det.window, "bruteforce": det.bruteforce, "spray": det.spray, "targeted": det.targeted}

    # findings table ----------------------------------------------------------

    def _visible(self, f: Finding) -> bool:
        if RISKS.index(f.risk) < self.min_risk:
            return False
        if not self.show_browsing and f.kind in BROWSING:
            return False
        if self.scope is not None and not self.scope[1](f):
            return False
        if self.predicate is not None:
            return self.predicate(f)
        return True

    def _cells(self, f: Finding, idx: int) -> tuple[Any, ...]:
        shown = masked(f) if self.mask else f
        detail = shown.display.replace("\n", "\\n").replace("\r", "\\r")
        if not self.verbose and len(detail) > 80:
            detail = detail[:77] + "..."
        route = f"{f.src.ip}" if f.kind in BROWSING else f"{f.src} → {f.dst}"
        return (
            self._mark_cell(idx), clock(f.timestamp), Text(f.risk.upper(), style=RISK_STYLE.get(f.risk, "")),
            f.protocol, KIND_LABEL.get(f.kind, f.kind.value), route, detail, " ".join(f.tags),
        )  # fmt: skip

    def _mark_cell(self, idx: int) -> Text:
        if idx not in self.marks:
            return Text("")
        return Text("✎" if self.marks[idx] else "★", style="bold yellow")

    def _add_row(self, f: Finding, idx: int) -> None:
        if not self._visible(f):
            return
        if self.frozen:
            self.pending += 1
            return
        table = self.q("#table", DataTable)
        table.add_row(*self._cells(f, idx), key=str(idx))
        if self.follow and self.screen is self._main:
            table.move_cursor(row=table.row_count - 1, animate=False)

    def _rebuild(self) -> None:
        table = self.q("#table", DataTable)
        table.clear()
        with self._lock:
            items = list(enumerate(self.findings))
        for idx, f in items:
            if self._visible(f):
                table.add_row(*self._cells(f, idx), key=str(idx))
        self.pending = 0
        if self.follow and table.row_count:
            table.move_cursor(row=table.row_count - 1, animate=False)

    def _sample_rate(self, st: RunStats) -> float:
        now = time.monotonic()
        dt = max(now - self._last_tick, 1e-3)
        rate = max(0.0, (st.frames - self._last_frames) / dt)
        self._last_frames, self._last_tick = st.frames, now
        if self.state in ("running", "following") and not self.paused.is_set():
            self.rates.append(rate)
            self.q("#rate", Sparkline).data = list(self.rates)
        return rate

    def _refresh_status(self) -> None:
        if self.session is None and self.store is None:
            return
        st = self.stats
        rate = self._sample_rate(st)
        high = sum(1 for f in self.findings if f.risk == "high")
        state = "PAUSED" if self.paused.is_set() else self.state.upper()
        extra = ""
        if self.capture is not None and self.capture.dropped:
            extra = f"  dropped {self.capture.dropped:,}"
        if self.store is not None and self.store.skipped:
            extra += f"  skipped {self.store.skipped:,} (unknown kind)"
        warn = st.total_plugin_errors + len(st.source_errors)
        view = "FROZEN" if self.frozen else "follow" if self.follow else ""
        self.q("#status", Static).update(
            Text.assemble(
                (f" {state} ", "reverse bold"),
                (f" {view}{f' +{self.pending} new' if self.pending else ''} ", "reverse yellow" if self.frozen else "dim")
                if view else "",
                f"  frames {st.frames:,} ({rate:,.0f}/s)  flows {st.tcp_flows + st.udp_flows:,}"
                f"  findings {len(self.findings):,}  ",
                (f"high {high}", RISK_STYLE["high"]),
                (f"  alerts {len(self.alerts)}" if self.alerts else "", "bold red"),
                f"  dup {st.duplicates:,}  min-risk {RISKS[self.min_risk]}"
                f"{'  masked' if self.mask else ''}{'' if self.show_browsing else '  no-browsing'}",
                (f"  bookmarks {len(self.marks)}" if self.marks else "", "yellow"),
                (f"  warnings {warn}" if warn else "", "yellow"),
                extra,
            )
        )
        if self.q("#side", Static).has_class("visible"):
            self._refresh_side()

    def _refresh_side(self) -> None:
        if self.session is None and self.store is None:
            return
        summary = self.summary()
        rc = summary.get("risk_counts", {})
        lines = Text()
        lines.append("Exposure analytics\n\n", style="bold")
        for r in ("high", "medium", "low", "info"):
            lines.append(f"{r:<7}", style=RISK_STYLE[r])
            lines.append(f"{rc.get(r, 0):>6}\n")
        lines.append(f"\nweak passwords {summary.get('weak_passwords', 0)}\n")
        lines.append(f"reused secrets {summary.get('reused_secrets', 0)}\n\n")
        alerts = summary.get("alerts") or []
        if alerts:
            lines.append("Alerts\n", style="bold red")
            for a in alerts[-8:]:
                lines.append(f"{a['detection']}", style=RISK_STYLE["high"])
                lines.append(f" {a['src']} > {a['dst']}\n")
            lines.append("\n")
        scores = summary.get("host_scores") or {}
        lines.append("Most exposed hosts\n", style="bold")
        hosts = sorted(summary.get("hosts") or [], key=lambda h: -int(scores.get(h["ip"], 0)))
        for h in hosts[:15]:
            lines.append(f"{h['ip']:<22}", style=RISK_STYLE.get(h["max_risk"], ""))
            lines.append(f" {scores.get(h['ip'], 0):>3} {', '.join(h['protocols'])[:14]}\n")
        st = self.stats
        if st.plugin_errors or st.source_errors:
            lines.append("\nWarnings\n", style="bold yellow")
            for name, n in st.plugin_errors.items():
                lines.append(f"{name}: {n}\n")
            for e in st.source_errors[:5]:
                lines.append(f"{e[:40]}\n")
        self.q("#side", Static).update(lines)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "table" or event.row_key is None or event.row_key.value is None:
            return
        idx = int(event.row_key.value)
        f = self.findings[idx]
        shown = masked(f) if self.mask else f
        body = Text()
        body.append("why: ", style="bold")
        body.append(headline(f) + "\n", style=RISK_STYLE.get(f.risk, ""))
        if idx in self.marks:
            body.append("note: " if self.marks[idx] else "", style="bold yellow")
            body.append((self.marks[idx] or "★ bookmarked") + "\n", style="yellow")
        data = shown.to_dict()
        data["timestamp"] = iso(f.timestamp)
        for key in ("timestamp", "protocol", "kind", "risk", "src", "dst", "username", "domain", "secret", "value",
                    "tags", "frame", "plugin", "confidence"):  # fmt: skip
            if key in data:
                body.append(f"{key:>11}: ", style="bold")
                body.append(f"{data[key]}\n")
        if data.get("extra"):
            body.append("      extra: ", style="bold")
            body.append(json.dumps(data["extra"], default=str) + "\n")
        self.q("#detail", Static).update(body)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter: open the inspector, or drill down from an analytics table."""
        table, key = event.data_table.id, event.row_key.value
        if key is None:
            return
        if table in ("table", "alerts-table", "bookmarks-table"):
            self.push_screen(FindingScreen(int(key)))
        elif table == "hosts-table":
            self._drill(f"host {key}", lambda g: key in (g.src.ip, g.dst.ip))
        elif table == "services-table":
            server, _, proto = key.partition("|")
            self._drill(f"service {proto} on {server}", lambda g: str(g.dst) == server and g.protocol == proto)
        elif table == "accounts-table":
            self._drill(f"account {key}", lambda g: account_of(g).lower() == key)

    # analytics tabs ------------------------------------------------------------

    def active_tab(self) -> str:
        return (self.q("#tabs", TabbedContent).active or "tab-findings").removeprefix("tab-")

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        name = self.active_tab()
        self._render_tab(name, force=True)
        widget = {"findings": "#table", "alerts": "#alerts-table", "hosts": "#hosts-table",
                  "services": "#services-table", "accounts": "#accounts-table",
                  "bookmarks": "#bookmarks-table"}.get(name)  # fmt: skip
        if widget:
            self.q(widget, DataTable).focus()

    def _refresh_active_tab(self) -> None:
        if self.screen is self._main:
            self._render_tab(self.active_tab())

    def _render_tab(self, name: str, force: bool = False) -> None:
        stamp = self._version + (len(self.marks) << 32) + (self.mask << 48)
        if not force and self._rendered.get(name) == stamp and name != "health":
            return
        self._rendered[name] = stamp
        render: dict[str, Callable[[], None]] = {
            "overview": self._render_overview, "alerts": self._render_alerts, "hosts": self._render_hosts,
            "services": self._render_services, "accounts": self._render_accounts,
            "bookmarks": self._render_bookmarks, "health": self._render_health,
        }  # fmt: skip
        if name in render:
            render[name]()

    @staticmethod
    def _refill(table: DataTable[Any], rows: list[tuple[str, tuple[Any, ...]]]) -> None:
        """Replace the rows, keeping the cursor on the same row key where possible."""
        current = None
        if table.row_count:
            try:
                current = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            except Exception:  # noqa: BLE001 - no valid cursor
                current = None
        table.clear()
        for key, cells in rows:
            table.add_row(*cells, key=key)
        if current is not None:
            try:
                table.move_cursor(row=table.get_row_index(current), animate=False)
            except Exception:  # noqa: BLE001 - the row is gone
                pass

    def _snapshot(self) -> list[Finding]:
        with self._lock:
            return list(self.findings)

    def _render_alerts(self) -> None:
        rows = []
        for idx, f in enumerate(self._snapshot()):
            if f.kind is Kind.ALERT:
                rows.append((str(idx), (clock(f.timestamp), Text(str(f.extra.get("detection", "alert")),
                             style=RISK_STYLE["high"]), str(f.src), str(f.dst), f.protocol,
                             str(f.extra.get("attempts", "")), (f.value or "")[:90])))  # fmt: skip
        self._refill(self.q("#alerts-table", DataTable), rows)

    def _render_hosts(self) -> None:
        summary = self.summary()
        scores = summary.get("host_scores") or {}
        hosts = sorted(summary.get("hosts") or [], key=lambda h: (-int(scores.get(h["ip"], 0)), h["ip"]))
        rows = [(h["ip"], (h["ip"], str(scores.get(h["ip"], 0)), Text(h["max_risk"], style=RISK_STYLE.get(h["max_risk"], "")),
                           str(h["as_client"]), str(h["as_server"]), ", ".join(h["protocols"])[:40],
                           str(len(h["accounts"])))) for h in hosts]  # fmt: skip
        self._refill(self.q("#hosts-table", DataTable), rows)

    def _render_services(self) -> None:
        rows = []
        for s in self.summary().get("services") or []:
            clear = Text("yes", style=RISK_STYLE["high"]) if s["cleartext"] else Text("no", style="dim")
            rows.append((f"{s['server']}|{s['protocol']}", (s["server"], s["protocol"], clear, str(s["findings"]),
                         str(s["clients"]), str(len(s["accounts"])), str(s["failures"]), str(s["successes"]))))  # fmt: skip
        self._refill(self.q("#services-table", DataTable), rows)

    def _render_accounts(self) -> None:
        def flag(on: bool) -> Text:
            return Text("yes", style=RISK_STYLE["high"]) if on else Text("")

        rows = []
        for a in accounts(self._snapshot()):
            secret = Text("cleartext", style=RISK_STYLE["high"]) if a.cleartext else Text("seen" if a.secret_seen else "")
            rows.append((a.account.lower(), (a.account, Text(a.max_risk, style=RISK_STYLE.get(a.max_risk, "")), secret,
                         flag(a.weak), flag(a.reused), str(len(a.services)), str(len(a.clients)), str(a.failures),
                         str(a.successes), clock(a.last_ts))))  # fmt: skip
        self._refill(self.q("#accounts-table", DataTable), rows)

    def _render_bookmarks(self) -> None:
        findings = self._snapshot()
        rows = []
        for idx in sorted(self.marks):
            f = findings[idx]
            route = f"{f.src.ip}" if f.kind in BROWSING else f"{f.src} → {f.dst}"
            rows.append((str(idx), (clock(f.timestamp), Text(f.risk.upper(), style=RISK_STYLE.get(f.risk, "")),
                         f.protocol, KIND_LABEL.get(f.kind, f.kind.value), route, self.marks[idx])))  # fmt: skip
        self._refill(self.q("#bookmarks-table", DataTable), rows)

    def _render_overview(self) -> None:
        findings = self._snapshot()
        st = self.stats
        risk = {r: sum(1 for f in findings if f.risk == r and f.kind not in BROWSING) for r in RISKS}
        browsing = sum(1 for f in findings if f.kind in BROWSING)
        parts: list[Any] = []

        head = Text()
        head.append("Exposure\n", style="bold underline")
        peak = max(risk.values(), default=0)
        for r in reversed(RISKS):
            head.append(f"{r:<7}", style=RISK_STYLE[r])
            head.append(f"{risk[r]:>6}  ")
            head.append(bar(risk[r], peak, 40) + "\n", style=RISK_STYLE[r])
        head.append(f"browsing {browsing:,}  alerts {len(self.alerts)}  bookmarks {len(self.marks)}\n")
        parts.append(head)

        width = max(20, min(100, self.size.width - 16))
        tl = timeline(findings, width)
        if tl is not None:
            t = Text()
            t.append("\nTimeline", style="bold underline")
            t.append(f"  {iso(tl.start)} → {iso(tl.end)}  (capture time, {width} buckets)\n")
            top = max((v for row in tl.buckets.values() for v in row), default=0)
            for r in reversed(RISKS):
                t.append(f"{r:<7}", style=RISK_STYLE[r])
                t.append(spark(tl.buckets[r], top) + "\n", style=RISK_STYLE[r] if r != "info" else "")
            parts.append(t)

        reasons = reason_counts(findings)
        if reasons:
            table = Table(title="Why findings matter (top reasons)", title_justify="left", box=None, pad_edge=False)
            table.add_column("Reason")
            table.add_column("Tag", style="dim")
            table.add_column("Findings", justify="right")
            for tag, title, n in reasons[:12]:
                table.add_row(title, tag, str(n))
            parts.append(Text())
            parts.append(table)

        for title, counter in (("By protocol", st.by_protocol or _count(f.protocol for f in findings)),
                               ("By kind", st.by_kind or _count(f.kind.value for f in findings))):  # fmt: skip
            block = Text()
            block.append(f"\n{title}\n", style="bold underline")
            items = sorted(counter.items(), key=lambda kv: -kv[1])[:12]
            peak = max((n for _, n in items), default=0)
            for name, n in items:
                block.append(f"{name:<14} {n:>6}  ")
                block.append(bar(n, peak, 30) + "\n", style="cyan")
            parts.append(block)

        health = assess(st)
        h = Text()
        h.append("\nCapture health ", style="bold underline")
        h.append(f" {health['status']}\n", style=_HEALTH_STYLE.get(health["status"], ""))
        h.append(health["verdict"] + "\n")
        parts.append(h)
        self.q("#overview", Static).update(Group(*parts))

    def _render_health(self) -> None:
        st = self.stats
        health = assess(st)
        out = Text()
        out.append("Capture health: ", style="bold")
        out.append(f"{health['status']}\n", style=_HEALTH_STYLE.get(health["status"], ""))
        out.append(health["verdict"] + "\n\n")
        if self.store is not None:
            runs = self.store.runs()
            out.append(f"Database {self.attach}: {len(runs)} run(s)\n", style="bold")
            for run in runs[-5:]:
                state = "in progress" if run.in_progress else "finished" if run.finished else "ended (no close)"
                out.append(f"  run {run.id}: {run.source or '?'}  started {iso(run.started) if run.started else '?'}"
                           f"  {state}\n")  # fmt: skip
            out.append("\n")
        if health["issues"]:
            out.append("Issues\n", style="bold underline")
            for issue in health["issues"]:
                out.append(f"  {issue['severity']:<8}", style=_HEALTH_STYLE.get(issue["severity"], ""))
                out.append(f"{issue['message']}\n")
            out.append("\n")
        out.append("Metrics\n", style="bold underline")
        for key, value in health["metrics"].items():
            shown = f"{value:.1%}" if key.endswith("_rate") else f"{value:,}"
            out.append(f"  {key:<26}{shown:>12}\n")
        out.append("\nRun counters\n", style="bold underline")
        for key in ("decoded", "undecodable", "ip_fragments", "ip_reassembled", "tcp_gaps", "evicted_flows",
                    "ambiguous_flows", "tls_sessions", "tls_decrypted", "tls_no_key", "findings", "duplicates"):  # fmt: skip
            out.append(f"  {key:<26}{getattr(st, key):>12,}\n")
        if st.plugin_errors or st.source_errors:
            out.append("\nWarnings\n", style="bold yellow")
            for name, n in st.plugin_errors.items():
                out.append(f"  {name}: {n}\n")
            for e in st.source_errors[:10]:
                out.append(f"  {e}\n")
        self.q("#health", Static).update(out)

    # actions -----------------------------------------------------------------

    def action_keys(self) -> None:
        """Show or hide the panel listing every key of the current screen."""
        if self.screen.query("HelpPanel"):
            self.action_hide_help_panel()
        else:
            self.action_show_help_panel()

    def action_tab(self, name: str) -> None:
        if self.screen is not self._main:
            return
        self.q("#tabs", TabbedContent).active = f"tab-{name}"

    def action_pause(self) -> None:
        if self.paused.is_set():
            self.paused.clear()
        else:
            self.paused.set()
        self._refresh_status()

    def action_follow(self) -> None:
        self.follow = not self.follow
        table = self.q("#table", DataTable)
        if self.follow and table.row_count and not self.frozen:
            table.move_cursor(row=table.row_count - 1, animate=False)
        self.notify("Follow on: the cursor jumps to each new finding" if self.follow else "Follow off")
        self._refresh_status()

    def action_freeze(self) -> None:
        self.frozen = not self.frozen
        if not self.frozen:
            self._rebuild()  # catches up on everything that arrived while frozen
        self._refresh_status()

    def action_filter(self) -> None:
        self.action_tab("findings")
        box = self.q("#filter", Input)
        box.disabled = False
        box.add_class("visible")
        box.focus()

    def action_clear_filter(self) -> None:
        box = self.q("#filter", Input)
        box.value = ""
        box.remove_class("visible")
        box.disabled = True
        self._set_filter("")
        self._set_scope(None)
        back, self._drill_from = self._drill_from, None
        if back:
            self.action_tab(back)  # back out of a drill-down to where it started
        else:
            self.q("#table", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self._set_filter(event.value)

    def _set_filter(self, text: str) -> None:
        try:
            predicate = parse_filter(text) if text.strip() else None
        except FilterError as exc:
            self.q("#filter", Input).border_subtitle = str(exc)
            return
        self.q("#filter", Input).border_subtitle = ""
        self.filter_text = text
        self.predicate = predicate
        self._rebuild()

    def _set_scope(self, scope: tuple[str, Predicate] | None) -> None:
        self.scope = scope
        label = self.q("#scope", Static)
        if scope is None:
            label.remove_class("visible")
        else:
            label.update(f"scope: {scope[0]}  (Esc to clear)")
            label.add_class("visible")
        self._rebuild()

    def _drill(self, label: str, predicate: Predicate) -> None:
        """Show the findings behind an analytics row; Esc returns to the tab it came from."""
        self._drill_from = self.active_tab()
        self.action_tab("findings")
        self._set_scope((label, predicate))
        self.q("#table", DataTable).focus()

    def _selected_index(self) -> int | None:
        """Finding index under the cursor of the findings, alerts or bookmarks table."""
        widget = {"findings": "#table", "alerts": "#alerts-table", "bookmarks": "#bookmarks-table"}.get(
            self.active_tab())
        if widget is None:
            return None
        table = self.q(widget, DataTable)
        if not table.row_count:
            return None
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
        except Exception:  # noqa: BLE001 - no valid cursor
            return None
        return int(key.value) if key.value is not None else None

    def _selected(self) -> Finding | None:
        idx = self._selected_index()
        return self.findings[idx] if idx is not None else None

    def scope_connection(self, f: Finding) -> None:
        pair = {(f.src.ip, f.src.port), (f.dst.ip, f.dst.port)}
        if self.active_tab() != "findings":
            self._drill_from = self.active_tab()
            self.action_tab("findings")
        self._set_scope((f"session {f.src} <> {f.dst}",
                         lambda g: {(g.src.ip, g.src.port), (g.dst.ip, g.dst.port)} == pair))  # fmt: skip

    def action_session(self) -> None:
        """Show every finding of the selected finding's connection (both directions)."""
        f = self._selected()
        if f is not None:
            self.scope_connection(f)

    def action_host(self, side: str) -> None:
        """Drill down to every finding involving the selected finding's source or destination host."""
        f = self._selected()
        if f is None:
            return
        ip = f.src.ip if side == "src" else f.dst.ip
        if self.active_tab() != "findings":
            self._drill(f"host {ip}", lambda g: ip in (g.src.ip, g.dst.ip))
            return
        self._set_scope((f"host {ip}", lambda g: ip in (g.src.ip, g.dst.ip)))

    # bookmarks and notes -----------------------------------------------------

    def toggle_mark(self, idx: int) -> None:
        if idx in self.marks:
            del self.marks[idx]
        else:
            self.marks[idx] = ""
        self._update_mark_cell(idx)

    def set_note(self, idx: int, text: str) -> None:
        if text:
            self.marks[idx] = text
        elif idx in self.marks:
            self.marks[idx] = ""  # an emptied note leaves the bookmark
        else:
            return
        self._update_mark_cell(idx)

    def _update_mark_cell(self, idx: int) -> None:
        table = self.q("#table", DataTable)
        try:
            table.update_cell(str(idx), self._cols[0], self._mark_cell(idx))
        except Exception:  # noqa: BLE001 - the row is filtered out
            pass
        self._refresh_status()

    def action_bookmark(self) -> None:
        idx = self._selected_index()
        if idx is None:
            self.notify("Highlight a finding first", severity="warning")
            return
        self.toggle_mark(idx)
        if self.active_tab() == "bookmarks":
            self._render_tab("bookmarks", force=True)

    def action_note(self) -> None:
        idx = self._selected_index()
        if idx is None:
            self.notify("Highlight a finding first", severity="warning")
            return

        def done(text: str | None) -> None:
            if text is not None:
                self.set_note(idx, text)

        self.push_screen(NoteScreen(self.marks.get(idx) or ""), done)

    # saved filters -----------------------------------------------------------

    def _load_filters(self) -> list[str]:
        try:
            data = json.loads(self.filters_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [str(x) for x in data if isinstance(x, str)] if isinstance(data, list) else []

    def action_save_filter(self) -> None:
        text = self.filter_text.strip()
        if not text:
            self.notify("Type a filter first (/), then Ctrl+S to save it", severity="warning")
            return
        if text not in self.saved_filters:
            self.saved_filters.append(text)
        try:
            self.filters_path.parent.mkdir(parents=True, exist_ok=True)
            self.filters_path.write_text(json.dumps(self.saved_filters, indent=2), encoding="utf-8")
        except OSError as exc:
            self.notify(f"Could not save filters: {exc}", severity="error")
            return
        self.notify(f"Saved filter: {text}")

    def action_next_filter(self) -> None:
        if not self.saved_filters:
            self.notify("No saved filters yet (Ctrl+S saves the current one)")
            return
        self.action_tab("findings")
        self._saved_index = (self._saved_index + 1) % len(self.saved_filters)
        text = self.saved_filters[self._saved_index]
        box = self.q("#filter", Input)
        box.disabled = False
        box.add_class("visible")
        box.value = text  # triggers on_input_changed
        self._set_filter(text)
        self.q("#table", DataTable).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter":
            self.q("#table", DataTable).focus()

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
        self.action_tab("findings")
        side = self.q("#side", Static)
        side.toggle_class("visible")
        self._refresh_side()

    # export ------------------------------------------------------------------

    def _stamp(self) -> str:
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    def action_export(self) -> None:
        path = f"netcreds-export-{self._stamp()}.jsonl"
        with self._lock:
            items = [(i, f) for i, f in enumerate(self.findings) if self._visible(f)]
        with open(path, "w", encoding="utf-8") as fh:
            for i, f in items:
                data = (masked(f) if self.mask else f).to_dict()
                data["timestamp"] = iso(f.timestamp)
                if i in self.marks:
                    data["bookmarked"] = True
                    if self.marks[i]:
                        data["note"] = self.marks[i]
                fh.write(json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n")
        self.notify(f"Exported {len(items)} findings to {path}")

    def action_report(self) -> None:
        from netcreds_ng.plugins.sinks.html import HtmlReportSink

        if self.session is None and self.store is None:
            return
        path = f"netcreds-report-{self._stamp()}.html"
        sink = HtmlReportSink(path, {"summary": self.summary, "include_secrets": not self.mask,
                                     "source_label": self.sub_title})  # fmt: skip
        with self._lock:
            items = list(self.findings)
        for f in items:
            sink.write(f)
        sink.close(self.stats)
        self.notify(f"Report written to {path}")

    async def action_quit(self) -> None:
        self.stopping.set()
        self.paused.clear()
        if self.capture is not None:
            self.capture.stop()
        self.exit(0)


_HEALTH_STYLE = {"good": "bold green", "degraded": "bold yellow", "poor": "bold red", "warning": "yellow",
                 "info": "dim"}  # fmt: skip


def _count(values: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return out


def run_tui(
    registry: Any,
    config: SessionConfig,
    files: list[str] | None = None,
    interface: str | None = None,
    bpf: str | None = None,
    verbose: bool = False,
    mask: bool = False,
    filters_path: Path | None = None,
    attach: str | None = None,
) -> int:
    app = NetcredsApp(registry, config, files=files, interface=interface, bpf=bpf, verbose=verbose, mask=mask,
                      filters_path=filters_path, attach=attach)  # fmt: skip
    result = app.run()
    return int(result or 0)


__all__ = ["Kind", "NetcredsApp", "run_tui"]
