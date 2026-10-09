"""Finding inspector: why a finding matters, its context, related findings and raw fields."""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from netcreds_ng.explain import RISK_MEANING, explain
from netcreds_ng.model import Finding, Kind
from netcreds_ng.output.console import KIND_LABEL, RISK_STYLE
from netcreds_ng.output.masking import masked
from netcreds_ng.plugins.sinks.files import iso
from netcreds_ng.tui.insight import account_of, related

if TYPE_CHECKING:
    from netcreds_ng.tui.app import NetcredsApp

SOURCE_LABEL = {"kind": "", "engine": "engine", "analytics": "analytics", "detection": "detection",
                "plugin": "plugin"}  # fmt: skip
FIELDS = ("timestamp", "protocol", "kind", "risk", "src", "dst", "username", "domain", "secret", "value", "tags",
          "frame", "plugin", "confidence")  # fmt: skip


def clock(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else ""


class NoteScreen(ModalScreen[str | None]):
    """Ask for a one-line note; Enter saves (empty removes the note), Esc cancels."""

    DEFAULT_CSS = """
    NoteScreen { align: center middle; }
    #note-box { width: 70; height: auto; border: round $primary; padding: 1 2; background: $panel; }
    """
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, current: str) -> None:
        super().__init__()
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(id="note-box"):
            yield Static("Note for this finding (Enter to save, empty to remove, Esc to cancel)")
            yield Input(value=self.current, id="note-input")

    def on_mount(self) -> None:
        self.query_one("#note-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class FindingScreen(Screen[None]):
    """Full-screen view of one finding. Enter on a related finding opens it; Esc goes back."""

    DEFAULT_CSS = """
    #insp-head { height: auto; padding: 0 1; background: $boost; }
    #insp-body { height: 1fr; }
    #insp-left { width: 3fr; padding: 0 1; }
    #insp-right { width: 2fr; border-left: solid $primary; }
    #insp-right-title { height: 1; padding: 0 1; text-style: bold; }
    .section { margin-bottom: 1; }
    """
    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("asterisk", "bookmark", "Bookmark"),
        Binding("n", "note", "Note"),
        Binding("s", "connection", "Show connection"),
        Binding("m", "mask", "Mask"),
        Binding("q", "back", "Back", show=False),
    ]

    def __init__(self, index: int, depth: int = 1) -> None:
        super().__init__()
        self.index = index
        self.depth = depth
        self.related: list[tuple[str, int]] = []

    @property
    def nc(self) -> NetcredsApp:
        return self.app  # type: ignore[return-value]

    @property
    def finding(self) -> Finding:
        return self.nc.findings[self.index]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="insp-head")
        with Horizontal(id="insp-body"):
            with VerticalScroll(id="insp-left"):
                yield Static("", id="insp-why", classes="section")
                yield Static("", id="insp-context", classes="section")
                yield Static("", id="insp-fields", classes="section")
            with Vertical(id="insp-right"):
                yield Static("Related findings (Enter opens)", id="insp-right-title")
                yield DataTable(id="related", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.sub_title = f"finding #{self.index + 1}" + (f"  (depth {self.depth})" if self.depth > 1 else "")
        table = self.query_one("#related", DataTable)
        table.add_columns("Relation", "Time", "Risk", "Protocol", "What", "Detail")
        with self.nc._lock:
            snapshot = list(self.nc.findings)
        self.related = related(snapshot, self.index)
        self.render_all()
        table.focus()

    # rendering -----------------------------------------------------------------------------

    def render_all(self) -> None:
        f = self.finding
        shown = masked(f) if self.nc.mask else f
        self.query_one("#insp-head", Static).update(self._head(f, shown))
        self.query_one("#insp-why", Static).update(self._why(f))
        self.query_one("#insp-context", Static).update(self._context_text(f))
        self.query_one("#insp-fields", Static).update(self._fields(f, shown))
        table = self.query_one("#related", DataTable)
        table.clear()
        for label, j in self.related:
            g = self.nc.findings[j]
            gs = masked(g) if self.nc.mask else g
            detail = gs.display.replace("\n", "\\n").replace("\r", "\\r")
            table.add_row(label, clock(g.timestamp), Text(g.risk.upper(), style=RISK_STYLE.get(g.risk, "")),
                          g.protocol, KIND_LABEL.get(g.kind, g.kind.value), detail[:60], key=str(j))  # fmt: skip
        title = f"Related findings: {len(self.related)}" + (" (Enter opens)" if self.related else "")
        self.query_one("#insp-right-title", Static).update(title)

    def _head(self, f: Finding, shown: Finding) -> Text:
        mark = self.nc.marks.get(self.index)
        head = Text()
        head.append(f" {f.risk.upper()} ", style=f"reverse {RISK_STYLE.get(f.risk, '')}")
        head.append(f"  {f.protocol} {KIND_LABEL.get(f.kind, f.kind.value)}", style="bold")
        head.append(f"   {f.src} → {f.dst}   {iso(f.timestamp) if f.timestamp else ''}   frame {f.frame}")
        if mark is not None:
            head.append("   ★ bookmarked", style="bold yellow")
            if mark:
                head.append(f": {mark}", style="yellow")
        display = shown.display.replace("\n", "\\n").replace("\r", "\\r")
        if display:
            head.append("\n  ")
            head.append(display[:400], style="bold")
        return head

    def _why(self, f: Finding) -> Text:
        weak = self.nc.weak_list()
        out = Text()
        out.append("Why this matters\n", style="bold underline")
        out.append(f"Risk {f.risk}: ", style=RISK_STYLE.get(f.risk, ""))
        out.append(RISK_MEANING.get(f.risk, "") + "\n\n")
        for reason in explain(f, weak, self.nc.detection_options()):
            out.append("• ", style="bold")
            out.append(reason.title, style="bold")
            src = SOURCE_LABEL.get(reason.source, reason.source)
            if src:
                out.append(f"  [{src}]", style="dim")
            out.append("\n")
            if reason.detail:
                out.append(f"  {reason.detail}\n")
        return out

    def _context_text(self, f: Finding) -> Text:
        summary = self.nc.summary()
        out = Text()
        out.append("Context\n", style="bold underline")
        server = str(f.dst)
        svc = next((s for s in summary.get("services", []) if s["server"] == server and s["protocol"] == f.protocol),
                   None)  # fmt: skip
        if svc is not None:
            out.append("Service ", style="bold")
            out.append(f"{f.protocol} on {server}: {svc['findings']} findings, {svc['clients']} clients, "
                       f"{len(svc['accounts'])} accounts, {svc['failures']} failed / {svc['successes']} "
                       "successful logins")  # fmt: skip
            if svc["cleartext"]:
                out.append("  cleartext secrets seen", style=RISK_STYLE["high"])
            out.append("\n")
        scores = summary.get("host_scores") or {}
        for label, ip in (("Client", f.src.ip), ("Server", f.dst.ip)):
            out.append(f"{label} ", style="bold")
            out.append(f"{ip}: exposure score {scores.get(ip, 0)}/100\n")
        account = account_of(f)
        if account:
            shared = next((a for a in summary.get("shared_accounts", []) if a["account"] == account.lower()), None)
            out.append("Account ", style="bold")
            if shared:
                out.append(f"{account} is used on {len(shared['services'])} services: "
                           f"{', '.join(shared['services'][:6])}\n")  # fmt: skip
            else:
                out.append(f"{account} seen on this service only\n")
        if f.kind is Kind.ALERT:
            for key in ("users", "clients"):
                if f.extra.get(key):
                    values = [str(v) for v in f.extra[key]]
                    out.append(f"{key.capitalize()} ", style="bold")
                    out.append(", ".join(values[:20]) + (f" (+{len(values) - 20})" if len(values) > 20 else "") + "\n")
        if f.kind is Kind.AUTH_RESULT and f.outcome:
            out.append("Outcome ", style="bold")
            out.append(f"{f.outcome}\n", style=RISK_STYLE["high"] if f.outcome == "success" else "")
        return out

    def _fields(self, f: Finding, shown: Finding) -> Text:
        data = shown.to_dict()
        data["timestamp"] = iso(f.timestamp)
        out = Text()
        out.append("Fields\n", style="bold underline")
        for key in FIELDS:
            if key in data:
                out.append(f"{key:>11}: ", style="bold")
                out.append(f"{data[key]}\n")
        if data.get("extra"):
            out.append("      extra: ", style="bold")
            out.append(json.dumps(data["extra"], default=str, ensure_ascii=False) + "\n")
        return out

    # actions -------------------------------------------------------------------------------

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key.value is not None:
            self.app.push_screen(FindingScreen(int(event.row_key.value), self.depth + 1))

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_bookmark(self) -> None:
        self.nc.toggle_mark(self.index)
        self.render_all()

    def action_note(self) -> None:
        def done(text: str | None) -> None:
            if text is not None:
                self.nc.set_note(self.index, text)
                self.render_all()

        self.app.push_screen(NoteScreen(self.nc.marks.get(self.index) or ""), done)

    def action_connection(self) -> None:
        """Back to the findings table, scoped to this finding's connection."""
        while len(self.app.screen_stack) > 1:
            self.app.pop_screen()
        self.nc.scope_connection(self.finding)

    def action_mask(self) -> None:
        self.nc.action_mask()
        self.render_all()
