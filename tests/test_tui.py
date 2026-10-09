"""Headless TUI test using Textual's pilot."""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3

from conftest import SYNTHETIC
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import SessionConfig
from netcreds_ng.tui.app import NetcredsApp


def _rows(app: NetcredsApp) -> int:
    return app.query_one("#table").row_count


async def _drive(tmp_path) -> None:
    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(),
                      files=[str(SYNTHETIC / "ftp_basic.pcap"), str(SYNTHETIC / "http_basic.pcap")],
                      filters_path=tmp_path / "filters.json")  # fmt: skip
    async with app.run_test(size=(160, 45)) as pilot:
        for _ in range(100):
            await pilot.pause(0.05)
            if app.state == "done":
                break
        await pilot.pause(0.2)
        assert app.state == "done"
        total = _rows(app)
        assert total == len(app.findings) >= 4

        await pilot.press("m")  # mask
        await pilot.pause()
        assert app.mask
        cells = [str(c) for row in range(_rows(app)) for c in app.query_one("#table").get_row_at(row)]
        assert not any("FakePass-123" in c for c in cells)

        await pilot.press("b")  # hide URL/POST/search
        await pilot.pause()
        assert _rows(app) < total

        await pilot.press("r", "r", "r")  # min risk -> high
        await pilot.pause()
        assert all(f.risk == "high" for f in app.findings if app._visible(f))

        await pilot.press("r")  # back to info
        await pilot.press("b")
        await pilot.press("slash")
        await pilot.press(*"basicuser")
        await pilot.pause()
        assert _rows(app) >= 1 and all("basicuser" in (f.username or "") or "basicuser" in f.display
                                       for f in app.findings if app._visible(f))  # fmt: skip
        await pilot.press("escape")
        await pilot.pause()
        assert _rows(app) == total

        await pilot.press("a")  # analytics side panel
        await pilot.pause()
        await pilot.press("e", "h")  # export JSONL + HTML report into cwd
        await pilot.pause(0.3)
        await pilot.press("q")
    assert list(tmp_path.glob("netcreds-export-*.jsonl"))
    assert list(tmp_path.glob("netcreds-report-*.html"))


def test_tui_headless(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    asyncio.run(_drive(tmp_path))


async def _wait_done(app: NetcredsApp, pilot) -> None:
    for _ in range(100):
        await pilot.pause(0.05)
        if app.state == "done":
            break
    await pilot.pause(0.2)
    assert app.state == "done"


async def _drive_m11(tmp_path, capture) -> None:
    filters = tmp_path / "filters.json"
    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(), files=[str(capture)],
                      filters_path=filters)  # fmt: skip
    async with app.run_test(size=(160, 45)) as pilot:
        await _wait_done(app, pilot)
        total = _rows(app)
        assert app.alerts, "brute-force capture should raise an alert"
        assert "alerts" in str(app.query_one("#status").render())

        # session view: only the selected finding's connection
        table = app.query_one("#table")
        table.move_cursor(row=0)
        first = app._selected()
        await pilot.press("s")
        await pilot.pause()
        assert app.scope is not None and 0 < _rows(app) < total
        pair = {(first.src.ip, first.src.port), (first.dst.ip, first.dst.port)}
        assert all({(f.src.ip, f.src.port), (f.dst.ip, f.dst.port)} == pair for f in app.findings if app._visible(f))
        await pilot.press("escape")
        await pilot.pause()
        assert app.scope is None and _rows(app) == total

        # host drill-down on the server side covers everything here
        await pilot.press("d")
        await pilot.pause()
        assert _rows(app) == total and "host" in app.scope[0]
        await pilot.press("escape")

        # field filters + saving and recalling them
        await pilot.press("slash", *"kind:alert", "enter")
        await pilot.pause()
        assert _rows(app) == len(app.alerts)
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert '"kind:alert"' in filters.read_text(encoding="utf-8")
        await pilot.press("escape")
        await pilot.pause()
        assert _rows(app) == total
        await pilot.press("f")
        await pilot.pause()
        assert app.filter_text == "kind:alert" and _rows(app) == len(app.alerts)
        assert len(app.rates) == 120
        await pilot.press("q")


def test_tui_m11_drilldown_filters_alerts(tmp_path, monkeypatch):
    from netcreds_ng.testing.packets import write_pcap
    from test_detection import attempt

    monkeypatch.chdir(tmp_path)
    capture = tmp_path / "bf.pcap"
    write_pcap(str(capture), [fr for n in range(6) for fr in attempt("192.0.2.30", n, "gina")])
    asyncio.run(_drive_m11(tmp_path, capture))


# --- dashboard v2: inspector, analytics tabs, bookmarks, live-view control, --attach -----------


def _plain(renderable) -> str:
    from rich.console import Console

    console = Console(width=150, record=True, file=io.StringIO())
    console.print(renderable)
    return console.export_text()


def _cell_texts(table) -> list[str]:
    return [str(c) for row in range(table.row_count) for c in table.get_row_at(row)]


async def _drive_v2(tmp_path, capture) -> None:
    from netcreds_ng.tui.inspector import FindingScreen

    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(),
                      files=[str(SYNTHETIC / "ftp_basic.pcap"), str(capture)],
                      filters_path=tmp_path / "filters.json")  # fmt: skip
    async with app.run_test(size=(160, 45)) as pilot:
        await _wait_done(app, pilot)
        table = app.query_one("#table")
        total = _rows(app)

        # the detail pane leads with why the finding matters
        cred = next(i for i, f in enumerate(app.findings) if f.kind.value == "credential")
        table.move_cursor(row=table.get_row_index(str(cred)))
        await pilot.pause()
        assert "why: Sent in cleartext" in str(app.query_one("#detail").render())

        # Enter opens the inspector: reasons, context, related findings; Enter on a related row goes deeper
        await pilot.press("enter")
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, FindingScreen) and screen.index == cred
        why = str(screen.query_one("#insp-why").render())
        assert "Why this matters" in why and "Sent in cleartext" in why and "[analytics]" in why
        assert "exposure score" in str(screen.query_one("#insp-context").render())
        assert screen.related and screen.query_one("#related").row_count == len(screen.related)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, FindingScreen) and app.screen.depth == 2
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is screen

        # bookmark and note from the inspector; m masks inside it too
        await pilot.press("asterisk")
        assert cred in app.marks
        await pilot.press("n", *"call owner", "enter")
        await pilot.pause()
        assert app.marks[cred] == "call owner"
        await pilot.press("m")
        await pilot.pause()
        assert app.mask and "FakePass-123" not in str(screen.query_one("#insp-head").render())
        await pilot.press("m", "escape")
        await pilot.pause()
        assert app.screen is app._main and "✎" in _cell_texts(table)

        # analytics tabs render; number keys switch
        for key, widget in (("3", "#alerts-table"), ("4", "#hosts-table"), ("5", "#services-table"),
                            ("6", "#accounts-table"), ("7", "#bookmarks-table")):  # fmt: skip
            await pilot.press(key)
            await pilot.pause()
            assert app.query_one(widget).row_count >= 1, widget
        assert "call owner" in _cell_texts(app.query_one("#bookmarks-table"))
        assert any("gina" in c for c in _cell_texts(app.query_one("#accounts-table")))
        await pilot.press("2")
        await pilot.pause()
        overview = _plain(app.query_one("#overview").content)
        assert "Exposure" in overview and "Timeline" in overview and "Capture health" in overview
        await pilot.press("8")
        await pilot.pause()
        assert "Capture health:" in str(app.query_one("#health").render())

        # drill down from the hosts tab, and Esc backs out to it
        await pilot.press("4")
        await pilot.pause()
        app.query_one("#hosts-table").move_cursor(row=0)
        await pilot.press("enter")
        await pilot.pause()
        assert app.active_tab() == "findings" and app.scope is not None and "host" in app.scope[0]
        await pilot.press("escape")
        await pilot.pause()
        assert app.active_tab() == "hosts" and app.scope is None

        # an alert opens with its rule and the attempts behind it
        await pilot.press("3", "enter")
        await pilot.pause()
        assert isinstance(app.screen, FindingScreen)
        assert "Rule:" in str(app.screen.query_one("#insp-why").render())
        assert app.screen.related and all(label == "alert attempt" for label, _ in app.screen.related)
        await pilot.press("escape", "1")
        await pilot.pause()

        # freeze holds new rows back and counts them; unfreezing catches up
        await pilot.press("space")
        assert app.frozen
        late = app.findings[0]
        app.findings.append(late)
        app._add_row(late, len(app.findings) - 1)
        app._refresh_status()
        assert _rows(app) == total and app.pending == 1
        assert "FROZEN +1 new" in str(app.query_one("#status").render())
        await pilot.press("space")
        await pilot.pause()
        assert not app.frozen and app.pending == 0 and _rows(app) == total + 1

        # export carries bookmarks and notes
        await pilot.press("e")
        await pilot.pause(0.2)
        await pilot.press("q")
    rows = [json.loads(line) for p in tmp_path.glob("netcreds-export-*.jsonl")
            for line in p.read_text(encoding="utf-8").splitlines()]  # fmt: skip
    assert any(r.get("note") == "call owner" and r.get("bookmarked") for r in rows)


def test_tui_inspector_tabs_bookmarks(tmp_path, monkeypatch):
    from netcreds_ng.testing.packets import write_pcap
    from test_detection import attempt

    monkeypatch.chdir(tmp_path)
    capture = tmp_path / "bf.pcap"
    write_pcap(str(capture), [fr for n in range(6) for fr in attempt("192.0.2.30", n, "gina")])
    asyncio.run(_drive_v2(tmp_path, capture))


async def _drive_attach(tmp_path, db) -> None:
    from netcreds_ng.model import Endpoint, Finding, Kind, RunStats
    from netcreds_ng.plugins.api import SinkContext
    from netcreds_ng.plugins.sinks.sqlite import SqliteSink

    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(), attach=str(db),
                      filters_path=tmp_path / "filters.json")  # fmt: skip
    async with app.run_test(size=(160, 45)) as pilot:
        for _ in range(60):
            await pilot.pause(0.05)
            if app.state == "attached":
                break
        loaded = len(app.findings)
        assert app.state == "attached" and loaded >= 4 and _rows(app) == loaded and app.follow
        assert app.summary()["services"], "analytics are rebuilt from the database"

        # a second, still running netcreds-ng appends to the database: the dashboard follows it
        stats = RunStats(frames=7)
        sink = SqliteSink(str(db), {"commit_interval": 0, "source_label": "eth0"})
        sink.open(SinkContext(stats))
        sink.write(Finding("Telnet", Kind.CREDENTIAL, Endpoint("192.0.2.40", 40000), Endpoint("192.0.2.41", 23),
                           username="dave", secret="FakePass-456", risk="high", tags=["cleartext"]))  # fmt: skip
        for _ in range(60):
            await pilot.pause(0.05)
            if len(app.findings) > loaded and app.state == "following":
                break
        assert len(app.findings) == loaded + 1 and app.findings[-1].username == "dave"
        assert app.state == "following"
        table = app.query_one("#table")
        assert table.cursor_row == table.row_count - 1  # follow mode
        sink.close(stats)
        await pilot.press("8")
        await pilot.pause()
        assert "2 run(s)" in str(app.query_one("#health").render())
        await pilot.press("q")


def test_tui_attach_follows_database(tmp_path, monkeypatch):
    from netcreds_ng.session import Session

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "run.db"
    session = Session(load_registry(use_entry_points=False), SessionConfig(outputs=[("sqlite", str(db))]))
    session.open()
    session.run_files([str(SYNTHETIC / "ftp_basic.pcap"), str(SYNTHETIC / "http_basic.pcap")])
    session.close()
    asyncio.run(_drive_attach(tmp_path, db))


async def _drive_tui_sqlite(tmp_path, db) -> None:
    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(outputs=[("sqlite", str(db))]),
                      files=[str(SYNTHETIC / "ftp_basic.pcap")], filters_path=tmp_path / "filters.json")  # fmt: skip
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait_done(app, pilot)
        assert not app.session.stats.plugin_errors, app.session.errors
        await pilot.press("q")


def test_tui_writes_sqlite_from_the_analysis_thread(tmp_path):
    """--tui --sqlite: the sink is opened on the UI thread and written from the analysis thread."""
    db = tmp_path / "tui.db"
    asyncio.run(_drive_tui_sqlite(tmp_path, db))
    con = sqlite3.connect(db)
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] >= 1
    con.close()
