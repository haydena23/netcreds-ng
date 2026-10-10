"""Headless test of the live findings table (--tui) using Textual's pilot."""

from __future__ import annotations

import asyncio
import sqlite3

from conftest import SYNTHETIC
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import SessionConfig
from netcreds_ng.tui.app import NetcredsApp


def _rows(app: NetcredsApp) -> int:
    return app.query_one("#table").row_count


async def _wait_done(app: NetcredsApp, pilot) -> None:
    for _ in range(100):
        await pilot.pause(0.05)
        if app.state == "done":
            break
    await pilot.pause(0.2)
    assert app.state == "done"


async def _drive(config: SessionConfig) -> NetcredsApp:
    app = NetcredsApp(load_registry(use_entry_points=False), config,
                      files=[str(SYNTHETIC / "ftp_basic.pcap"), str(SYNTHETIC / "http_basic.pcap")])  # fmt: skip
    async with app.run_test(size=(140, 40)) as pilot:
        await _wait_done(app, pilot)
        total = _rows(app)
        assert total == len(app.findings) >= 4
        table = app.query_one("#table")
        assert table.cursor_row == total - 1, "the table follows new findings"

        # the detail pane shows every field of the highlighted finding, secrets as seen
        cred = next(i for i, f in enumerate(app.findings) if f.username == "fakeuser" and f.secret)
        table.move_cursor(row=table.get_row_index(str(cred)))
        await pilot.pause()
        detail = str(app.query_one("#detail").render())
        assert "fakeuser" in detail and "FakePass-123" in detail

        # filter: free text and field:value; Esc clears
        await pilot.press("slash", *"basicuser")
        await pilot.pause()
        assert 1 <= _rows(app) < total
        await pilot.press("escape")
        await pilot.pause()
        assert _rows(app) == total
        await pilot.press("slash", *"proto:ftp", "enter")
        await pilot.pause()
        assert all(app.findings[int(table.coordinate_to_cell_key((r, 0)).row_key.value)].protocol == "FTP"
                   for r in range(_rows(app)))  # fmt: skip
        await pilot.press("escape")

        # pause toggles; status bar reports state and plugin count
        await pilot.press("p")
        await pilot.pause()
        assert app.paused.is_set() and "PAUSED" in str(app.query_one("#status").render())
        await pilot.press("p")
        assert not app.paused.is_set()
        assert f"plugins {len(app.session.protocols)}" in str(app.query_one("#status").render())
        await pilot.press("q")
    return app


def test_tui_table_follow_detail_filter_pause():
    asyncio.run(_drive(SessionConfig()))


def test_tui_respects_plugin_selection():
    app = asyncio.run(_drive(SessionConfig(plugins=["web", "file-transfer"])))
    assert {p.name for p in app.session.protocols} == {"ftp", "http", "http2"}


async def _drive_sqlite(db) -> None:
    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(outputs=[("sqlite", str(db))]),
                      files=[str(SYNTHETIC / "ftp_basic.pcap")])  # fmt: skip
    async with app.run_test(size=(120, 40)) as pilot:
        await _wait_done(app, pilot)
        assert not app.session.stats.plugin_errors, app.session.errors
        await pilot.press("q")


def test_tui_writes_sqlite_from_the_analysis_thread(tmp_path):
    """--tui --sqlite: the sink is opened on the UI thread and written from the analysis thread (E-25)."""
    db = tmp_path / "tui.db"
    asyncio.run(_drive_sqlite(db))
    con = sqlite3.connect(db)
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] >= 1
    con.close()
