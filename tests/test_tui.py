"""Headless TUI test using Textual's pilot."""

from __future__ import annotations

import asyncio

from conftest import SYNTHETIC
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import SessionConfig
from netcreds_ng.tui.app import NetcredsApp


def _rows(app: NetcredsApp) -> int:
    return app.query_one("#table").row_count


async def _drive(tmp_path) -> None:
    app = NetcredsApp(load_registry(use_entry_points=False), SessionConfig(),
                      files=[str(SYNTHETIC / "ftp_basic.pcap"), str(SYNTHETIC / "http_basic.pcap")])  # fmt: skip
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
