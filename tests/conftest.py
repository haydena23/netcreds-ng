"""Shared test fixtures and paths."""

from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC = ROOT / "tests" / "fixtures" / "synthetic"
GOLDEN = ROOT / "tests" / "golden" / "legacy"
REAL_DIR = ROOT / "test"

SYNTHETIC_CAPTURES = sorted(SYNTHETIC.glob("*.pcap"))
REAL_CAPTURES = sorted(p for p in REAL_DIR.rglob("*") if p.suffix in (".pcap", ".pcapng", ".cap"))


def run_legacy(capture: Path) -> tuple[bytes, bytes]:
    """Run the --legacy engine on a capture in an isolated directory; return (stdout, credentials.txt)."""
    from netcreds_ng.engine.pcapio import open_capture
    from netcreds_ng.legacy import LegacyNetCreds

    with tempfile.TemporaryDirectory() as d:
        out = io.BytesIO()
        log = os.path.join(d, "credentials.txt")
        LegacyNetCreds(out=out, log_path=log, eol=b"\n").process(open_capture(str(capture)))
        with open(log, "rb") as fh:
            return out.getvalue(), fh.read()


@pytest.fixture
def synthetic() -> Path:
    return SYNTHETIC
