"""--legacy must reproduce the original Python 2 net-creds byte for byte.

Goldens were recorded by running the unmodified original under Python 2.7 +
scapy 2.4.4 (tools/make_goldens.py). Synthetic fixtures (fake values only) have
plaintext goldens; third-party captures are compared by SHA-256 only.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from conftest import GOLDEN, REAL_CAPTURES, ROOT, SYNTHETIC_CAPTURES, run_legacy

REAL_GOLDEN = json.loads((GOLDEN / "real.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("capture", SYNTHETIC_CAPTURES, ids=lambda p: p.stem)
def test_synthetic_byte_identical(capture):
    stdout, log = run_legacy(capture)
    assert stdout == (GOLDEN / "synthetic" / f"{capture.stem}.stdout").read_bytes()
    assert log == (GOLDEN / "synthetic" / f"{capture.stem}.log").read_bytes()


@pytest.mark.parametrize("capture", REAL_CAPTURES, ids=lambda p: p.name)
def test_real_capture_digest_identical(capture):
    key = capture.relative_to(ROOT).as_posix()
    expected = REAL_GOLDEN[key]
    stdout, log = run_legacy(capture)
    assert hashlib.sha256(stdout).hexdigest() == expected["stdout_sha256"]
    assert hashlib.sha256(log).hexdigest() == expected["log_sha256"]
    assert stdout.count(b"\n") == expected["lines"]


def test_every_golden_has_a_fixture():
    names = {p.stem for p in SYNTHETIC_CAPTURES}
    goldens = {p.stem for p in (GOLDEN / "synthetic").glob("*.stdout")}
    assert names == goldens
    if REAL_CAPTURES:  # third-party captures are not shipped in the sdist
        assert {c.relative_to(ROOT).as_posix() for c in REAL_CAPTURES} == set(REAL_GOLDEN)


def test_legacy_dedup_against_credentials_txt(tmp_path):
    """Second run in the same directory prints nothing new (original printer() behaviour)."""
    import io

    from netcreds_ng.engine.pcapio import open_capture
    from netcreds_ng.legacy import LegacyNetCreds

    cap = str(ROOT / "tests" / "fixtures" / "synthetic" / "ftp_basic.pcap")
    log = str(tmp_path / "credentials.txt")
    first, second = io.BytesIO(), io.BytesIO()
    LegacyNetCreds(out=first, log_path=log, eol=b"\n").process(open_capture(cap))
    LegacyNetCreds(out=second, log_path=log, eol=b"\n").process(open_capture(cap))
    assert first.getvalue().count(b"\n") == 3
    assert second.getvalue() == b""


def test_legacy_crlf_text_mode_emulation(tmp_path):
    import io

    from netcreds_ng.engine.pcapio import open_capture
    from netcreds_ng.legacy import LegacyNetCreds

    cap = str(ROOT / "tests" / "fixtures" / "synthetic" / "ftp_basic.pcap")
    out = io.BytesIO()
    LegacyNetCreds(out=out, log_path=str(tmp_path / "c.txt"), eol=b"\r\n").process(open_capture(cap))
    lf = io.BytesIO()
    LegacyNetCreds(out=lf, log_path=str(tmp_path / "d.txt"), eol=b"\n").process(open_capture(cap))
    assert out.getvalue().replace(b"\r\n", b"\n") == lf.getvalue()
    assert b"\r\n" in out.getvalue()
