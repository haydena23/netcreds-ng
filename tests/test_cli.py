"""End-to-end CLI behaviour (run in-process through main(), and once as a real subprocess)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys

import pytest

from conftest import GOLDEN, ROOT, SYNTHETIC
from netcreds_ng import __version__
from netcreds_ng.cli import EXIT_ERROR, EXIT_OK, EXIT_WARNINGS, main

FTP = str(SYNTHETIC / "ftp_basic.pcap")


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"netcreds-ng {__version__}"


def test_help_mentions_original_flags(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for flag in ("-p", "-i", "-f", "-v", "--legacy", "--html", "--jsonl"):
        assert flag in out


def test_pcap_console_output_and_summary(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["-p", FTP, "--no-tui"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "fakeuser:FakePass-123" in out
    assert "Run summary" in out
    assert not (tmp_path / "credentials.txt").exists(), "only --legacy writes credentials.txt"


def test_mask_hides_secrets(capsys):
    assert main(["-p", FTP, "--no-tui", "--mask"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "FakePass-123" not in out and "F**********3 (12)" in out


def test_outputs_jsonl_csv_sqlite_html(tmp_path):
    j, c, d, h = (tmp_path / n for n in ("o.jsonl", "o.csv", "o.db", "r.html"))
    rc = main(["-p", str(SYNTHETIC), "-q", "--jsonl", str(j), "--csv", str(c), "--sqlite", str(d), "--html", str(h)])
    assert rc == EXIT_OK
    rows = [json.loads(line) for line in j.read_text(encoding="utf-8").splitlines()]
    assert any(r.get("username") == "fakeuser" and r.get("secret") == "FakePass-123" for r in rows)
    assert all("timestamp" in r and "risk" in r for r in rows)
    header = c.read_text(encoding="utf-8").splitlines()[0]
    assert header.startswith("timestamp,protocol,kind,risk")
    con = sqlite3.connect(d)
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == len(rows)
    assert con.execute("SELECT findings FROM runs").fetchone()[0] == len(rows)
    con.close()
    report = h.read_text(encoding="utf-8")
    assert "<title>Credential Exposure Report</title>" in report
    assert "FakePass-123" not in report, "HTML reports mask secrets by default"


def test_html_report_escapes_markup(tmp_path):
    from netcreds_ng.testing.packets import TCPConversation, write_pcap

    conv = TCPConversation("192.0.2.1", 50000, "198.51.100.1", 21).handshake()
    conv.server(b"220 x\r\n").client(b"USER <script>alert(1)</script>\r\nPASS x\r\n").close()
    cap = tmp_path / "xss.pcap"
    write_pcap(str(cap), conv.frames)
    report = tmp_path / "r.html"
    assert main(["-p", str(cap), "-q", "--html", str(report)]) == EXIT_OK
    text = report.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in text and "&lt;script&gt;" in text


def test_missing_capture(capsys):
    assert main(["-p", "does-not-exist.pcap", "--no-tui"]) == EXIT_ERROR
    assert "capture not found" in capsys.readouterr().err


@pytest.mark.parametrize("content", [b"", b"not a capture file at all"])
def test_unreadable_capture_reports_error(tmp_path, capsys, content):
    p = tmp_path / "bad.pcap"
    p.write_bytes(content)
    assert main(["-p", str(p), "--no-tui"]) == EXIT_ERROR
    assert "bad.pcap" in capsys.readouterr().out


def test_strict_mode_exit_code(tmp_path):
    good = SYNTHETIC / "ftp_basic.pcap"
    bad = tmp_path / "trunc.pcap"
    bad.write_bytes(good.read_bytes()[:-10])
    assert main(["-p", str(bad), "-q"]) == EXIT_OK
    assert main(["-p", str(bad), "-q", "--strict"]) == EXIT_WARNINGS


def test_filter_excludes_hosts(capsys):
    assert main(["-p", FTP, "--no-tui", "-f", "198.51.100.20"]) == EXIT_OK
    assert "fakeuser" not in capsys.readouterr().out


def test_disable_and_unknown_plugin(capsys):
    assert main(["-p", FTP, "--no-tui", "--disable", "ftp"]) == EXIT_OK
    assert "fakeuser" not in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["-p", FTP, "--no-tui", "-o", "nosuchformat:x"])


@pytest.mark.parametrize("flag", ["--enable", "--disable"])
def test_unknown_plugin_name_is_usage_error(capsys, flag):
    with pytest.raises(SystemExit) as exc:
        main(["-p", FTP, "--no-tui", flag, "ftp,nosuchplugin"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "unknown plugin(s): nosuchplugin" in err
    assert "Traceback" not in err


def test_list_plugins(capsys):
    assert main(["--list-plugins"]) == EXIT_OK
    out = capsys.readouterr().out
    for name in ("ftp", "http", "kerberos", "ldap", "mysql", "postgres", "redis", "sip", "vnc", "mqtt", "jsonl", "html"):
        assert name in out


def test_config_file_and_plugin_option(tmp_path, monkeypatch, capsys):
    (tmp_path / "netcreds-ng.toml").write_text('[plugins]\ndisable = ["ftp"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["-p", FTP, "--no-tui"]) == EXIT_OK
    assert "fakeuser" not in capsys.readouterr().out


def test_legacy_mode_matches_golden(tmp_path, monkeypatch, capfdbinary):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("netcreds_ng.legacy.EOL", b"\n")
    assert main(["--legacy", "-p", FTP]) == EXIT_OK
    out = capfdbinary.readouterr().out
    assert out.replace(b"\r\n", b"\n") == (GOLDEN / "synthetic" / "ftp_basic.stdout").read_bytes()
    assert (tmp_path / "credentials.txt").exists()


def test_legacy_missing_file(capsys):
    assert main(["--legacy", "-p", "nope.pcap"]) == EXIT_ERROR
    assert "[-] Could not open nope.pcap" in capsys.readouterr().err


def test_installed_entry_point_subprocess(tmp_path):
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "netcreds_ng", "-p", FTP, "--no-tui", "--mask", "--jsonl", "-"],
        capture_output=True, text=True, cwd=tmp_path, timeout=120,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert any(json.loads(line).get("username") == "fakeuser" for line in proc.stdout.splitlines() if line.startswith("{"))
    assert str(ROOT) not in proc.stderr
