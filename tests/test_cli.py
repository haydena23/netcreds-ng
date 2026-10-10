"""End-to-end CLI behaviour (run in-process through main(), and once as a real subprocess)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys

import pytest

import netcreds_ng.session as session_mod
from conftest import GOLDEN, ROOT, SYNTHETIC
from netcreds_ng import __version__
from netcreds_ng.cli import EXIT_ERROR, EXIT_OK, EXIT_WARNINGS, main

FTP = str(SYNTHETIC / "ftp_basic.pcap")
_SESSION_INIT = session_mod.Session.__init__


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"netcreds-ng {__version__}"


def test_help_mentions_original_flags(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for flag in ("-p", "-i", "-f", "-v", "--legacy", "--jsonl", "--plugins", "--tui"):
        assert flag in out


def test_pcap_console_output_and_summary(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["-p", FTP, "--no-tui"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "fakeuser:FakePass-123" in out
    assert "Run summary" in out
    assert not (tmp_path / "credentials.txt").exists(), "only --legacy writes credentials.txt"


@pytest.mark.parametrize("flag", ["--mask", "--html=r.html", "--attach=run.db"])
def test_removed_options_are_usage_errors(flag):
    with pytest.raises(SystemExit) as exc:
        main(["-p", FTP, flag])
    assert exc.value.code == 2


def test_outputs_jsonl_csv_sqlite(tmp_path):
    j, c, d = (tmp_path / n for n in ("o.jsonl", "o.csv", "o.db"))
    rc = main(["-p", str(SYNTHETIC), "-q", "--jsonl", str(j), "--csv", str(c), "--sqlite", str(d)])
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
    assert "unknown plugin(s) or set(s): nosuchplugin" in err
    assert "Traceback" not in err


def test_list_plugins(capsys):
    assert main(["--list-plugins"]) == EXIT_OK
    out = capsys.readouterr().out
    for name in ("ftp", "http", "kerberos", "ldap", "mysql", "postgres", "redis", "sip", "vnc", "mqtt", "jsonl"):
        assert name in out
    assert "Plugin sets" in out
    for name in ("databases", "legacy", "remote-access", "default"):
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
        [sys.executable, "-B", "-m", "netcreds_ng", "-p", FTP, "--jsonl", "-"],
        capture_output=True, text=True, encoding="utf-8", cwd=tmp_path, timeout=120,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert any(json.loads(line).get("username") == "fakeuser" for line in proc.stdout.splitlines() if line.startswith("{"))
    assert str(ROOT) not in proc.stderr


def _protocols_run(monkeypatch, argv: list[str]) -> list[str]:
    """Run main() with ``argv`` and return the names of the protocol plugins the session used."""
    seen: list[str] = []
    real = _SESSION_INIT

    def spy(self, *a, **k):  # type: ignore[no-untyped-def]
        real(self, *a, **k)
        seen.extend(sorted(p.name for p in self.protocols))

    monkeypatch.setattr(session_mod.Session, "__init__", spy)
    assert main(["-p", FTP, "-q", *argv]) == EXIT_OK
    return seen


def test_plugins_selects_only_named_plugins_and_sets(monkeypatch):
    assert _protocols_run(monkeypatch, ["-P", "ftp"]) == ["ftp"]
    assert _protocols_run(monkeypatch, ["--plugins", "databases,ftp"]) == ["ftp", "mssql", "mysql", "oracle",
                                                                            "postgres", "redis"]  # fmt: skip
    assert _protocols_run(monkeypatch, ["-P", "legacy", "--disable", "keyvalue,web"]) == [
        "ftp", "irc", "kerberos", "mail", "ntlm", "snmp", "telnet"]  # fmt: skip
    everything = _protocols_run(monkeypatch, [])
    assert "ftp" in everything and "mysql" in everything
    assert "http" not in _protocols_run(monkeypatch, ["--disable", "web"])
    assert _protocols_run(monkeypatch, ["-P", "all"]) == everything  # no opt-in built-ins today


def test_plugins_selection_finds_only_what_was_asked(capsys):
    assert main(["-p", FTP, "-P", "databases"]) == EXIT_OK
    assert "fakeuser" not in capsys.readouterr().out
    assert main(["-p", FTP, "-P", "file-transfer"]) == EXIT_OK
    assert "fakeuser:FakePass-123" in capsys.readouterr().out


@pytest.mark.parametrize(("argv", "message"), [
    (["-P", "nosuch"], "unknown plugin(s) or set(s): nosuch"),
    (["-P", "detection"], "not protocol plugins: detection"),
    (["-P", "ftp", "--disable", "ftp"], "leaves no protocol plugins"),
    (["-P", ","], "needs at least one plugin or set name"),  # M31 validation F1: not "everything"
    (["-P", ""], "needs at least one plugin or set name"),
])  # fmt: skip
def test_plugins_selection_errors(capsys, argv, message):
    with pytest.raises(SystemExit) as exc:
        main(["-p", FTP, *argv])
    assert exc.value.code == 2 and message in capsys.readouterr().err


def test_plugins_not_allowed_with_legacy(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--legacy", "-p", FTP, "-P", "ftp"])
    assert exc.value.code == 2 and "do not apply to --legacy" in capsys.readouterr().err


def test_config_select_and_user_sets(tmp_path, monkeypatch, capsys):
    (tmp_path / "netcreds-ng.toml").write_text(
        '[plugins]\nselect = ["mine"]\n\n[sets]\nmine = ["file-transfer", "telnet"]\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert _protocols_run(monkeypatch, []) == ["ftp", "telnet"]
    assert _protocols_run(monkeypatch, ["-P", "mine,redis"]) == ["ftp", "redis", "telnet"]  # -P overrides select
    capsys.readouterr()
    assert main(["--list-plugins"]) == EXIT_OK
    assert "your set (config file)" in capsys.readouterr().out


def test_user_set_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "netcreds-ng.toml"
    for body, message in (('ftp = ["telnet"]', "same name as a plugin"),
                          ('a = ["b"]\nb = ["a"]', "cycle"),
                          ('x = ["nosuch"]', "unknown protocol plugin or set 'nosuch'")):  # fmt: skip
        cfg.write_text("[sets]\n" + body + "\n", encoding="utf-8")
        with pytest.raises(SystemExit):
            main(["-p", FTP, "-q"])
        assert message in capsys.readouterr().err


def test_removed_config_keys_are_reported(tmp_path, monkeypatch, capsys):
    (tmp_path / "netcreds-ng.toml").write_text('[output]\nmask = true\nhtml = "r.html"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["-p", FTP]) == EXIT_OK
    out, err = capsys.readouterr()
    assert "[output] mask, html in the config file is no longer supported" in err
    assert "fakeuser:FakePass-123" in out and not (tmp_path / "r.html").exists()
