"""tools/corpus.py: manifest, tshark row parsing and comparison (no network, no tshark needed)."""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from pathlib import Path

from conftest import ROOT

_spec = importlib.util.spec_from_file_location("corpus", ROOT / "tools" / "corpus.py")
assert _spec is not None and _spec.loader is not None
corpus = importlib.util.module_from_spec(_spec)
sys.modules["corpus"] = corpus  # dataclasses look the module up while it executes
_spec.loader.exec_module(corpus)


def row(**values: list[str]) -> dict[str, list[str]]:
    r = {f: [] for f in corpus.FIELDS}
    for key, v in values.items():
        r[key.replace("__", ".")] = v
    return r


def test_manifest_is_well_formed():
    with open(ROOT / "tools" / "corpus.toml", "rb") as fh:
        entries = tomllib.load(fh)["capture"]
    names = [e["name"] for e in entries]
    assert len(names) == len(set(names)), "duplicate names"
    by_name = {e["name"]: e for e in entries}
    for e in entries:
        assert e["url"].startswith("https://"), e["name"]
        assert len(e["sha256"]) == 64 and int(e["sha256"], 16) >= 0, e["name"]
        assert e["size"] > 0 and e["license"], e["name"]
        assert e.get("kind", "capture") in ("capture", "keylog"), e["name"]
        if "keylog" in e:
            assert by_name[e["keylog"]].get("kind") == "keylog", e["name"]
        if "zeek/zeek/" in e["url"] or "wireshark/wireshark/-/raw/" in e["url"]:
            assert "/master/" not in e["url"] and "/main/" not in e["url"], "pin repository files to a commit"


def test_corpus_directory_inside_repository_is_refused(tmp_path):
    assert corpus.fetch([], ROOT / "corpus-here") == 1
    assert corpus.fetch([], tmp_path) == 0


def test_unescape_tshark_fields():
    assert corpus._unescape(r"FTBCO\\A70") == "FTBCO\\A70"
    assert corpus._unescape(r"a\tb\x41\a") == "a\tbA\a"
    assert corpus._unescape("plain") == "plain"
    assert corpus._unescape("trailing\\") == "trailing\\"


def test_identities_from_rows():
    rows = [
        row(ftp__request__command=["USER"], ftp__request__arg=["fakeuser"]),
        row(ftp__request__command=["PASS"], ftp__request__arg=["Fake-Pass"]),
        row(http__authbasic=["webuser:Fake-Web-Pass"]),
        row(http__authorization=['Digest username="digestuser", realm="x"']),
        row(smtp__auth__username=["bWFpbHVzZXJAZXhhbXBsZS50ZXN0"]),  # base64 of mailuser@example.test
        row(ldap__protocolOp=["0"], ldap__name=["cn=fake,dc=example,dc=test"]),
        row(ldap__protocolOp=["3"], ldap__name=["dc=search,dc=only"]),  # a search, not a bind
        row(kerberos__msg_type=["10"], kerberos__CNameString=["krbuser"]),
        row(kerberos__msg_type=["12"], kerberos__CNameString=["tgsonly"]),
        row(ntlmssp__messagetype=["0x00000003"], ntlmssp__auth__username=["ntlmuser", "NULL"]),
        row(pgsql__parameter_name=["user", "database"], pgsql__parameter_value=["pguser", "db"]),
        row(snmp__community=["fake-community"]),
        row(rdp__rt_cookie=["Cookie: mstshash=rdpuser"]),
        row(tns__connect_data=["(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=x)(USER=osuser))))"]),
        row(http2__header__name=[":method", "authorization"], http2__header__value=["GET", "Basic aDJ1c2VyOkZha2U="]),
    ]
    ids = corpus.identities_from_rows(rows)
    assert ids == {
        ("ftp", "fakeuser"), ("http-basic", "webuser"), ("http-digest", "digestuser"),
        ("smtp", "mailuser@example.test"), ("ldap-bind", "cn=fake,dc=example,dc=test"), ("kerberos", "krbuser"),
        ("ntlm", "ntlmuser"), ("postgres", "pguser"), ("snmp-community", "fake-community"), ("rdp", "rdpuser"),
        ("oracle-connect", "osuser"), ("http2-basic", "h2user"),
    }  # fmt: skip
    assert not any("Fake" in v for _, v in ids), "passwords are never extracted"


def test_compare_categories():
    ng = [
        ("FTP", frozenset({"fakeuser"})),
        ("NTLM", frozenset({"admin", "corp\\admin", "admin@corp"})),
        ("LDAP", frozenset({"cn=svc,dc=example,dc=test"})),
        ("MySQL", frozenset({"onlyng"})),
        ("IRC", frozenset({"nick"})),
        ("SNMP", frozenset({"fake-community"})),
    ]
    ts = {("ftp", "FakeUser"), ("ntlm", "CORP\\admin"), ("ldap-bind", "svc"), ("radius", "nobody"),
          ("snmp-community", "fake-community")}  # fmt: skip
    cmp = corpus.compare(ts, ng, {"fake-community"})
    assert sorted(cmp.matched) == [("ftp", "FakeUser"), ("ntlm", "CORP\\admin"), ("snmp-community", "fake-community")]
    assert cmp.partial == [("ldap-bind", "svc", "cn=svc,dc=example,dc=test")]
    assert cmp.missed == [("radius", "nobody")]
    assert cmp.extra == ["MySQL: onlyng"]
    assert cmp.unreferenced == ["IRC: nick"]


def test_secrets_are_masked_in_report_rows():
    assert corpus.show("snmp-community", "fake-community") != "fake-community"
    assert corpus.show("ftp", "fakeuser") == "fakeuser"


def test_write_report(tmp_path: Path):
    rows = [{
        "name": "x/a.pcap", "expected_plugins": ["ftp"], "notes": "", "findings": 2, "by_plugin": {"ftp": 2},
        "by_kind": {}, "plugin_errors": {}, "source_errors": [], "errors": [], "frames": 10, "tls": None,
        "health": {"status": "good", "issues": [], "verdict": "good: no capture problems detected"},
        "tshark": {"matched": ["ftp: fakeuser"], "partial": [], "missed": [], "extra": [], "unreferenced": []},
    }]  # fmt: skip
    report = corpus.write_report(rows, tmp_path, ["ftp", "telnet"])
    text = report.read_text(encoding="utf-8")
    assert "| ftp | 1 |" in text and "| telnet | 0 |" in text
    assert "1 matched, 0 partial, 0 missed" in text
    assert (tmp_path / "corpus-report.json").is_file()
