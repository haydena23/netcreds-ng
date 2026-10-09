"""Explanations: every tag the built-in code can set is described, and reasons never leak secrets."""

from __future__ import annotations

import re
from pathlib import Path

from netcreds_ng.explain import SECRET_PROVIDERS, explain, headline, known_tags, tag_info
from netcreds_ng.model import Endpoint, Finding, Kind

SRC = Path(__file__).resolve().parents[1] / "src" / "netcreds_ng"
TAG_LINE = re.compile(r"\b(tags|more|all_tags)\b")
LITERAL = re.compile(r"(?<![\w.])f?\"([a-z0-9][a-z0-9.-]*-[a-z0-9.{}-]*|[a-z0-9]{2,})\"")
# String literals on tag-handling lines that are not tags (dict keys, option names, values).
NOT_TAGS = {"full", "strict", "phase", "outcome", "command", "detection", "note", "frames", "attempts", "users",
            "clients", "window", "version", "pdu", "service", "args", "plugin", "database", "encryption",
            "server_version", "session_id", "packet_type", "minor_version", "priv_lvl", "authen_type", "info",
            "low", "medium", "high", "pass", "user", "ascii", "utf-8", "secret", "username", "domain", "value",
            "risk", "kind", "protocol", "confidence", "extra", "tags", "mask", "summary"}  # fmt: skip


def _tag_literals() -> dict[str, list[str]]:
    """Tag-like string literals on lines that build tag lists, per tag -> files."""
    found: dict[str, list[str]] = {}
    files = [*sorted((SRC / "plugins" / "protocols").glob("*.py")), *sorted((SRC / "plugins" / "enrichers").glob("*.py")),
             SRC / "engine" / "engine.py"]  # fmt: skip
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not TAG_LINE.search(line) or line.lstrip().startswith("#"):
                continue
            for lit in LITERAL.findall(line):
                if lit in NOT_TAGS:
                    continue
                found.setdefault(lit, []).append(path.name)
    return found


def test_every_builtin_tag_is_explained():
    missing = {}
    for lit, where in _tag_literals().items():
        if "{" in lit:  # f-string tag: some explained tag (or prefix rule) must start with its fixed part
            prefix = lit.split("{")[0]
            if tag_info(prefix + "x") is None and not any(t.startswith(prefix) for t in known_tags()):
                missing[lit] = where
            continue
        if tag_info(lit) is None:
            missing[lit] = where
    assert not missing, f"tags without an explanation in netcreds_ng.explain: {missing}"


def test_dynamic_tags_are_explained():
    from netcreds_ng.plugins.protocols import kerberos, secrets

    for provider, _rx in secrets._SIMPLE.values():
        assert provider in SECRET_PROVIDERS
    for provider in ("aws", "azure", "gcp", "pem"):
        assert tag_info(provider) is not None
    for etype in kerberos.WEAK:
        assert tag_info(f"weak-preauth-{kerberos.etype_name(etype)}") is not None
    for level in ("noAuthNoPriv", "authNoPriv", "invalid"):
        assert tag_info(f"snmpv3-{level}") is not None
    for ms in ("MS-CHAP", "MS-CHAPv2"):
        assert tag_info(ms.lower()) is not None
    for detection in ("brute-force", "password-spraying", "targeted-account", "login-after-failures"):
        assert tag_info(detection) is not None
    assert {"cleartext", "weak-password", "password-reuse", "tls-decrypted"} <= known_tags()


def _cred(secret: str, tags: list[str]) -> Finding:
    return Finding("FTP", Kind.CREDENTIAL, Endpoint("192.0.2.10", 50000), Endpoint("192.0.2.20", 21),
                   username="alice", secret=secret, risk="high", tags=tags, plugin="ftp")  # fmt: skip


def test_reasons_never_contain_the_secret():
    f = _cred("FakePass-123", ["cleartext", "weak-password", "password-reuse", "nonstandard-port"])
    text = " ".join(r.title + " " + r.detail for r in explain(f, frozenset({"fakepass-123"})))
    assert "FakePass-123" not in text and "fakepass-123" not in text
    assert "common passwords" in text


def test_weak_password_rule_is_named():
    short = explain(_cred("abc", ["weak-password"]))
    assert any("3 characters" in r.detail for r in short)
    unknown = explain(_cred("Zz9!long-enough", ["weak-password"]))  # no list given: generic text
    assert any("common passwords" in r.detail for r in unknown)


def test_alert_reason_states_the_rule():
    alert = Finding("FTP", Kind.ALERT, Endpoint("192.0.2.30", 0), Endpoint("192.0.2.20", 21), risk="high",
                    plugin="detection", value="Brute force: 6 failed logins", tags=["brute-force"],
                    extra={"detection": "brute-force", "attempts": 6, "window_seconds": 300.0, "frames": [1, 2]})  # fmt: skip
    reasons = explain(alert, thresholds={"bruteforce": 5, "window": 300.0})
    assert reasons[0].source == "kind"
    rule = reasons[1]
    assert rule.title == "Brute force" and "at least 5 failures" in rule.detail and "300s" in rule.detail
    assert len(reasons) == 2  # the detection tag is not repeated


def test_unknown_tag_and_low_confidence():
    f = Finding("X", Kind.TOKEN, Endpoint("192.0.2.1", 1), Endpoint("192.0.2.2", 2), plugin="thirdparty",
                tags=["vendor-thing"], confidence=0.5)  # fmt: skip
    reasons = explain(f)
    assert any("thirdparty" in r.detail for r in reasons)
    assert any(r.title.startswith("Confidence 50%") for r in reasons)
    assert "Tag 'vendor-thing'" in headline(f)


def test_headline_without_tags_uses_kind():
    f = Finding("HTTP", Kind.URL, Endpoint("192.0.2.1", 1), Endpoint("192.0.2.2", 80), value="http://example.test/")
    assert headline(f).startswith("A URL")
