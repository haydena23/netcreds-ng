"""Dashboard filter expressions."""

from __future__ import annotations

import pytest

from netcreds_ng.model import Endpoint, Finding, Kind
from netcreds_ng.tui.filters import FilterError, parse_filter


def f(**kw):
    base = dict(protocol="FTP", kind=Kind.CREDENTIAL, src=Endpoint("192.0.2.10", 40000),
                dst=Endpoint("198.51.100.20", 21), username="alice", secret="x", risk="high", plugin="ftp",
                tags=["cleartext", "weak-password"])  # fmt: skip
    base.update(kw)
    return Finding(**base)


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("", True), ("alice", True), ("bob", False), ("proto:ftp", True), ("proto:http", False),
        ("kind:credential", True), ("kind:auth-result", False), ("risk:high", True), ("risk:medium", False),
        ("risk:medium+", True), ("host:192.0.2.", True), ("host:203.0.113.", False), ("dst::21", True),
        ("src::21", False), ("port:21", True), ("port:22", False), ("user:ali", True), ("tag:weak", True),
        ("plugin:ftp", True), ("-tag:weak", False), ("-proto:http alice", True), ("proto:", True),
        ("unknownfield:x", False),  # not a field: treated as free text
    ],
)
def test_filter_terms(expr, expected):
    assert parse_filter(expr)(f()) is expected


def test_domain_user_and_risk_order():
    assert parse_filter(r"user:corp\al")(f(domain="CORP"))
    assert not parse_filter("risk:high")(f(risk="low"))
    assert parse_filter("risk:low+")(f(risk="medium"))


@pytest.mark.parametrize("bad", ["risk:severe", "port:abc"])
def test_bad_values_raise(bad):
    with pytest.raises(FilterError):
        parse_filter(bad)
