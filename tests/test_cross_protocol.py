"""With every plugin enabled, each fixture must only trigger the plugins that own its protocol."""

from __future__ import annotations

import pytest

from conftest import SYNTHETIC
from netcreds_ng.testing.harness import analyze

EXPECTED_PLUGINS = {
    "ftp_basic": {"ftp"},
    "ftp_nonstd_port": {"ftp"},
    "telnet_charbychar": {"telnet"},
    "irc_identify": {"irc"},
    "smtp_auth_login": {"mail"},
    "smtp_auth_plain": {"mail"},
    "pop3_userpass": {"mail"},
    "imap_login": {"mail"},
    "http_basic": {"http"},
    "http_form": {"http"},
    "http_search_url": {"http"},
    "http_ntlm": {"http"},
    "smb_ntlm_raw": {"ntlm"},
    "kerberos_udp_tcp": {"kerberos"},
    "snmp_communities": {"snmp"},
    "ipv6_ftp": {"ftp"},
    "vlan_ftp": {"ftp"},
    "ooo_retrans_ftp": {"ftp"},
    "http_chunked_json": {"http"},
    "noise": set(),
}


@pytest.mark.parametrize("name", sorted(EXPECTED_PLUGINS))
def test_only_owning_plugins_fire(name):
    findings = analyze(str(SYNTHETIC / f"{name}.pcap"), enable=["all"], enrichers=[])
    assert {f.plugin for f in findings} == EXPECTED_PLUGINS[name]


def test_expected_table_covers_all_fixtures():
    assert set(EXPECTED_PLUGINS) == {p.stem for p in SYNTHETIC.glob("*.pcap")}
