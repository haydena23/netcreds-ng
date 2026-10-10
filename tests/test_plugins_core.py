"""Exact expected findings for each synthetic fixture (all values are fake)."""

from __future__ import annotations

import pytest

from conftest import SYNTHETIC
from netcreds_ng.model import Kind
from netcreds_ng.testing.harness import analyze
from netcreds_ng.testing.packets import TCPConversation

C, S = "192.0.2.10", "198.51.100.20"


def run(name: str, **kw):
    return analyze(str(SYNTHETIC / f"{name}.pcap"), enrichers=[], **kw)


def creds(findings):
    return sorted(
        (f.protocol, f.kind.value, f.username, f.secret)
        for f in findings
        if f.kind in (Kind.CREDENTIAL, Kind.PASSWORD, Kind.USERNAME, Kind.TOKEN, Kind.API_KEY, Kind.COOKIE, Kind.COMMUNITY)
    )


def results(findings):
    return [(f.protocol, f.value) for f in findings if f.kind is Kind.AUTH_RESULT]


def test_ftp_basic():
    f = run("ftp_basic")
    assert creds(f) == [("FTP", "credential", "fakeuser", "FakePass-123")]
    cred = next(x for x in f if x.kind is Kind.CREDENTIAL)
    assert (str(cred.src), str(cred.dst), cred.risk, cred.tags) == (f"{C}:50000", f"{S}:21", "high", [])
    assert results(f) == [("FTP", "login succeeded")]


def test_ftp_nonstandard_port_and_failure():
    f = run("ftp_nonstd_port")
    cred = next(x for x in f if x.kind is Kind.CREDENTIAL)
    assert (cred.username, cred.secret, cred.tags) == ("nonstd", "Nonstd-Pass-9", ["nonstandard-port"])
    assert results(f) == [("FTP", "login failed")]


def test_telnet_char_by_char_with_options_and_echo():
    f = run("telnet_charbychar")
    assert creds(f) == [("Telnet", "credential", "telnetuser", "Telnet-Fake-1")]


def test_irc_server_password_nick_and_nickserv():
    f = run("irc_identify")
    assert creds(f) == [
        ("IRC", "credential", "fakenick", "Irc-Fake-Pass"),
        ("IRC", "password", None, "fake-server-pass"),
        ("IRC", "username", "fakenick", None),
    ]
    assert not [x for x in f if x.protocol == "FTP"], "FTP plugin must not claim IRC traffic"


def test_smtp_auth_login_success():
    f = run("smtp_auth_login")
    assert creds(f) == [("SMTP", "credential", "smtpuser@example.com", "Smtp-Fake-Pass")]
    assert results(f) == [("SMTP", "login succeeded")]


def test_smtp_auth_plain_failure():
    f = run("smtp_auth_plain")
    assert creds(f) == [("SMTP", "credential", "plainuser", "Plain-Fake-Pass")]
    assert results(f) == [("SMTP", "login failed")]


def test_pop3_user_pass():
    f = run("pop3_userpass")
    assert creds(f) == [("POP3", "credential", "popuser", "Pop-Fake-Pass")]
    assert results(f) == [("POP3", "login succeeded")]


def test_imap_login_quoted_password():
    f = run("imap_login")
    assert creds(f) == [("IMAP", "credential", "imapuser", "Imap Fake Pass")]
    assert results(f) == [("IMAP", "login succeeded")]


def test_http_basic_auth():
    f = run("http_basic")
    assert creds(f) == [("HTTP", "credential", "basicuser", "Basic-Fake-Pass")]
    url = next(x for x in f if x.kind is Kind.URL)
    assert url.value == "GET www.example.com/admin"
    assert results(f) == [("HTTP", "Basic login succeeded (HTTP 200)")]


def test_http_form_login():
    f = run("http_form")
    assert creds(f) == [("HTTP", "credential", "formuser", "Form-Fake-Pass")]
    post = next(x for x in f if x.kind is Kind.POST)
    assert post.value == "username=formuser&password=Form-Fake-Pass&remember=1"


def test_http_search_and_static_filter():
    f = run("http_search_url")
    assert [x.value for x in f if x.kind is Kind.SEARCH] == ["fake search terms"]
    urls = [x.value for x in f if x.kind is Kind.URL]
    assert urls == ["GET search.example.com/search?q=fake+search+terms"]  # logo.png filtered


def test_http_ntlm_reports_auth_event_without_response_material():
    f = run("http_ntlm")
    events = [x for x in f if x.kind is Kind.AUTH_EVENT]
    assert len(events) == 1
    ev = events[0]
    assert (ev.protocol, ev.username, ev.domain, ev.value) == ("HTTP", "ntlmuser", "FAKEDOM", "NTLMv2 authentication over HTTP")
    assert ev.extra["workstation"] == "FAKEWS" and ev.secret is None
    assert "bbbb" not in repr(ev.to_dict()), "challenge/response bytes must never be reported"


def test_raw_smb_ntlmv1_is_high_risk():
    f = run("smb_ntlm_raw")
    (ev,) = [x for x in f if x.kind is Kind.AUTH_EVENT]
    assert (ev.protocol, ev.username, ev.domain, ev.risk, ev.tags) == ("NTLM", "smbuser", "FAKEDOM", "high", ["ntlmv1"])
    assert ev.extra["target"] == "FAKEDOM" and len(ev.extra["event_id"]) == 16


def test_kerberos_hygiene():
    f = run("kerberos_udp_tcp")
    events = sorted((x.username, x.value, x.risk) for x in f if x.kind is Kind.AUTH_EVENT)
    assert events == [
        ("aesuser", "Kerberos pre-authentication (aes256-cts-hmac-sha1-96)", "low"),
        ("krbuser", "Kerberos pre-authentication (rc4-hmac)", "medium"),
        ("krbuser", "service ticket for cifs/fs1.example.test issued with rc4-hmac", "medium"),
        ("nopreauth", "AS-REP issued without pre-authentication", "high"),
        ("tcpuser", "Kerberos pre-authentication (rc4-hmac)", "medium"),
    ]
    assert results(f) == [("Kerberos", "pre-authentication failed (wrong password)")]
    assert all(x.domain == "EXAMPLE.TEST" for x in f)
    assert all("eeee" not in repr(x.to_dict()) for x in f), "encrypted parts must never be reported"


def test_snmp_communities_and_v3_levels():
    f = run("snmp_communities")
    comm = sorted((x.secret, x.extra["version"], x.extra["pdu"], tuple(x.tags)) for x in f if x.kind is Kind.COMMUNITY)
    assert comm == [
        ("fake-community", "v2c", "GetRequest", ()),
        ("public", "v1", "SetRequest", ("write-access", "default-community")),
    ]
    v3 = sorted((x.username, x.value, x.risk) for x in f if x.kind is Kind.AUTH_EVENT)
    assert v3 == [("v3authpriv", "SNMPv3 authPriv", "info"), ("v3noauth", "SNMPv3 noAuthNoPriv", "high")]


def test_ipv6_and_vlan():
    assert creds(run("ipv6_ftp")) == [("FTP", "credential", "v6user", "V6-Fake-Pass")]
    v6 = next(x for x in run("ipv6_ftp") if x.kind is Kind.CREDENTIAL)
    assert str(v6.src) == "[2001:db8::10]:50020"
    assert creds(run("vlan_ftp")) == [("FTP", "credential", "vlanuser", "Vlan-Fake-Pass")]


def test_out_of_order_and_retransmitted_segments():
    stats_f = run("ooo_retrans_ftp")
    assert creds(stats_f) == [("FTP", "credential", "splituser", "Split-Fake-Pass")]


def test_chunked_json_login():
    f = run("http_chunked_json")
    assert creds(f) == [("HTTP", "credential", "jsonuser@example.com", "Json-Fake-Pass")]
    assert results(f) == [("HTTP", "form login failed (HTTP 401)")]


def test_noise_produces_nothing():
    assert run("noise") == []


def test_http_bearer_api_key_cookie_and_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.ZmFrZS1zaWduYXR1cmUtdmFsdWU"
    c = TCPConversation(C, 50100, S, 80).handshake()
    c.client(
        b"GET /api HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer " + jwt.encode()
        + b"\r\nX-Api-Key: fake-api-key-123456\r\nCookie: theme=dark; PHPSESSID=fake-session-1\r\n\r\n"
    )  # fmt: skip
    c.close()
    f = analyze(c.frames, enrichers=[])
    got = creds(f)
    assert ("HTTP", "token", None, jwt) in got
    assert ("HTTP", "api_key", None, "fake-api-key-123456") in got
    assert ("HTTP", "cookie", None, "PHPSESSID=fake-session-1") in got
    assert not any(s and s.startswith("theme=") for *_, s in got), "non-session cookies are not reported by default"


def test_http_digest_reports_metadata_only():
    c = TCPConversation(C, 50101, S, 80).handshake()
    c.client(b'GET / HTTP/1.1\r\nHost: x.example\r\nAuthorization: Digest username="digestuser", realm="r", '
             b'nonce="0123456789abcdef", uri="/", response="fedcba9876543210"\r\n\r\n')  # fmt: skip
    c.close()
    (ev,) = [x for x in analyze(c.frames, enrichers=[]) if x.kind is Kind.AUTH_EVENT]
    assert (ev.username, ev.extra["realm"]) == ("digestuser", "r")
    assert "fedcba9876543210" not in repr(ev.to_dict()) and "0123456789abcdef" not in repr(ev.to_dict())


def test_mail_starttls_stops_parsing():
    c = TCPConversation(C, 50102, S, 587).handshake()
    c.server(b"220 mail ESMTP\r\n").client(b"EHLO x\r\n").server(b"250 STARTTLS\r\n").client(b"STARTTLS\r\n")
    c.server(b"220 Ready to start TLS\r\n").client(b"AUTH PLAIN AHVzZXIAcGFzcw==\r\n").close()
    assert creds(analyze(c.frames, enrichers=[])) == []


@pytest.mark.parametrize("segment", [1, 3, 7])
def test_tiny_segments(segment):
    c = TCPConversation(C, 50103, S, 110).handshake()
    c.server(b"+OK ready\r\n").client(b"USER seguser\r\nPASS Seg-Fake-Pass\r\n", segment=segment).close()
    assert creds(analyze(c.frames, enrichers=[])) == [("POP3", "credential", "seguser", "Seg-Fake-Pass")]


def test_keyvalue_generic_cleartext():
    c = TCPConversation(C, 50104, S, 7000).handshake()
    c.client(b"hello\nlogin user=kvuser pass=Kv-Fake-Pass\n").close()
    (cred,) = [x for x in analyze(c.frames, enrichers=[]) if x.kind is Kind.CREDENTIAL]
    assert (cred.protocol, cred.username, cred.secret, cred.confidence) == ("Cleartext", "kvuser", "Kv-Fake-Pass", 0.5)


@pytest.mark.parametrize(
    "code,verdict",
    [
        (1, "login failed: account expired"),
        (18, "login failed: account disabled or locked out"),
        (23, "login failed: password expired"),
    ],
)
def test_kerberos_account_state_errors_are_failures(code, verdict):
    # Seen in real traffic (zeek krb/kinit.pcap): KDC_ERR_NAME_EXP, KDC_ERR_CLIENT_REVOKED, KDC_ERR_KEY_EXPIRED.
    from netcreds_ng.testing.packets import udp_frame
    from netcreds_ng.testing.protocols import as_req, krb_error

    frames = [udp_frame(C, 51000, S, 88, as_req("fakeuser", "EXAMPLE.TEST", preauth_etype=18)),
              udp_frame(S, 88, C, 51000, krb_error(code, "EXAMPLE.TEST", "fakeuser"))]  # fmt: skip
    f = analyze(frames)
    (result,) = [x for x in f if x.kind is Kind.AUTH_RESULT]
    assert (result.username, result.domain, result.value, result.outcome) == ("fakeuser", "EXAMPLE.TEST", verdict, "failure")
    assert result.extra["error_code"] == code


@pytest.mark.parametrize(
    "pa_types,user,method,tags",
    [
        ((133, 16, 149), "fakeuser", "PKINIT", ["pkinit"]),
        ((14,), "fakeuser", "PKINIT", ["pkinit"]),
        ((133, 16, 149), "WELLKNOWN/ANONYMOUS", "PKINIT", ["anonymous", "pkinit"]),
        ((136, 149), "fakeuser", "FAST armored", ["fast"]),
    ],
)
def test_kerberos_pkinit_and_fast_are_preauthenticated(pa_types, user, method, tags):
    # M32, real traffic (zeek krb/kinit.pcap): a PKINIT AS-REQ answered by an AS-REP was reported as
    # "AS-REP issued without pre-authentication" (high), because only PA-ENC-TIMESTAMP counted as pre-auth.
    from netcreds_ng.testing.packets import udp_frame
    from netcreds_ng.testing.protocols import as_req, kdc_rep

    frames = [udp_frame(C, 51000, S, 88, as_req(user, "EXAMPLE.TEST", preauth_etype=None, offered=(18,),
                                                 pa_types=pa_types)),
              udp_frame(S, 88, C, 51000, kdc_rep(0x6B, user, "EXAMPLE.TEST", ("krbtgt", "EXAMPLE.TEST")))]  # fmt: skip
    (ev,) = [x for x in analyze(frames, enrichers=[]) if x.plugin == "kerberos"]
    assert (ev.kind, ev.username, ev.value, ev.risk) == (
        Kind.AUTH_EVENT, user, f"Kerberos pre-authentication ({method})", "low")
    assert ev.tags == tags and "no-preauth" not in ev.tags


def test_kerberos_as_rep_without_any_preauth_is_still_flagged():
    from netcreds_ng.testing.packets import udp_frame
    from netcreds_ng.testing.protocols import as_req, kdc_rep

    frames = [udp_frame(C, 51000, S, 88, as_req("fakeuser", "EXAMPLE.TEST", preauth_etype=None, pa_types=(149,))),
              udp_frame(S, 88, C, 51000, kdc_rep(0x6B, "fakeuser", "EXAMPLE.TEST", ("krbtgt", "EXAMPLE.TEST")))]  # fmt: skip
    (ev,) = [x for x in analyze(frames, enrichers=[]) if x.plugin == "kerberos"]
    assert (ev.value, ev.risk, ev.tags) == ("AS-REP issued without pre-authentication", "high", ["no-preauth"])


def test_kerberos_other_errors_are_not_login_results():
    from netcreds_ng.testing.packets import udp_frame
    from netcreds_ng.testing.protocols import as_req, krb_error

    frames = [udp_frame(C, 51000, S, 88, as_req("fakeuser", "EXAMPLE.TEST", preauth_etype=18)),
              udp_frame(S, 88, C, 51000, krb_error(14, "EXAMPLE.TEST", "fakeuser"))]  # fmt: skip
    assert [x for x in analyze(frames) if x.kind is Kind.AUTH_RESULT] == []
