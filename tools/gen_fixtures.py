"""Generate the deterministic synthetic capture fixtures in tests/fixtures/synthetic/.

All addresses are documentation ranges (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32)
and all credentials are obviously fake. Re-running produces byte-identical files.

    python tools/gen_fixtures.py
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netcreds_ng.testing.packets import Frame, TCPConversation, frame_for, ip_packet, udp, write_pcap
from netcreds_ng.testing.protocols import (
    as_req,
    b64,
    kdc_rep,
    krb_error,
    krb_tcp,
    ntlm_type2,
    ntlm_type3,
    snmp_v1v2,
    snmp_v3,
)

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic"
C, S = "192.0.2.10", "198.51.100.20"
T0 = 1_700_000_000.0


def conv(port: int, cport: int = 50000, **kw: object) -> TCPConversation:
    c = TCPConversation(kw.pop("client", C), cport, kw.pop("server", S), port, start=T0, **kw)  # type: ignore[arg-type]
    return c.handshake()


def ftp_basic() -> list[Frame]:
    c = conv(21)
    c.server(b"220 FakeFTP ready\r\n").client(b"USER fakeuser\r\n").server(b"331 Password required\r\n")
    c.client(b"PASS FakePass-123\r\n").server(b"230 Login successful.\r\n").client(b"QUIT\r\n").close()
    return c.frames


def ftp_nonstd_port() -> list[Frame]:
    c = conv(2121, 50001)
    c.server(b"220 ready\r\n").client(b"USER nonstd\r\n").server(b"331 ok\r\n").client(b"PASS Nonstd-Pass-9\r\n")
    c.server(b"530 Login incorrect.\r\n").close()
    return c.frames


def telnet_charbychar() -> list[Frame]:
    c = conv(23, 50002)
    c.server(b"\xff\xfd\x18\xff\xfd\x20")  # option negotiation
    c.server(b"\r\nfakehost login: ")
    for ch in b"telnetuser\r\n":
        c.client(bytes([ch]))
        if ch not in b"\r\n":
            c.server(bytes([ch]))  # echo
    c.server(b"Password: ")
    for ch in b"Telnet-Fake-1\r\n":
        c.client(bytes([ch]))
    c.server(b"\r\nLast login: never\r\n$ ").close()
    return c.frames


def irc_identify() -> list[Frame]:
    c = conv(6667, 50003)
    c.client(b"PASS fake-server-pass\r\nNICK fakenick\r\nUSER fakenick 0 * :Fake Name\r\n")
    c.server(b":irc.example 001 fakenick :Welcome\r\n")
    c.client(b"PRIVMSG NickServ :IDENTIFY fakenick Irc-Fake-Pass\r\n").close()
    return c.frames


def smtp_auth_login() -> list[Frame]:
    c = conv(587, 50004)
    c.server(b"220 mail.example ESMTP FakeMail\r\n").client(b"EHLO client.example\r\n")
    c.server(b"250-mail.example\r\n250 AUTH LOGIN PLAIN\r\n").client(b"AUTH LOGIN\r\n")
    c.server(b"334 VXNlcm5hbWU6\r\n").client(b64(b"smtpuser@example.com") + b"\r\n")
    c.server(b"334 UGFzc3dvcmQ6\r\n").client(b64(b"Smtp-Fake-Pass") + b"\r\n")
    c.server(b"235 2.7.0 Authentication successful\r\n").close()
    return c.frames


def smtp_auth_plain() -> list[Frame]:
    c = conv(25, 50005)
    c.server(b"220 mail.example ESMTP\r\n").client(b"EHLO x\r\n").server(b"250 AUTH PLAIN\r\n")
    c.client(b"AUTH PLAIN " + b64(b"\x00plainuser\x00Plain-Fake-Pass") + b"\r\n")
    c.server(b"535 5.7.8 Authentication failed\r\n").close()
    return c.frames


def pop3_userpass() -> list[Frame]:
    c = conv(110, 50006)
    c.server(b"+OK FakePOP ready\r\n").client(b"USER popuser\r\n").server(b"+OK\r\n")
    c.client(b"PASS Pop-Fake-Pass\r\n").server(b"+OK logged in\r\n").close()
    return c.frames


def imap_login() -> list[Frame]:
    c = conv(143, 50007)
    c.server(b"* OK FakeIMAP ready\r\n").client(b'a1 LOGIN imapuser "Imap Fake Pass"\r\n')
    c.server(b"a1 OK LOGIN completed\r\n").close()
    return c.frames


def http_basic() -> list[Frame]:
    c = conv(80, 50008)
    c.client(b"GET /admin HTTP/1.1\r\nHost: www.example.com\r\nAuthorization: Basic " + b64(b"basicuser:Basic-Fake-Pass")
             + b"\r\n\r\n")  # fmt: skip
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").close()
    return c.frames


def http_form() -> list[Frame]:
    body = b"username=formuser&password=Form-Fake-Pass&remember=1"
    c = conv(8080, 50009)
    c.client(b"POST /login HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n"
             b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)  # fmt: skip
    c.server(b"HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n").close()
    return c.frames


def http_search_url() -> list[Frame]:
    c = conv(80, 50010)
    c.client(b"GET /search?q=fake+search+terms HTTP/1.1\r\nHost: search.example.com\r\n\r\n")
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    c.client(b"GET /static/logo.png HTTP/1.1\r\nHost: search.example.com\r\n\r\n").close()
    return c.frames


def http_ntlm() -> list[Frame]:
    c = conv(80, 50011)
    c.client(b"GET /intranet HTTP/1.1\r\nHost: intranet.example\r\nAuthorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n")
    c.server(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM " + b64(ntlm_type2()) + b"\r\nContent-Length: 0\r\n\r\n")
    c.client(b"GET /intranet HTTP/1.1\r\nHost: intranet.example\r\nAuthorization: NTLM "
             + b64(ntlm_type3("ntlmuser", "FAKEDOM", "FAKEWS")) + b"\r\n\r\n")  # fmt: skip
    c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").close()
    return c.frames


def smb_ntlm_raw() -> list[Frame]:
    c = conv(445, 50012)
    c.server(b"\x00\x00\x00\x80\xfeSMB" + b"\x00" * 56 + ntlm_type2("FAKEDOM"))
    c.client(b"\x00\x00\x01\x00\xfeSMB" + b"\x00" * 56 + ntlm_type3("smbuser", "FAKEDOM", "FAKEWS", nt_len=24))
    c.close()
    return c.frames


def kerberos_udp_tcp() -> list[Frame]:
    frames: list[Frame] = []
    t = T0
    for payload, src, sport, dst, dport in (
        (as_req("krbuser", "EXAMPLE.TEST", preauth_etype=None), C, 51000, S, 88),
        (krb_error(25, "EXAMPLE.TEST", "krbuser"), S, 88, C, 51000),
        (as_req("krbuser", "EXAMPLE.TEST", preauth_etype=23), C, 51001, S, 88),
        (as_req("aesuser", "EXAMPLE.TEST", preauth_etype=18, offered=(18, 17)), C, 51002, S, 88),
        (as_req("nopreauth", "EXAMPLE.TEST", preauth_etype=None), C, 51003, S, 88),
        (kdc_rep(0x6B, "nopreauth", "EXAMPLE.TEST", ("krbtgt", "EXAMPLE.TEST")), S, 88, C, 51003),
        (kdc_rep(0x6D, "krbuser", "EXAMPLE.TEST", ("cifs", "fs1.example.test"), ticket_etype=23), S, 88, C, 51004),
        (krb_error(24, "EXAMPLE.TEST", "baduser"), S, 88, C, 51005),
    ):
        frames.append(Frame(frame_for(ip_packet(src, dst, 17, udp(src, dst, sport, dport, payload))), t))
        t += 0.01
    c = TCPConversation(C, 51010, S, 88, start=t).handshake()
    c.client(krb_tcp(as_req("tcpuser", "EXAMPLE.TEST", preauth_etype=23)), segment=60).close()
    return frames + c.frames


def snmp_communities() -> list[Frame]:
    frames = []
    t = T0
    for payload, sport, dport in (
        (snmp_v1v2("fake-community", 1, 0xA0), 50100, 161),
        (snmp_v1v2("fake-community", 1, 0xA2), 161, 50100),
        (snmp_v1v2("public", 0, 0xA3), 50101, 161),
        (snmp_v3("v3noauth", 0x04), 50102, 161),
        (snmp_v3("v3authpriv", 0x07), 50103, 161),
    ):
        src, dst = (C, S) if dport == 161 else (S, C)
        frames.append(Frame(frame_for(ip_packet(src, dst, 17, udp(src, dst, sport, dport, payload))), t))
        t += 0.01
    return frames


def ipv6_ftp() -> list[Frame]:
    c = conv(21, 50020, client="2001:db8::10", server="2001:db8::20")
    c.server(b"220 v6 ftp\r\n").client(b"USER v6user\r\n").server(b"331 ok\r\n").client(b"PASS V6-Fake-Pass\r\n")
    c.server(b"230 ok\r\n").close()
    return c.frames


def vlan_ftp() -> list[Frame]:
    c = conv(21, 50021, vlan=42)
    c.server(b"220 vlan ftp\r\n").client(b"USER vlanuser\r\n").server(b"331 ok\r\n").client(b"PASS Vlan-Fake-Pass\r\n")
    c.close()
    return c.frames


def ooo_retrans_ftp() -> list[Frame]:
    """Credential split across segments delivered out of order, plus retransmissions."""
    c = conv(21, 50022)
    c.server(b"220 ready\r\n")
    c.client(b"USER splituser\r\n")
    c.server(b"331 ok\r\n")
    data = b"PASS Split-Fake-Pass\r\n"
    c.raw_segment(True, data[10:], rel_offset=10)  # second half first
    c.raw_segment(True, data[:10], rel_offset=0)  # then the first half
    c.raw_segment(True, data[:10], rel_offset=0)  # retransmission
    c.advance(True, len(data))
    c.server(b"230 ok\r\n").close()
    return c.frames


def http_chunked_json() -> list[Frame]:
    body = b'{"user": {"email": "jsonuser@example.com", "password": "Json-Fake-Pass"}}'
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
    c = conv(80, 50023)
    c.client(b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n"
             b"Transfer-Encoding: chunked\r\n\r\n" + chunked, segment=40)  # fmt: skip
    c.server(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n").close()
    return c.frames


def noise() -> list[Frame]:
    c = conv(9999, 50024)
    c.client(bytes(range(256)) * 4).server(b"\x00\x01binary\xff" * 50).close()
    dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    c.frames.append(Frame(frame_for(ip_packet(C, S, 17, udp(C, S, 53000, 53, dns))), T0 + 9))
    return c.frames


FIXTURES: dict[str, Callable[[], list[Frame]]] = {
    f.__name__: f
    for f in (
        ftp_basic, ftp_nonstd_port, telnet_charbychar, irc_identify, smtp_auth_login, smtp_auth_plain, pop3_userpass,
        imap_login, http_basic, http_form, http_search_url, http_ntlm, smb_ntlm_raw, kerberos_udp_tcp,
        snmp_communities, ipv6_ftp, vlan_ftp, ooo_retrans_ftp, http_chunked_json, noise,
    )
}  # fmt: skip


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in FIXTURES.items():
        write_pcap(str(OUT / f"{name}.pcap"), build())
        print(f"wrote {name}.pcap")


if __name__ == "__main__":
    main()
