"""Bit-for-bit compatible port of the original net-creds algorithm (``--legacy``).

This module reproduces the observable behaviour of ``net-creds.py`` (upstream
commit 07a25e1, Python 2) on Python 3: the same per-packet heuristics, the same
message texts, the same stdout lines (with ANSI colours) and the same
``credentials.txt`` log with its substring de-duplication. Wire data stays
``bytes`` end to end, exactly like Python 2 ``str``.

Documented deviations from Python 2 (see docs/MIGRATION_PLAN.md):

* TCP payloads are always treated as scapy ``Raw`` (the original was written
  against scapy 2.3; later scapy versions dissect SMB/NBT/... and hide those
  payloads from it). This is the intended, port-agnostic semantics.
* SNMP is recognised the way scapy binds it (UDP port 161/162) with a strict
  BER check of version/community/PDU; v3 messages are not SNMP-dissected.
* Messages that Python 2 built as ``unicode`` (Telnet, HTTP form credentials,
  ``Decoded:`` mail lines) are written as UTF-8. Python 2 wrote UTF-8 to the
  log file but crashed or used the console code page on stdout.
* HTTP header iteration uses wire order (Python 2 used hash order).
* The NTLM struct format uses explicit little-endian (identical on x86).
* Unreadable captures print ``[-] ...`` instead of a scapy traceback.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import struct
import sys
from collections import OrderedDict
from collections.abc import Callable, Iterable
from typing import BinaryIO
from urllib.parse import unquote_to_bytes

from netcreds_ng.engine.decode import PROTO_TCP, PROTO_UDP, decode_ip, decode_l4, l3_offset, ETH_IPV4
from netcreds_ng.engine.pcapio import RawFrame

LOG_FILE = "credentials.txt"
# Python 2 wrote stdout and the log in text mode, so newlines became os.linesep.
EOL = os.linesep.encode()

authenticate_re = rb"(www-|proxy-)?authenticate"
authorization_re = rb"(www-|proxy-)?authorization"
ftp_user_re = rb"USER (.+)\r\n"
ftp_pw_re = rb"PASS (.+)\r\n"
irc_user_re = rb"NICK (.+?)((\r)?\n|\s)"
irc_pw_re = rb"NS IDENTIFY (.+)"
irc_pw_re2 = rb"nickserv :identify (.+)"
mail_auth_re = rb"(\d+ )?(auth|authenticate) (login|plain)"
mail_auth_re1 = rb"(\d+ )?login "
NTLMSSP2_re = b"NTLMSSP\x00\x02\x00\x00\x00.+"
NTLMSSP3_re = b"NTLMSSP\x00\x03\x00\x00\x00.+"
http_search_re = (
    rb"((search|query|&q|\?q|search\?p|searchterm|keywords|keyword|command|terms|keys|question|kwd|searchPhrase)"
    rb"=([^&][^&]*))"
)

W = b"\033[0m"
T = b"\033[93m"

HTTP_METHODS = [b"GET ", b"POST ", b"CONNECT ", b"TRACE ", b"TRACK ", b"PUT ", b"DELETE ", b"HEAD "]

USERFIELDS = [
    b"log", b"login", b"wpname", b"ahd_username", b"unickname", b"nickname", b"user", b"user_name",
    b"alias", b"pseudo", b"email", b"username", b"_username", b"userid", b"form_loginname", b"loginname",
    b"login_id", b"loginid", b"session_key", b"sessionkey", b"pop_login", b"uid", b"id", b"user_id", b"screename",
    b"uname", b"ulogin", b"acctname", b"account", b"member", b"mailaddress", b"membername", b"login_username",
    b"login_email", b"loginusername", b"loginemail", b"uin", b"sign-in", b"usuario",
]  # fmt: skip
# The missing comma after 'login_password' in the original is preserved on purpose.
PASSFIELDS = [
    b"ahd_password", b"pass", b"password", b"_password", b"passwd", b"session_password", b"sessionpassword",
    b"login_password", b"loginpassword", b"form_pw", b"pw", b"userpassword", b"pwd", b"upassword",
    b"login_password" b"passwort", b"passwrd", b"wppassword", b"upasswd", b"senha", b"contrasena",
]  # fmt: skip

_ANSI = re.compile(rb"\x1b[^m]*m")
_SNMP_PORTS = (161, 162)


class LegacyAbort(Exception):
    """An exception that terminated the original program mid-capture."""


def _u(text: str) -> bytes:
    """Encode a message Python 2 held as ``unicode``."""
    return text.encode("utf-8", "surrogateescape")


# --- minimal BER for the SNMP check -----------------------------------------


def _ber(data: bytes, pos: int) -> tuple[int, int, int] | None:
    """Return (tag, value_start, value_end) for the TLV at ``pos``."""
    if pos + 2 > len(data):
        return None
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            return None
        length = int.from_bytes(data[pos : pos + n], "big")
        pos += n
    if pos + length > len(data):
        return None
    return tag, pos, pos + length


def snmp_community(payload: bytes) -> tuple[int, bytes] | None:
    """(version, community) of an SNMPv1/v2c message, or None."""
    top = _ber(payload, 0)
    if top is None or top[0] != 0x30:
        return None
    ver = _ber(payload, top[1])
    if ver is None or ver[0] != 0x02 or ver[2] - ver[1] < 1:
        return None
    version = int.from_bytes(payload[ver[1] : ver[2]], "big", signed=True)
    com = _ber(payload, ver[2])
    if com is None or com[0] != 0x04:
        return None
    pdu = _ber(payload, com[2])
    if pdu is None or not 0xA0 <= pdu[0] <= 0xA8:
        return None
    return version, payload[com[1] : com[2]]


class LegacyNetCreds:
    """Stateful port of ``pkt_parser`` and friends."""

    def __init__(
        self,
        out: BinaryIO | None = None,
        verbose: bool = False,
        log_path: str = LOG_FILE,
        write_log: bool = True,
        eol: bytes = EOL,
    ) -> None:
        self.eol = eol
        self.out = out if out is not None else sys.stdout.buffer
        self.verbose = verbose
        self.log_path = log_path
        self.write_log = write_log
        self.pkt_frag_loads: OrderedDict[bytes, OrderedDict[bytes, bytes]] = OrderedDict()
        self.challenge_acks: OrderedDict[bytes, bytes] = OrderedDict()
        self.mail_auths: OrderedDict[bytes, list[bytes]] = OrderedDict()
        self.telnet_stream: OrderedDict[bytes, str] = OrderedDict()
        self.listeners: list[Callable[[bytes, bytes | None, bytes], None]] = []
        if write_log:
            # logging.basicConfig(filename=...) creates/opens the file at import time.
            with open(log_path, "ab"):
                pass

    # --- entry point -------------------------------------------------------

    def process_frame(self, frame: RawFrame) -> None:
        res = l3_offset(frame)
        if res is None or res[1] != ETH_IPV4:
            return  # no scapy IP layer: nothing in pkt_parser applies
        ip = decode_ip(frame.data[res[0] :])
        if ip is None:
            return
        if ip.frag_offset > 0:
            return  # scapy leaves non-first fragments as Raw (no TCP/UDP layer)
        pkt = decode_l4(frame, res[0], ip, ip.payload)
        if not pkt.l4_header_len:
            return
        raw_str = frame.data  # str(pkt) in Python 2: the frame bytes

        if pkt.proto == PROTO_UDP:
            src_ip_port = b"%s:%d" % (ip.src.encode(), pkt.sport)
            dst_ip_port = b"%s:%d" % (ip.dst.encode(), pkt.dport)
            if (pkt.sport in _SNMP_PORTS or pkt.dport in _SNMP_PORTS) and pkt.payload:
                snmp = snmp_community(pkt.payload)
                if snmp is not None:
                    self.parse_snmp(src_ip_port, dst_ip_port, snmp)
                    return
            decoded = self.decode_ip_packet(raw_str[14:])
            kerb_hash = self.parse_ms_kerb5_udp(decoded[8:])
            if kerb_hash:
                self.printer(src_ip_port, dst_ip_port, kerb_hash)

        elif pkt.proto == PROTO_TCP and pkt.payload:
            load = pkt.payload
            ack = str(pkt.ack).encode()
            seq = str(pkt.seq).encode()
            src_ip_port = b"%s:%d" % (ip.src.encode(), pkt.sport)
            dst_ip_port = b"%s:%d" % (ip.dst.encode(), pkt.dport)
            self.frag_remover()
            self.pkt_frag_loads[src_ip_port] = self.frag_joiner(ack, src_ip_port, load)
            full_load = self.pkt_frag_loads[src_ip_port][ack]

            if 0 < len(full_load) < 750:
                ftp_creds = self.parse_ftp(full_load, dst_ip_port)
                if ftp_creds:
                    for msg in ftp_creds:
                        self.printer(src_ip_port, dst_ip_port, msg)
                    return
                self.mail_logins(full_load, src_ip_port, dst_ip_port, ack, seq)
                irc_creds = self.irc_logins(full_load)
                if irc_creds is not None:
                    self.printer(src_ip_port, dst_ip_port, irc_creds)
                    return
                self.telnet_logins(src_ip_port, dst_ip_port, load, ack, seq)

            self.other_parser(src_ip_port, dst_ip_port, full_load, ack, seq, raw_str, self.verbose)

    def process(self, frames: Iterable[RawFrame]) -> None:
        for frame in frames:
            self.process_frame(frame)

    # --- reassembly --------------------------------------------------------

    def frag_remover(self) -> None:
        while len(self.pkt_frag_loads) > 50:
            self.pkt_frag_loads.popitem(last=False)
        for ip_port in list(self.pkt_frag_loads):
            loads = self.pkt_frag_loads[ip_port]
            while len(loads) > 25:
                loads.popitem(last=False)
        for ip_port in list(self.pkt_frag_loads):
            loads = self.pkt_frag_loads[ip_port]
            for ack in list(loads):
                if len(loads[ack]) > 5000:
                    loads[ack] = loads[ack][-200:]

    def frag_joiner(self, ack: bytes, src_ip_port: bytes, load: bytes) -> OrderedDict[bytes, bytes]:
        if src_ip_port in self.pkt_frag_loads and ack in self.pkt_frag_loads[src_ip_port]:
            return OrderedDict([(ack, self.pkt_frag_loads[src_ip_port][ack] + load)])
        return OrderedDict([(ack, load)])

    # --- telnet ------------------------------------------------------------

    def telnet_logins(self, src_ip_port: bytes, dst_ip_port: bytes, load: bytes, ack: bytes, seq: bytes) -> None:
        if src_ip_port in self.telnet_stream:
            try:
                self.telnet_stream[src_ip_port] += load.decode("utf8")
            except UnicodeDecodeError:
                pass
            stream = self.telnet_stream[src_ip_port]
            if "\r" in stream or "\n" in stream:
                cred_type, value = stream.split(" ", 1)
                value = value.replace("\r\n", "").replace("\r", "").replace("\n", "")
                self.printer(src_ip_port, dst_ip_port, _u("Telnet %s: %s" % (cred_type, value)))
                del self.telnet_stream[src_ip_port]
        if len(self.telnet_stream) > 100:
            self.telnet_stream.popitem(last=False)
        mod_load = load.lower().strip()
        if mod_load.endswith(b"username:") or mod_load.endswith(b"login:"):
            self.telnet_stream[dst_ip_port] = "username "
        elif mod_load.endswith(b"password:"):
            self.telnet_stream[dst_ip_port] = "password "

    # --- kerberos ----------------------------------------------------------

    @staticmethod
    def _b(data: bytes) -> int:
        try:
            return struct.unpack("<b", data)[0]
        except struct.error as exc:
            raise LegacyAbort(f"struct.error in Kerberos parser: {exc}") from exc

    @staticmethod
    def _hash(name: bytes, domain: bytes, switch: bytes) -> bytes:
        return b"MS Kerberos: $krb5pa$23$" + name + b"$" + domain + b"$dummy$" + binascii.hexlify(switch)

    def parse_ms_kerb5_tcp(self, data: bytes) -> bytes | None:
        msg_type, enc_type, message_type = data[21:22], data[43:44], data[32:33]
        if msg_type == b"\x0a" and enc_type == b"\x17" and message_type == b"\x02":
            b = self._b
            if data[49:53] in (b"\xa2\x36\x04\x34", b"\xa2\x35\x04\x33"):
                hash_len = b(data[50:51])
                if hash_len == 54:
                    h = data[53:105]
                    switch = h[16:] + h[0:16]
                    name_len = b(data[153:154])
                    name = data[154 : 154 + name_len]
                    dom_len = b(data[154 + name_len + 3 : 154 + name_len + 4])
                    domain = data[154 + name_len + 4 : 154 + name_len + 4 + dom_len]
                    return self._hash(name, domain, switch)
            if data[44:48] in (b"\xa2\x36\x04\x34", b"\xa2\x35\x04\x33"):
                hash_len = b(data[47:48])
                h = data[48 : 48 + hash_len]
                switch = h[16:] + h[0:16]
                name_len = b(data[hash_len + 96 : hash_len + 96 + 1])
                name = data[hash_len + 97 : hash_len + 97 + name_len]
                dom_len = b(data[hash_len + 97 + name_len + 3 : hash_len + 97 + name_len + 4])
                domain = data[hash_len + 97 + name_len + 4 : hash_len + 97 + name_len + 4 + dom_len]
                return self._hash(name, domain, switch)
            h = data[48:100]
            switch = h[16:] + h[0:16]
            name_len = b(data[148:149])
            name = data[149 : 149 + name_len]
            dom_len = b(data[149 + name_len + 3 : 149 + name_len + 4])
            domain = data[149 + name_len + 4 : 149 + name_len + 4 + dom_len]
            return self._hash(name, domain, switch)
        return None

    def parse_ms_kerb5_udp(self, data: bytes) -> bytes | None:
        msg_type, enc_type = data[17:18], data[39:40]
        if msg_type == b"\x0a" and enc_type == b"\x17":
            try:
                unpack = lambda d: struct.unpack("<b", d)[0]  # noqa: E731
                if data[40:44] in (b"\xa2\x36\x04\x34", b"\xa2\x35\x04\x33"):
                    hash_len = unpack(data[41:42])
                    if hash_len == 54:
                        h = data[44:96]
                        switch = h[16:] + h[0:16]
                        name_len = unpack(data[144:145])
                        name = data[145 : 145 + name_len]
                        dom_len = unpack(data[145 + name_len + 3 : 145 + name_len + 4])
                        domain = data[145 + name_len + 4 : 145 + name_len + 4 + dom_len]
                        return self._hash(name, domain, switch)
                    if hash_len == 53:
                        h = data[44:95]
                        switch = h[16:] + h[0:16]
                        name_len = unpack(data[143:144])
                        name = data[144 : 144 + name_len]
                        dom_len = unpack(data[144 + name_len + 3 : 144 + name_len + 4])
                        domain = data[144 + name_len + 4 : 144 + name_len + 4 + dom_len]
                        return self._hash(name, domain, switch)
                else:
                    hash_len = unpack(data[48:49])
                    h = data[49 : 49 + hash_len]
                    switch = h[16:] + h[0:16]
                    name_len = unpack(data[hash_len + 97 : hash_len + 97 + 1])
                    name = data[hash_len + 98 : hash_len + 98 + name_len]
                    dom_len = unpack(data[hash_len + 98 + name_len + 3 : hash_len + 98 + name_len + 4])
                    domain = data[hash_len + 98 + name_len + 4 : hash_len + 98 + name_len + 4 + dom_len]
                    return self._hash(name, domain, switch)
            except struct.error:
                return None
        return None

    @staticmethod
    def decode_ip_packet(s: bytes) -> bytes:
        if not s:
            raise LegacyAbort("IndexError in Decode_Ip_Packet (frame shorter than 15 bytes)")
        header_len = s[0] & 0x0F
        return s[4 * header_len :]

    # --- ftp / mail / irc --------------------------------------------------

    @staticmethod
    def double_line_checker(full_load: bytes, count_str: bytes) -> bytes:
        if full_load.lower().count(count_str) > 1:
            if full_load.count(b"\r\n") > 1:
                full_load = full_load.split(b"\r\n")[-2]
        return full_load

    def parse_ftp(self, full_load: bytes, dst_ip_port: bytes) -> list[bytes]:
        print_strs: list[bytes] = []
        full_load = self.double_line_checker(full_load, b"USER")  # never true: preserved
        ftp_user = re.match(ftp_user_re, full_load)
        ftp_pass = re.match(ftp_pw_re, full_load)
        nonstd = b"Nonstandard FTP port, confirm the service that is running on it"
        if ftp_user:
            print_strs.append(b"FTP User: " + ftp_user.group(1).strip())
            if dst_ip_port[-3:] != b":21":
                print_strs.append(nonstd)
        elif ftp_pass:
            print_strs.append(b"FTP Pass: " + ftp_pass.group(1).strip())
            if dst_ip_port[-3:] != b":21":
                print_strs.append(nonstd)
        return print_strs

    def mail_decode(self, src_ip_port: bytes, dst_ip_port: bytes, mail_creds: bytes) -> None:
        try:
            decoded = base64.b64decode(mail_creds).replace(b"\x00", b" ").decode("utf8")
            decoded = decoded.replace("\x00", " ")
        except (binascii.Error, ValueError):  # Py2: TypeError / UnicodeDecodeError
            return
        self.printer(src_ip_port, dst_ip_port, _u("Decoded: %s" % decoded))

    def mail_logins(self, full_load: bytes, src_ip_port: bytes, dst_ip_port: bytes, ack: bytes, seq: bytes) -> bool | None:
        found = False
        full_load = self.double_line_checker(full_load, b"auth")
        if src_ip_port in self.mail_auths:
            if seq in self.mail_auths[src_ip_port][-1]:
                stripped = full_load.strip(b"\r\n")
                try:
                    decoded = base64.b64decode(stripped)
                    self.printer(src_ip_port, dst_ip_port, b"Mail authentication: " + decoded)
                except binascii.Error:
                    pass
                self.mail_auths[src_ip_port].append(ack)
        elif dst_ip_port in self.mail_auths:
            if seq in self.mail_auths[dst_ip_port][-1]:
                a_s = b"Authentication successful"
                a_f = b"Authentication failed"
                lower = full_load.lower()
                result = None
                if full_load.startswith(b"235") and b"auth" in lower:
                    result = a_s
                elif full_load.startswith(b"535 "):
                    result = a_f
                elif b" fail" in lower:
                    result = a_f
                elif b" OK [" in full_load:
                    result = a_s
                if result is not None:
                    self.printer(dst_ip_port, src_ip_port, result)
                    found = True
                    self.mail_auths.pop(dst_ip_port, None)
                else:
                    if len(self.mail_auths) > 100:
                        self.mail_auths.popitem(last=False)
                    self.mail_auths[dst_ip_port].append(ack)
        else:
            mail_auth_search = re.match(mail_auth_re, full_load, re.IGNORECASE)
            if mail_auth_search is not None:
                auth_msg = full_load.split()[1:] if mail_auth_search.group(1) is not None else full_load.split()
                if len(auth_msg) > 2:
                    mail_creds = b" ".join(auth_msg[2:])
                    self.printer(src_ip_port, dst_ip_port, b"Mail authentication: " + mail_creds)
                    self.mail_decode(src_ip_port, dst_ip_port, mail_creds)
                    self.mail_auths.pop(src_ip_port, None)
                    found = True
                if len(self.mail_auths) > 100:
                    self.mail_auths.popitem(last=False)
                self.mail_auths[src_ip_port] = [ack]
            elif re.match(mail_auth_re1, full_load, re.IGNORECASE) is not None:
                auth_msg = full_load.split()
                if 2 < len(auth_msg) < 5:
                    mail_creds = b" ".join(auth_msg[2:])
                    self.printer(src_ip_port, dst_ip_port, b"Authentication: " + mail_creds)
                    self.mail_decode(src_ip_port, dst_ip_port, mail_creds)
                    found = True
        return True if found else None

    @staticmethod
    def irc_logins(full_load: bytes) -> bytes | None:
        user_search = re.match(irc_user_re, full_load)
        pass_search = re.match(irc_pw_re, full_load)
        pass_search2 = re.search(irc_pw_re2, full_load.lower())
        if user_search:
            return b"IRC nick: " + user_search.group(1)
        if pass_search:
            return b"IRC pass: " + pass_search.group(1)
        if pass_search2:
            return b"IRC pass: " + pass_search2.group(1)
        return None

    # --- http / ntlm -------------------------------------------------------

    def other_parser(
        self,
        src_ip_port: bytes,
        dst_ip_port: bytes,
        full_load: bytes,
        ack: bytes,
        seq: bytes,
        raw_str: bytes,
        verbose: bool,
    ) -> None:
        method = None
        http_url_req = None
        http_line, header_lines, body = self.parse_http_load(full_load)
        headers = self.headers_to_dict(header_lines)
        host = headers.get(b"host", b"")

        if http_line is not None:
            method, path = self.parse_http_line(http_line)
            http_url_req = self.get_http_url(method, host, path)
            if http_url_req is not None:
                if not verbose and len(http_url_req) > 98:
                    http_url_req = http_url_req[:99] + b"..."
                self.printer(src_ip_port, None, http_url_req)

        searched = self.get_http_searches(http_url_req, body, host)
        if searched:
            self.printer(src_ip_port, dst_ip_port, searched)

        if body != b"":
            user_passwd = self.get_login_pass(body)
            if user_passwd is not None:
                try:
                    http_user = user_passwd[0].decode("utf8")
                    http_pass = user_passwd[1].decode("utf8")
                    if len(http_user) > 75 or len(http_pass) > 75:
                        return
                    self.printer(src_ip_port, dst_ip_port, _u("HTTP username: %s" % http_user))
                    self.printer(src_ip_port, dst_ip_port, _u("HTTP password: %s" % http_pass))
                except UnicodeDecodeError:
                    pass

        if method == b"POST" and b"ocsp." not in host:
            try:
                if not verbose and len(body) > 99:
                    body[:99].decode("ascii")  # Py2 str.encode('utf8') implicit ASCII decode
                    msg = b"POST load: " + body[:99] + b"..."
                else:
                    body.decode("ascii")
                    msg = b"POST load: " + body
                self.printer(src_ip_port, None, msg)
            except UnicodeDecodeError:
                pass

        decoded = self.decode_ip_packet(raw_str[14:])
        kerb_hash = self.parse_ms_kerb5_tcp(decoded[20:])
        if kerb_hash:
            self.printer(src_ip_port, dst_ip_port, kerb_hash)

        ntlmssp2 = re.search(NTLMSSP2_re, full_load, re.DOTALL)
        ntlmssp3 = re.search(NTLMSSP3_re, full_load, re.DOTALL)
        if ntlmssp2:
            self.parse_ntlm_chal(ntlmssp2.group(), ack)
        if ntlmssp3:
            ntlm_resp_found = self.parse_ntlm_resp(ntlmssp3.group(), seq)
            if ntlm_resp_found is not None:
                self.printer(src_ip_port, dst_ip_port, ntlm_resp_found)

        authenticate_header = authorization_header = None
        for header in headers:
            authenticate_header = re.match(authenticate_re, header)
            authorization_header = re.match(authorization_re, header)
            if authenticate_header or authorization_header:
                break

        if authorization_header or authenticate_header:
            netntlm_found = self.parse_netntlm(authenticate_header, authorization_header, headers, ack, seq)
            if netntlm_found is not None:
                self.printer(src_ip_port, dst_ip_port, netntlm_found)
            self.parse_basic_auth(src_ip_port, dst_ip_port, headers, authorization_header)

    def get_http_searches(self, http_url_req: bytes | None, body: bytes, host: bytes) -> bytes | None:
        searched = None
        if http_url_req is not None:
            searched = re.search(http_search_re, http_url_req, re.IGNORECASE)
            if searched is None:
                searched = re.search(http_search_re, body, re.IGNORECASE)
        if searched is not None and host not in (b"i.stack.imgur.com",):
            raw = searched.group(3)
            try:
                text = raw.decode("utf8")
            except UnicodeDecodeError:
                return None
            if text in [str(n) for n in range(10)]:
                return None
            if len(text) > 100:
                return None
            return b"Searched " + host + b": " + unquote_to_bytes(raw).replace(b"+", b" ")
        return None

    def parse_basic_auth(self, src_ip_port: bytes, dst_ip_port: bytes, headers: dict[bytes, bytes], authorization_header: re.Match[bytes] | None) -> None:
        if authorization_header:
            header_val = headers.get(authorization_header.group())
            if header_val is None:
                return
            b64_auth_re = re.match(rb"basic (.+)", header_val, re.IGNORECASE)
            if b64_auth_re is not None:
                try:
                    creds = base64.decodebytes(b64_auth_re.group(1))
                except Exception:  # noqa: BLE001 - mirrors the original
                    return
                self.printer(src_ip_port, dst_ip_port, b"Basic Authentication: " + creds)

    def parse_netntlm(self, authenticate_header: re.Match[bytes] | None, authorization_header: re.Match[bytes] | None, headers: dict[bytes, bytes], ack: bytes, seq: bytes) -> bytes | None:
        if authenticate_header is not None:
            self.parse_netntlm_chal(headers, authenticate_header.group(), ack)
        elif authorization_header is not None:
            return self.parse_netntlm_resp_msg(headers, authorization_header.group(), seq)
        return None

    def parse_snmp(self, src_ip_port: bytes, dst_ip_port: bytes, snmp: tuple[int, bytes]) -> None:
        version, community = snmp
        self.printer(src_ip_port, dst_ip_port, b"SNMPv%d community string: %s" % (version, community))

    def get_http_url(self, method: bytes | None, host: bytes, path: bytes | None) -> bytes | None:
        if method is not None and path is not None:
            try:
                same_host = host != b"" and re.match(b"(http(s)?://)?" + host, path)
            except re.error as exc:
                raise LegacyAbort(f"re.error on Host header: {exc}") from exc
            if host != b"" and not same_host:
                url = method + b" " + host + path
            else:
                url = method + b" " + path
            return self.url_filter(url)
        return None

    @staticmethod
    def headers_to_dict(header_lines: list[bytes]) -> dict[bytes, bytes]:
        headers: dict[bytes, bytes] = {}
        for line in header_lines:
            parts = line.split(b": ", 1)
            headers[parts[0].lower()] = parts[1] if len(parts) > 1 else b""
        return headers

    @staticmethod
    def parse_http_line(http_line: bytes) -> tuple[bytes | None, bytes | None]:
        split = http_line.split()
        method: bytes | None = b""
        path: bytes | None = b""
        if len(split) > 1:
            method, path = split[0], split[1]
        if (method or b"") + b" " not in HTTP_METHODS:
            method = path = None
        return method, path

    def parse_http_load(self, full_load: bytes) -> tuple[bytes | None, list[bytes], bytes]:
        parts = full_load.split(b"\r\n\r\n", 1)
        if len(parts) == 2:
            headers, body = parts
        else:
            headers, body = full_load, b""
        header_lines = headers.split(b"\r\n")
        http_line = self.get_http_line(header_lines)
        if not http_line:
            body = full_load
        header_lines = [line for line in header_lines if line != http_line]
        return http_line, header_lines, body

    @staticmethod
    def get_http_line(header_lines: list[bytes]) -> bytes | None:
        for header in header_lines:
            for method in HTTP_METHODS:
                if header.startswith(method):
                    return header
        return None

    def parse_netntlm_chal(self, headers: dict[bytes, bytes], chal_header: bytes, ack: bytes) -> None:
        header_val2 = headers.get(chal_header)
        if header_val2 is None:
            return
        parts = header_val2.split(b" ", 1)
        if parts[0] == b"NTLM" or parts[0].lower() == b"negotiate":
            if len(parts) < 2:
                return
            try:
                msg2 = base64.decodebytes(parts[1])
            except binascii.Error as exc:
                raise LegacyAbort(f"binascii.Error decoding NTLM challenge: {exc}") from exc
            self.parse_ntlm_chal(msg2, ack)

    def parse_ntlm_chal(self, msg2: bytes, ack: bytes) -> None:
        try:
            msg_type = struct.unpack("<I", msg2[8:12])[0]
            if msg_type != 2:
                return
        except Exception:  # noqa: BLE001
            return
        server_challenge = binascii.hexlify(msg2[24:32])
        if len(self.challenge_acks) > 50:
            self.challenge_acks.popitem(last=False)
        self.challenge_acks[ack] = server_challenge

    def parse_netntlm_resp_msg(self, headers: dict[bytes, bytes], resp_header: bytes, seq: bytes) -> bytes | None:
        header_val3 = headers.get(resp_header)
        if header_val3 is None:
            return None
        parts = header_val3.split(b" ", 1)
        if parts[0] in (b"NTLM", b"Negotiate"):
            if len(parts) < 2:
                raise LegacyAbort("IndexError: Authorization header without value")
            try:
                msg3 = base64.decodebytes(parts[1])
            except binascii.Error:
                return None
            return self.parse_ntlm_resp(msg3, seq)
        return None

    def parse_ntlm_resp(self, msg3: bytes, seq: bytes) -> bytes | None:
        challenge = self.challenge_acks.get(seq, b"CHALLENGE NOT FOUND")
        if len(msg3) > 43:
            (lmlen, _lmmax, lmoff, ntlen, _ntmax, ntoff, domlen, _dommax, domoff, userlen, _usermax, useroff) = (
                struct.unpack("<12xhhihhihhihhi", msg3[:44])
            )
            lmhash = binascii.b2a_hex(msg3[lmoff : lmoff + lmlen])
            nthash = binascii.b2a_hex(msg3[ntoff : ntoff + ntlen])
            domain = msg3[domoff : domoff + domlen].replace(b"\0", b"")
            user = msg3[useroff : useroff + userlen].replace(b"\0", b"")
            if ntlen == 24:
                return b"NETNTLMv1: " + user + b"::" + domain + b":" + lmhash + b":" + nthash + b":" + challenge
            if ntlen > 60:
                return b"NETNTLMv2: " + user + b"::" + domain + b":" + challenge + b":" + nthash[:32] + b":" + nthash[32:]
        return None

    @staticmethod
    def url_filter(http_url_req: bytes | None) -> bytes | None:
        if http_url_req:
            for ext in (b".jpg", b".jpeg", b".gif", b".png", b".css", b".ico", b".js", b".svg", b".woff"):
                if http_url_req.endswith(ext):
                    return None
        return http_url_req

    @staticmethod
    def get_login_pass(body: bytes) -> tuple[bytes, bytes] | None:
        user = passwd = None
        for login in USERFIELDS:
            m = re.search(b"(" + login + b"=[^&]+)", body, re.IGNORECASE)
            if m:
                user = m.group()
        for passfield in PASSFIELDS:
            m = re.search(b"(" + passfield + b"=[^&]+)", body, re.IGNORECASE)
            if m:
                passwd = m.group()
        if user and passwd:
            return user, passwd
        return None

    # --- output ------------------------------------------------------------

    def _textmode(self, data: bytes) -> bytes:
        """Emulate Python 2 text-mode newline translation (every LF, including embedded ones)."""
        return data if self.eol == b"\n" else data.replace(b"\n", self.eol)

    def printer(self, src_ip_port: bytes, dst_ip_port: bytes | None, msg: bytes) -> None:
        if dst_ip_port is not None:
            print_str = b"[" + src_ip_port + b" > " + dst_ip_port + b"] " + T + msg + W
            for s in (b"Searched ", b"POST load:"):
                if s not in msg and self.write_log and os.path.isfile(self.log_path):
                    with open(self.log_path, "rb") as fh:
                        if msg in fh.read():
                            return
            self.out.write(self._textmode(print_str + b"\n"))
            self.out.flush()
            if self.write_log:
                with open(self.log_path, "ab") as fh:
                    fh.write(self._textmode(b"INFO:root:" + _ANSI.sub(b"", print_str) + b"\n"))
        else:
            print_str = b"[" + src_ip_port.split(b":")[0] + b"] " + msg
            self.out.write(self._textmode(print_str + b"\n"))
            self.out.flush()
        for listener in self.listeners:
            listener(src_ip_port, dst_ip_port, msg)
