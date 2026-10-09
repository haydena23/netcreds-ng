"""Builders for MSSQL (TDS) and Oracle Net (TNS) messages used in tests and fixtures.

Values are obviously fake. The MSSQL password is obfuscated with the real, public LOGIN7
transform so that de-obfuscation is tested end to end. Oracle challenge/response fields
(AUTH_SESSKEY, AUTH_PASSWORD, AUTH_VFR_DATA) are filled with placeholder bytes only.
"""

from __future__ import annotations

import struct

# ======================================================================================
# MSSQL / TDS
# ======================================================================================

TDS_PRELOGIN, TDS_LOGIN7, TDS_SSPI, TDS_TABULAR, TDS_SQL_BATCH = 0x12, 0x10, 0x11, 0x04, 0x01
ENCRYPT_OFF, ENCRYPT_ON, ENCRYPT_NOT_SUP, ENCRYPT_REQ = 0, 1, 2, 3


def tds_packets(ptype: int, payload: bytes, packet_size: int = 4096, spid: int = 0) -> bytes:
    """Split ``payload`` into TDS packets of at most ``packet_size`` bytes; EOM on the last."""
    chunk = packet_size - 8
    parts = [payload[i : i + chunk] for i in range(0, len(payload), chunk)] or [b""]
    out = bytearray()
    for i, part in enumerate(parts):
        status = 0x01 if i == len(parts) - 1 else 0x00
        out += struct.pack("!BBHHBB", ptype, status, 8 + len(part), spid, (i + 1) & 0xFF, 0) + part
    return bytes(out)


def prelogin(encryption: int, version: tuple[int, int, int, int] = (16, 0, 4100, 0), client: bool = True) -> bytes:
    """PRELOGIN option table + data (VERSION, ENCRYPTION, INSTOPT, [THREADID], MARS)."""
    opts: list[tuple[int, bytes]] = [
        (0x00, struct.pack("!BBHH", *version)),
        (0x01, bytes([encryption])),
        (0x02, b"\x00"),
    ]
    if client:
        opts.append((0x03, struct.pack("!I", 0x1234)))
    opts.append((0x04, b"\x00"))
    table_len = 5 * len(opts) + 1
    table, data = bytearray(), bytearray()
    for tok, val in opts:
        table += struct.pack("!BHH", tok, table_len + len(data), len(val))
        data += val
    return bytes(table) + b"\xff" + bytes(data)


def obfuscate_password(password: str) -> bytes:
    """The public LOGIN7 password transform: UTF-16LE, swap nibbles, XOR 0xA5."""
    return bytes((((b << 4) & 0xF0) | (b >> 4)) ^ 0xA5 for b in password.encode("utf-16-le"))


def login7(
    user: str = "alice",
    password: str = "Fake-Pass-1",
    host: str = "WS1",
    app: str = "FakeApp",
    server: str = "db.example.test",
    database: str = "appdb",
    *,
    integrated: bool = False,
    sspi: bytes = b"",
    new_password: str | None = None,
    tds_version: int = 0x74000004,
) -> bytes:
    """A LOGIN7 payload (TDS 7.2+ layout, 94-byte fixed part)."""
    utf = {
        "host": host.encode("utf-16-le"),
        "user": user.encode("utf-16-le"),
        "password": obfuscate_password(password),
        "app": app.encode("utf-16-le"),
        "server": server.encode("utf-16-le"),
        "extension": b"",
        "library": "ODBC".encode("utf-16-le"),
        "language": b"",
        "database": database.encode("utf-16-le"),
    }
    data = bytearray()
    offsets = bytearray()
    base = 94
    for raw in utf.values():
        offsets += struct.pack("<HH", base + len(data), len(raw) // 2)
        data += raw
    client_id = b"\x02\x00\x00\x00\x00\x01"
    sspi_off = base + len(data)
    data += sspi
    atch = struct.pack("<HH", base + len(data), 0)
    newpw = obfuscate_password(new_password) if new_password is not None else b""
    chg = struct.pack("<HH", base + len(data), len(newpw) // 2)
    data += newpw
    flags2 = 0x80 if integrated else 0x00
    flags3 = 0x01 if new_password is not None else 0x00
    fixed = struct.pack("<IIIIII", 0, tds_version, 4096, 0x07000000, 4242, 0)
    fixed += bytes([0xE0, flags2 | 0x03, 0x00, flags3]) + struct.pack("<iI", 0, 0x0409)
    fixed += bytes(offsets) + client_id + struct.pack("<HH", sspi_off, len(sspi)) + atch + chg
    fixed += struct.pack("<I", 0)
    assert len(fixed) == 94, len(fixed)
    body = fixed + bytes(data)
    return struct.pack("<I", len(body)) + body[4:]


def _us_varchar(s: str) -> bytes:
    raw = s.encode("utf-16-le")
    return struct.pack("<H", len(raw) // 2) + raw


def _b_varchar(s: str) -> bytes:
    raw = s.encode("utf-16-le")
    return bytes([len(raw) // 2]) + raw


def envchange_database(name: str = "appdb") -> bytes:
    body = b"\x01" + _b_varchar(name) + _b_varchar("master")
    return b"\xe3" + struct.pack("<H", len(body)) + body


def info_token(number: int = 5701, message: str = "Changed database context to 'appdb'.") -> bytes:
    body = (
        struct.pack("<iBB", number, 2, 0)
        + _us_varchar(message)
        + _b_varchar("FAKESRV")
        + _b_varchar("")
        + struct.pack("<i", 1)
    )
    return b"\xab" + struct.pack("<H", len(body)) + body


def loginack(program: str = "Microsoft SQL Server", tds_version: int = 0x74000004) -> bytes:
    body = b"\x01" + struct.pack("!I", tds_version) + _b_varchar(program) + bytes([16, 0, 0x10, 0x04])
    return b"\xad" + struct.pack("<H", len(body)) + body


def error_token(number: int = 18456, message: str = "Login failed for user 'alice'.") -> bytes:
    body = (
        struct.pack("<iBB", number, 1, 14)
        + _us_varchar(message)
        + _b_varchar("FAKESRV")
        + _b_varchar("")
        + struct.pack("<i", 1)
    )
    return b"\xaa" + struct.pack("<H", len(body)) + body


def done(status: int = 0) -> bytes:
    return b"\xfd" + struct.pack("<HHQ", status, 0, 0)


def login_ok_response() -> bytes:
    return envchange_database() + info_token() + loginack() + done()


def login_failed_response(message: str = "Login failed for user 'alice'.") -> bytes:
    return error_token(18456, message) + done(0x0002)


def sspi_token(blob: bytes) -> bytes:
    return b"\xed" + struct.pack("<H", len(blob)) + blob


def ntlm_negotiate() -> bytes:
    return b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", 0x00088207) + b"\x00" * 16


def ntlm_authenticate(user: str = "alice", domain: str = "EXAMPLE", workstation: str = "WS1") -> bytes:
    """NTLMSSP AUTHENTICATE with placeholder (0x11) response bytes."""
    payload = [
        b"\x11" * 24,
        b"\x11" * 48,
        domain.encode("utf-16-le"),
        user.encode("utf-16-le"),
        workstation.encode("utf-16-le"),
        b"",
    ]
    off = 64
    hdr = b"NTLMSSP\x00" + struct.pack("<I", 3)
    body = bytearray()
    for item in payload:
        hdr += struct.pack("<HHI", len(item), len(item), off + len(body))
        body += item
    hdr += struct.pack("<I", 0x00088205 | 0x01)
    return hdr + bytes(body)


# ======================================================================================
# Oracle / TNS
# ======================================================================================

TNS_CONNECT, TNS_ACCEPT, TNS_REFUSE, TNS_REDIRECT, TNS_DATA, TNS_RESEND = 1, 2, 4, 5, 6, 11

DESCRIPTOR = (
    b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=198.51.100.20)(PORT=1521))"
    b"(CONNECT_DATA=(SERVICE_NAME=ORCL)(CID=(PROGRAM=sqlplus)(HOST=ws1)(USER=alice))))"
)


def tns_packet(ptype: int, body: bytes, *, large: bool = False, flags: int = 0) -> bytes:
    length = 8 + len(body)
    if large:
        head = struct.pack("!I", length)
    else:
        head = struct.pack("!HH", length, 0)
    return head + struct.pack("!BBH", ptype, flags, 0) + body


def tns_connect(descriptor: bytes = DESCRIPTOR, version: int = 314, *, separate: bool | None = None) -> bytes:
    """A CONNECT packet; descriptors longer than 230 bytes (or ``separate=True``) follow in a DATA packet."""
    if separate is None:
        separate = len(descriptor) > 230
    offset = 58
    fixed = struct.pack("!HHHHHHHH", version, 300, 0x0C41, 8192, 65535, 0x7F08, 0, 0x0100)
    fixed += struct.pack("!HHIBB", len(descriptor), offset, 2048, 0x41, 0x41)
    fixed += b"\x00" * (offset - 8 - len(fixed))
    if separate:
        return tns_packet(TNS_CONNECT, fixed) + tns_data(descriptor)
    return tns_packet(TNS_CONNECT, fixed + descriptor)


def tns_accept(version: int = 314) -> bytes:
    body = struct.pack("!HHHHHHHBB", version, 0x0C41, 8192, 65535, 0x0100, 0, 32, 0x41, 0x41) + b"\x00" * 8
    return tns_packet(TNS_ACCEPT, body)


def tns_refuse(err: int = 12514) -> bytes:
    data = f"(DESCRIPTION=(TMP=)(VSNNUM=0)(ERR={err})(ERROR_STACK=(ERROR=(CODE={err})(EMFI=4))))".encode()
    return tns_packet(TNS_REFUSE, bytes([34, 0]) + struct.pack("!H", len(data)) + data)


def tns_data(payload: bytes, *, flags: int = 0, large: bool = False) -> bytes:
    return tns_packet(TNS_DATA, struct.pack("!H", flags) + payload, large=large)


def ano_response(algorithm: int = 17) -> bytes:
    """ANO negotiation answer (supervisor, authentication, encryption, data integrity)."""

    def sub(stype: int, value: bytes) -> bytes:
        return struct.pack("!HH", len(value), stype) + value

    def service(sid: int, subs: list[bytes]) -> bytes:
        return struct.pack("!HHI", sid, len(subs), 0) + b"".join(subs)

    version = sub(5, struct.pack("!I", 0x13000000))
    services = [
        service(4, [version, sub(6, b"\x00\x00\x00\x00\x00\x00\x00\x00")]),
        service(1, [version, sub(3, b"\xfb\xfb")]),
        service(2, [version, sub(2, bytes([algorithm]))]),
        service(3, [version, sub(2, b"\x00")]),
    ]
    body = b"".join(services)
    return tns_data(b"\xde\xad\xbe\xef" + struct.pack("!HIHB", 13 + len(body), 0x13000000, len(services), 0) + body)


def _thin_ub4(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([len(raw)]) + raw


def _kv(key: bytes, value: bytes, style: str) -> bytes:
    if style == "thin":
        out = _thin_ub4(len(key)) + bytes([len(key)]) + key + _thin_ub4(len(value))
        if value:
            out += bytes([len(value)]) + value
        return out + b"\x00"
    out = struct.pack("<I", len(key)) + bytes([len(key)]) + key + struct.pack("<I", len(value))
    if value:
        out += bytes([len(value)]) + value
    return out + b"\x00\x00\x00\x00"


def _auth_request(func: int, user: bytes, pairs: list[tuple[bytes, bytes]], style: str) -> bytes:
    head = bytes([0x03, func, 0x02])
    if style == "thin":
        head += b"\x01" + _thin_ub4(len(user)) + _thin_ub4(1) + b"\x01" + _thin_ub4(len(pairs)) + b"\x01\x01"
    else:
        head += b"\x01\x01" + bytes([len(user)]) + b"\x01\x01\x01" + bytes([len(pairs)]) + b"\x01\x01"
    if user:
        head += bytes([len(user)]) + user
    return head + b"".join(_kv(k, v, style) for k, v in pairs)


def auth_phase_one(user: bytes = b"alice", style: str = "thin") -> bytes:
    pairs = [
        (b"AUTH_TERMINAL", b"pts/0"),
        (b"AUTH_PROGRAM_NM", b"sqlplus@ws1 (TNS V1-V3)"),
        (b"AUTH_MACHINE", b"ws1.example.test"),
        (b"AUTH_PID", b"4242"),
        (b"AUTH_SID", b"alice"),
    ]
    return tns_data(_auth_request(0x76, user, pairs, style))


#: Placeholder challenge/response values; tests assert these never reach a finding.
PLACEHOLDER_SESSKEY = b"AB" * 32
PLACEHOLDER_PASSWORD = b"CD" * 32
PLACEHOLDER_VFR = b"EF" * 8


def auth_phase_one_response() -> bytes:
    body = (
        b"\x08\x03" + _kv(b"AUTH_SESSKEY", PLACEHOLDER_SESSKEY, "thin") + _kv(b"AUTH_VFR_DATA", PLACEHOLDER_VFR, "thin")
    )
    return tns_data(body)


def auth_phase_two(user: bytes = b"alice", style: str = "thin") -> bytes:
    pairs = [
        (b"AUTH_SESSKEY", PLACEHOLDER_SESSKEY),
        (b"AUTH_PASSWORD", PLACEHOLDER_PASSWORD),
        (b"AUTH_TERMINAL", b"pts/0"),
    ]
    return tns_data(_auth_request(0x73, user, pairs, style))


def auth_ok_response() -> bytes:
    body = b"\x08\x05" + _kv(b"AUTH_VERSION_STRING", b"- Fake Edition", "thin") + _kv(b"AUTH_SESSION_ID", b"77", "thin")
    return tns_data(body)


def auth_failed_response(code: int = 1017) -> bytes:
    return tns_data(b"\x04\x01\x00" + f"ORA-{code:05d}: invalid username/password; logon denied\n".encode())
