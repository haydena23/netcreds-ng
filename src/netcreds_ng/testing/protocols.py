"""Builders for structurally valid protocol messages used in tests and fixtures.

All "encrypted" or response fields are filled with obvious placeholder bytes;
nothing here performs or relies on cryptography.
"""

from __future__ import annotations

import base64
import struct

# --- DER encoding ---------------------------------------------------------------


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_len(len(value)) + value


def der_int(v: int) -> bytes:
    raw = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, raw)


def der_octets(v: bytes) -> bytes:
    return tlv(0x04, v)


def der_gstr(v: str) -> bytes:
    return tlv(0x1B, v.encode())


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def ctx(n: int, value: bytes) -> bytes:
    return tlv(0xA0 | n, value)


def principal(name_type: int, *parts: str) -> bytes:
    return seq(ctx(0, der_int(name_type)), ctx(1, seq(*(der_gstr(p) for p in parts))))


def encrypted_data(etype: int, size: int = 52) -> bytes:
    return seq(ctx(0, der_int(etype)), ctx(2, der_octets(b"\xee" * size)))


# --- Kerberos -----------------------------------------------------------------


def as_req(user: str, realm: str, preauth_etype: int | None = 23, offered: tuple[int, ...] = (18, 17, 23)) -> bytes:
    padata = b""
    if preauth_etype is not None:
        pa = seq(ctx(1, der_int(2)), ctx(2, der_octets(encrypted_data(preauth_etype))))
        padata = ctx(3, seq(pa))
    body = seq(
        ctx(0, tlv(0x03, b"\x00\x40\x81\x00\x10")),
        ctx(1, principal(1, user)),
        ctx(2, der_gstr(realm)),
        ctx(3, principal(2, "krbtgt", realm)),
        ctx(5, tlv(0x18, b"20370913024805Z")),
        ctx(7, der_int(12345)),
        ctx(8, seq(*(der_int(e) for e in offered))),
    )
    return tlv(0x6A, seq(ctx(1, der_int(5)), ctx(2, der_int(10)), padata, ctx(4, body)))


def _ticket(realm: str, service: tuple[str, ...], etype: int) -> bytes:
    return tlv(0x61, seq(ctx(0, der_int(5)), ctx(1, der_gstr(realm)), ctx(2, principal(2, *service)),
                         ctx(3, encrypted_data(etype, 64))))  # fmt: skip


def kdc_rep(app: int, user: str, realm: str, service: tuple[str, ...], ticket_etype: int = 18) -> bytes:
    msg_type = 11 if app == 0x6B else 13
    return tlv(app, seq(
        ctx(0, der_int(5)), ctx(1, der_int(msg_type)), ctx(3, der_gstr(realm)), ctx(4, principal(1, user)),
        ctx(5, _ticket(realm, service, ticket_etype)), ctx(6, encrypted_data(ticket_etype, 40)),
    ))  # fmt: skip


def krb_error(code: int, realm: str, user: str | None = None) -> bytes:
    items = [ctx(0, der_int(5)), ctx(1, der_int(30)), ctx(4, tlv(0x18, b"20250101000000Z")), ctx(5, der_int(0)),
             ctx(6, der_int(code))]  # fmt: skip
    if user:
        items += [ctx(7, der_gstr(realm)), ctx(8, principal(1, user))]
    items += [ctx(9, der_gstr(realm)), ctx(10, principal(2, "krbtgt", realm))]
    return tlv(0x7E, seq(*items))


def krb_tcp(msg: bytes) -> bytes:
    return struct.pack("!I", len(msg)) + msg


# --- NTLM -----------------------------------------------------------------------


def ntlm_type2(target: str = "EXAMPLE") -> bytes:
    t = target.encode("utf-16-le")
    flags = 0x00000001 | 0x00000200 | 0x00080000
    header = b"NTLMSSP\x00" + struct.pack("<I", 2) + struct.pack("<HHI", len(t), len(t), 48) + struct.pack("<I", flags)
    header += b"\x11" * 8 + b"\x00" * 8 + struct.pack("<HHI", 0, 0, 48 + len(t))
    return header + t


def ntlm_type3(user: str, domain: str, workstation: str, nt_len: int = 64, lm_len: int = 24) -> bytes:
    flags = 0x00000001 | 0x00000200 | 0x00080000
    dom, usr, ws = (s.encode("utf-16-le") for s in (domain, user, workstation))
    lm, nt = b"\xaa" * lm_len, b"\xbb" * nt_len
    off = 72
    fields = []
    payload = b""
    for blob in (lm, nt, dom, usr, ws, b""):
        fields.append(struct.pack("<HHI", len(blob), len(blob), off + len(payload)))
        payload += blob
    msg = b"NTLMSSP\x00" + struct.pack("<I", 3) + b"".join(fields) + struct.pack("<I", flags) + b"\x00" * 8
    assert len(msg) == off
    return msg + payload


def b64(data: bytes) -> bytes:
    return base64.b64encode(data)


# --- SNMP -----------------------------------------------------------------------


def snmp_v1v2(community: str, version: int = 1, pdu_tag: int = 0xA0) -> bytes:
    varbind = seq(seq(tlv(0x06, b"\x2b\x06\x01\x02\x01\x01\x01\x00"), b"\x05\x00"))
    pdu = tlv(pdu_tag, der_int(1) + der_int(0) + der_int(0) + varbind)
    return seq(der_int(version), der_octets(community.encode()), pdu)


def snmp_v3(user: str, flags: int) -> bytes:
    global_data = seq(der_int(1), der_int(65507), der_octets(bytes([flags])), der_int(3))
    usm = seq(der_octets(b"\x80\x00\x1f\x88\x01"), der_int(1), der_int(100), der_octets(user.encode()),
              der_octets(b"\x00" * 12 if flags & 1 else b""), der_octets(b"\x00" * 8 if flags & 2 else b""))  # fmt: skip
    scoped = der_octets(b"\xcc" * 20) if flags & 2 else seq(der_octets(b""), der_octets(b""), tlv(0xA0, der_int(1) + der_int(0) + der_int(0) + seq()))
    return seq(der_int(3), global_data, der_octets(usm), scoped)
