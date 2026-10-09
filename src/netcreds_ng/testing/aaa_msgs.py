"""Builders for RADIUS and TACACS+ messages used in tests and fixtures.

Fields that are obfuscated on the wire (RADIUS User-Password, CHAP responses, request
authenticators, encrypted TACACS+ bodies) are filled with obvious placeholder bytes;
nothing here performs or relies on cryptography.
"""

from __future__ import annotations

import struct

PLACEHOLDER = b"\xee" * 16  # stands in for any obfuscated / digest field
AUTHENTICATOR = b"\xaa" * 16

# --- RADIUS -----------------------------------------------------------------------


def radius_attr(atype: int, value: bytes) -> bytes:
    return bytes([atype, len(value) + 2]) + value


def radius_packet(
    code: int, ident: int, attrs: list[bytes] | bytes = b"", authenticator: bytes = AUTHENTICATOR
) -> bytes:
    body = attrs if isinstance(attrs, bytes) else b"".join(attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + authenticator + body


def radius_vsa(vendor: int, subtype: int, value: bytes) -> bytes:
    return radius_attr(26, struct.pack("!I", vendor) + bytes([subtype, len(value) + 2]) + value)


def eap_packet(code: int, ident: int, eap_type: int | None = None, data: bytes = b"") -> bytes:
    body = b"" if eap_type is None else bytes([eap_type]) + data
    return struct.pack("!BBH", code, ident, 4 + len(body)) + body


def eap_attrs(eap: bytes, chunk: int = 253) -> list[bytes]:
    """Split an EAP packet into EAP-Message (79) attributes."""
    return [radius_attr(79, eap[i : i + chunk]) for i in range(0, len(eap), chunk)] or [radius_attr(79, b"")]


def radius_nas_attrs(nas_ip: bytes = bytes([192, 0, 2, 1]), nas_id: bytes = b"nas-fake-1",
                     called: bytes = b"00-00-5E-00-53-01:FakeSSID") -> list[bytes]:  # fmt: skip
    return [radius_attr(4, nas_ip), radius_attr(32, nas_id), radius_attr(30, called)]


# --- TACACS+ ----------------------------------------------------------------------

TAC_UNENCRYPTED = 0x01
TAC_AUTHEN, TAC_AUTHOR, TAC_ACCT = 1, 2, 3


def tacacs_packet(ptype: int, seq: int, body: bytes, *, session_id: int = 0x0BADF00D,
                  flags: int = TAC_UNENCRYPTED, version: int = 0xC0) -> bytes:  # fmt: skip
    return struct.pack("!BBBBII", version, ptype, seq, flags, session_id, len(body)) + body


def tacacs_authen_start(user: bytes = b"", data: bytes = b"", *, action: int = 1, priv_lvl: int = 1,
                        authen_type: int = 1, service: int = 1, port: bytes = b"tty0",
                        rem_addr: bytes = b"192.0.2.99") -> bytes:  # fmt: skip
    return (
        bytes([action, priv_lvl, authen_type, service, len(user), len(port), len(rem_addr), len(data)])
        + user
        + port
        + rem_addr
        + data
    )


def tacacs_authen_continue(user_msg: bytes = b"", data: bytes = b"", flags: int = 0) -> bytes:
    return struct.pack("!HHB", len(user_msg), len(data), flags) + user_msg + data


def tacacs_authen_reply(status: int, server_msg: bytes = b"", data: bytes = b"", flags: int = 0) -> bytes:
    return struct.pack("!BBHH", status, flags, len(server_msg), len(data)) + server_msg + data


def _arg_block(user: bytes, port: bytes, rem_addr: bytes, args: list[bytes]) -> bytes:
    return (
        bytes([len(user), len(port), len(rem_addr), len(args)])
        + bytes(len(a) for a in args)
        + user
        + port
        + rem_addr
        + b"".join(args)
    )


def tacacs_author_request(user: bytes, args: list[bytes], *, authen_method: int = 6, priv_lvl: int = 15,
                          authen_type: int = 1, service: int = 1, port: bytes = b"tty0",
                          rem_addr: bytes = b"192.0.2.99") -> bytes:  # fmt: skip
    return bytes([authen_method, priv_lvl, authen_type, service]) + _arg_block(user, port, rem_addr, args)


def tacacs_author_response(status: int = 1, args: list[bytes] | None = None, server_msg: bytes = b"") -> bytes:
    args = args or []
    return (
        struct.pack("!BBHH", status, len(args), len(server_msg), 0)
        + bytes(len(a) for a in args)
        + server_msg
        + b"".join(args)
    )


def tacacs_acct_request(user: bytes, args: list[bytes], *, flags: int = 0x02, authen_method: int = 6,
                        priv_lvl: int = 15, authen_type: int = 1, service: int = 1, port: bytes = b"tty0",
                        rem_addr: bytes = b"192.0.2.99") -> bytes:  # fmt: skip
    return bytes([flags, authen_method, priv_lvl, authen_type, service]) + _arg_block(user, port, rem_addr, args)


def tacacs_acct_reply(status: int = 1, server_msg: bytes = b"") -> bytes:
    return struct.pack("!HHB", len(server_msg), 0, status) + server_msg
