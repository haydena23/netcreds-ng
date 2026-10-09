"""Builders for RDP connection-negotiation messages (MS-RDPBCGR 2.2.1.1 / 2.2.1.2).

Only the cleartext TPKT + X.224 negotiation is built; everything after it is
TLS / CredSSP (or legacy RDP security) and is never modelled here.
"""

from __future__ import annotations

import struct

PROTOCOL_RDP = 0x00
PROTOCOL_SSL = 0x01
PROTOCOL_HYBRID = 0x02
PROTOCOL_RDSTLS = 0x04
PROTOCOL_HYBRID_EX = 0x08


def tpkt(payload: bytes) -> bytes:
    """TPKT header (RFC 1006): version 3, reserved 0, big-endian total length."""
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


def x224(code: int, variable: bytes, src_ref: int = 0) -> bytes:
    """X.224 TPDU with fixed part (code, DST-REF, SRC-REF, class 0) and a variable part."""
    fixed = bytes([code]) + struct.pack("!HHB", 0, src_ref, 0)
    return bytes([len(fixed) + len(variable)]) + fixed + variable


def neg_req(protocols: int, flags: int = 0) -> bytes:
    return struct.pack("<BBHI", 0x01, flags, 8, protocols)


def neg_rsp(selected: int, flags: int = 0) -> bytes:
    return struct.pack("<BBHI", 0x02, flags, 8, selected)


def neg_failure(code: int) -> bytes:
    return struct.pack("<BBHI", 0x03, 0, 8, code)


def connection_request(cookie: bytes | None = None, protocols: int | None = None, routing_token: bytes | None = None) -> bytes:
    """Client X.224 Connection Request: optional mstshash cookie or routing token, optional RDP_NEG_REQ."""
    variable = b""
    if routing_token is not None:
        variable += b"Cookie: msts=" + routing_token + b"\r\n"
    elif cookie is not None:
        variable += b"Cookie: mstshash=" + cookie + b"\r\n"
    if protocols is not None:
        variable += neg_req(protocols)
    return tpkt(x224(0xE0, variable))


def connection_confirm(selected: int | None = None, failure: int | None = None) -> bytes:
    """Server X.224 Connection Confirm with RDP_NEG_RSP, RDP_NEG_FAILURE, or no negotiation data."""
    variable = b""
    if failure is not None:
        variable = neg_failure(failure)
    elif selected is not None:
        variable = neg_rsp(selected)
    return tpkt(x224(0xD0, variable, src_ref=0x1234))
