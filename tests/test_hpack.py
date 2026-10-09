"""HPACK decoder tests: RFC 7541 Appendix C examples (byte-exact) plus malformed input."""

from __future__ import annotations

import pytest

from netcreds_ng.proto.hpack import (
    HUFFMAN_CODES,
    HUFFMAN_LENGTHS,
    Decoder,
    HpackError,
    decode_integer,
    huffman_decode,
)
from netcreds_ng.testing.h2_msgs import Encoder, encode_integer, huffman_encode


def h(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr.replace(" ", ""))


def pairs(headers) -> list[tuple[bytes, bytes]]:
    return [(x.name, x.value) for x in headers]


# --------------------------------------------------------------------- Huffman table


def test_huffman_code_is_complete_prefix_code():
    assert sum(2.0**-n for n in HUFFMAN_LENGTHS) == 1.0


@pytest.mark.parametrize(
    ("sym", "code", "length"),
    [
        (0, 0x1FF8, 13), (1, 0x7FFFD8, 23), (9, 0xFFFFEA, 24), (10, 0x3FFFFFFC, 30), (13, 0x3FFFFFFD, 30),
        (22, 0x3FFFFFFE, 30), (32, 0x14, 6), (48, 0x0, 5), (58, 0x5C, 7), (60, 0x7FFC, 15), (88, 0xFC, 8),
        (92, 0x7FFF0, 19), (97, 0x3, 5), (122, 0x7B, 7), (126, 0x1FFD, 13), (127, 0xFFFFFFC, 28),
        (128, 0xFFFE6, 20), (153, 0x1FFFDC, 21), (199, 0x1FFFFEC, 25), (203, 0x7FFFFDE, 27),
        (220, 0xFFFFFFD, 28), (249, 0xFFFFFFE, 28), (254, 0x7FFFFF0, 27), (255, 0x3FFFFEE, 26),
        (256, 0x3FFFFFFF, 30),
    ],
)  # fmt: skip
def test_huffman_codes_match_rfc_table(sym, code, length):
    assert HUFFMAN_CODES[sym] == (code, length)


def test_huffman_roundtrip_all_bytes():
    data = bytes(range(256)) * 2
    assert huffman_decode(huffman_encode(data)) == data


@pytest.mark.parametrize(
    "bad",
    [
        b"\xff\xff\xff\xff",  # EOS (30 ones) inside the string
        b"\x00",  # '0' (00000) followed by 3 zero bits of padding
        b"\x1f\xff",  # 'a' then 11 one bits: padding longer than 7 bits
    ],
)
def test_huffman_rejects_invalid(bad):
    with pytest.raises(HpackError):
        huffman_decode(bad)


# --------------------------------------------------------------------- integers (C.1)


def test_integer_examples_c1():
    assert decode_integer(bytes([0b01010]), 0, 5) == (10, 1)
    assert decode_integer(h("1f9a0a"), 0, 5) == (1337, 3)
    assert decode_integer(bytes([42]), 0, 8) == (42, 1)
    assert encode_integer(1337, 5) == h("1f9a0a")


@pytest.mark.parametrize("bad", [b"", b"\x1f", b"\x1f\x80", b"\x1f" + b"\xff" * 10])
def test_integer_rejects_truncated_or_huge(bad):
    with pytest.raises(HpackError):
        decode_integer(bad, 0, 5)


# --------------------------------------------------------------------- C.2


def test_c2_1_literal_with_indexing():
    d = Decoder()
    out = d.decode(h("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572"))
    assert pairs(out) == [(b"custom-key", b"custom-header")]
    assert d.table == [(b"custom-key", b"custom-header")] and d.table_bytes == 55


def test_c2_2_literal_without_indexing():
    d = Decoder()
    assert pairs(d.decode(h("040c 2f73 616d 706c 652f 7061 7468"))) == [(b":path", b"/sample/path")]
    assert d.table == [] and d.table_bytes == 0


def test_c2_3_never_indexed():
    d = Decoder()
    (hdr,) = d.decode(h("1008 7061 7373 776f 7264 0673 6563 7265 74"))
    assert (hdr.name, hdr.value, hdr.never_indexed) == (b"password", b"secret", True)
    assert d.table == []


def test_c2_4_indexed():
    d = Decoder()
    assert pairs(d.decode(h("82"))) == [(b":method", b"GET")]
    assert d.table == []


# --------------------------------------------------------------------- C.3 / C.4 requests

REQ1 = [(b":method", b"GET"), (b":scheme", b"http"), (b":path", b"/"), (b":authority", b"www.example.com")]
REQ2 = [*REQ1, (b"cache-control", b"no-cache")]
REQ3 = [(b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/index.html"),
        (b":authority", b"www.example.com"), (b"custom-key", b"custom-value")]  # fmt: skip
TABLE1 = [(b":authority", b"www.example.com")]
TABLE2 = [(b"cache-control", b"no-cache"), *TABLE1]
TABLE3 = [(b"custom-key", b"custom-value"), *TABLE2]

C3 = [
    "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
    "8286 84be 5808 6e6f 2d63 6163 6865",
    "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
]
C4 = [
    "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
    "8286 84be 5886 a8eb 1064 9cbf",
    "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
]


@pytest.mark.parametrize("blocks", [C3, C4], ids=["C.3-plain", "C.4-huffman"])
def test_request_sequence(blocks):
    d = Decoder()
    expected = [(REQ1, TABLE1, 57), (REQ2, TABLE2, 110), (REQ3, TABLE3, 164)]
    for block, (headers, table, size) in zip(blocks, expected, strict=True):
        assert pairs(d.decode(h(block))) == headers
        assert d.table == table
        assert d.table_bytes == size


# --------------------------------------------------------------------- C.6 responses (eviction, Huffman)

DATE1 = b"Mon, 21 Oct 2013 20:13:21 GMT"
DATE2 = b"Mon, 21 Oct 2013 20:13:22 GMT"
LOC = b"https://www.example.com"
COOKIE = b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
C6 = [
    "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6"
    "2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
    "4883 640e ffc1 c0bf",
    "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab"
    "77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f"
    "9587 3160 65c0 03ed 4ee5 b106 3d50 07",
]


def test_c6_responses_with_eviction():
    d = Decoder(max_table_size=256)
    out = pairs(d.decode(h(C6[0])))
    assert out == [(b":status", b"302"), (b"cache-control", b"private"), (b"date", DATE1), (b"location", LOC)]
    assert d.table_bytes == 222
    out = pairs(d.decode(h(C6[1])))
    assert out == [(b":status", b"307"), (b"cache-control", b"private"), (b"date", DATE1), (b"location", LOC)]
    assert d.table_bytes == 222
    assert d.table[0] == (b":status", b"307")
    out = pairs(d.decode(h(C6[2])))
    assert out == [
        (b":status", b"200"), (b"cache-control", b"private"), (b"date", DATE2), (b"location", LOC),
        (b"content-encoding", b"gzip"), (b"set-cookie", COOKIE),
    ]  # fmt: skip
    assert d.table == [(b"set-cookie", COOKIE), (b"content-encoding", b"gzip"), (b"date", DATE2)]
    assert d.table_bytes == 215


# --------------------------------------------------------------------- dynamic table behaviour


def test_size_update_evicts_and_is_bounded():
    d = Decoder()
    d.decode(h(C3[0]))
    d.decode(h(C3[1]))
    assert len(d.table) == 2
    d.decode(b"\x20")  # size update to 0 clears the table
    assert d.table == [] and d.max_table_size == 0
    with pytest.raises(HpackError):
        d.decode(encode_integer(8192, 5, 0x20))  # above the advertised limit (4096)
    d.allow_table_size(8192)
    d.decode(encode_integer(8192, 5, 0x20))
    assert d.max_table_size == 8192


def test_size_update_after_header_is_rejected():
    with pytest.raises(HpackError):
        Decoder().decode(h("82 20"))


def test_oversized_entry_clears_table():
    enc, d = Encoder(max_table_size=64), Decoder()
    d.decode(enc.size_update(64))
    d.decode(enc.literal(b"x-a", b"1"))
    assert len(d.table) == 1
    d.decode(enc.literal(b"x-big", b"v" * 100))
    assert d.table == [] and len(enc.table) == 0


def test_encoder_decoder_roundtrip_with_huffman_and_never_indexed():
    enc, d = Encoder(), Decoder()
    block = enc.literal(b"authorization", b"Basic ZmFrZQ==", mode="never", huffman=True)
    block += enc.literal(b"x-custom", b"abc", mode="index", huffman=True, name_index=False)
    out = d.decode(block)
    assert [(x.name, x.value, x.never_indexed) for x in out] == [
        (b"authorization", b"Basic ZmFrZQ==", True), (b"x-custom", b"abc", False),
    ]  # fmt: skip
    assert pairs(d.decode(enc.encode([(b"x-custom", b"abc")]))) == [(b"x-custom", b"abc")]


@pytest.mark.parametrize(
    "bad",
    [
        b"\x80",  # index 0
        b"\xbe",  # index 62 with an empty dynamic table
        b"\x40\x05ab",  # truncated name
        b"\x41\x85\xff",  # truncated Huffman value
        b"\x00\x81\x00\x00",  # bad Huffman padding in the name
        b"\x7f\xff\xff\xff\xff\x0f",  # huge index
    ],
)
def test_malformed_blocks_raise_hpack_error(bad):
    with pytest.raises(HpackError):
        Decoder().decode(bad)
