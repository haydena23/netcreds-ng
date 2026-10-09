"""Dependency-free pcap / pcapng reader.

Yields :class:`RawFrame` objects carrying the link type of the interface that
captured them, so the decoder never has to assume Ethernet. Truncated or
malformed files raise :class:`CaptureFormatError` *after* yielding every
complete frame, so callers can report the problem without losing data.
"""

from __future__ import annotations

import gzip
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO, cast

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D
GZIP_MAGIC = b"\x1f\x8b"

MAX_FRAME = 256 * 1024 * 1024  # sanity bound for corrupt length fields


class CaptureFormatError(Exception):
    """The capture file is not a supported format or is corrupt/truncated."""


@dataclass(frozen=True)
class RawFrame:
    index: int  # 1-based frame number, as Wireshark shows it
    timestamp: float  # seconds since epoch
    linktype: int
    data: bytes
    wirelen: int


def open_capture(path: str) -> Iterator[RawFrame]:
    """Iterate frames of a pcap or pcapng file, gzip-compressed or not (detected by content)."""
    with open(path, "rb") as raw:
        if raw.read(2) == GZIP_MAGIC:
            raw.seek(0)
            with gzip.GzipFile(fileobj=raw, mode="rb") as gz:
                try:
                    yield from _read_any(cast(BinaryIO, gz))
                except (EOFError, OSError, zlib.error) as exc:
                    # Truncated or corrupt compressed stream: frames before it were yielded.
                    raise CaptureFormatError(f"corrupt gzip stream: {exc}") from exc
        else:
            raw.seek(0)
            yield from _read_any(raw)


def _read_any(fh: BinaryIO) -> Iterator[RawFrame]:
    head = fh.read(4)
    if len(head) == 0:
        raise CaptureFormatError("empty file")
    if len(head) < 4:
        raise CaptureFormatError("file too short to be a capture")
    fh.seek(0)
    (magic_le,) = struct.unpack("<I", head)
    (magic_be,) = struct.unpack(">I", head)
    if magic_le == PCAPNG_SHB:
        yield from _read_pcapng(fh)
    elif PCAP_MAGIC_US in (magic_le, magic_be) or PCAP_MAGIC_NS in (magic_le, magic_be):
        yield from _read_pcap(fh)
    else:
        raise CaptureFormatError("not a pcap or pcapng file")


def _read_pcap(fh: BinaryIO) -> Iterator[RawFrame]:
    header = fh.read(24)
    if len(header) < 24:
        raise CaptureFormatError("truncated pcap global header")
    (magic,) = struct.unpack("<I", header[:4])
    if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        endian = "<"
    else:
        endian = ">"
        (magic,) = struct.unpack(">I", header[:4])
    divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    _vmaj, _vmin, _zone, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", header[4:])
    # Some writers put FCS info in the upper bits of the link type field.
    linktype &= 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    index = 0
    while True:
        rh = fh.read(16)
        if not rh:
            return
        if len(rh) < 16:
            raise CaptureFormatError(f"truncated record header after frame {index}")
        sec, frac, incl, orig = rec.unpack(rh)
        if incl > MAX_FRAME:
            raise CaptureFormatError(f"corrupt record length {incl} after frame {index}")
        data = fh.read(incl)
        if len(data) < incl:
            raise CaptureFormatError(f"truncated frame data in frame {index + 1}")
        index += 1
        yield RawFrame(index, sec + frac / divisor, linktype, data, orig)


@dataclass
class _Interface:
    linktype: int
    tsresol: float = 1e-6
    snaplen: int = 0


def _parse_options(body: bytes, endian: str) -> dict[int, bytes]:
    opts: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[pos : pos + 4])
        pos += 4
        if code == 0:
            break
        opts[code] = body[pos : pos + length]
        pos += (length + 3) & ~3
    return opts


def _tsresol(raw: bytes) -> float:
    if not raw:
        return 1e-6
    value = raw[0]
    if value & 0x80:
        return 2.0 ** -(value & 0x7F)
    return 10.0 ** -value


def _read_pcapng(fh: BinaryIO) -> Iterator[RawFrame]:
    endian = "<"
    interfaces: list[_Interface] = []
    index = 0
    while True:
        bh = fh.read(8)
        if not bh:
            return
        if len(bh) < 8:
            raise CaptureFormatError(f"truncated block header after frame {index}")
        (btype_le,) = struct.unpack("<I", bh[:4])
        if btype_le == PCAPNG_SHB:
            bom = fh.read(4)
            if len(bom) < 4:
                raise CaptureFormatError("truncated section header")
            if struct.unpack("<I", bom)[0] == PCAPNG_BOM:
                endian = "<"
            elif struct.unpack(">I", bom)[0] == PCAPNG_BOM:
                endian = ">"
            else:
                raise CaptureFormatError("bad pcapng byte-order magic")
            (blen,) = struct.unpack(endian + "I", bh[4:8])
            if blen < 28 or blen > MAX_FRAME:
                raise CaptureFormatError(f"corrupt section header length {blen}")
            rest = fh.read(blen - 12)
            if len(rest) < blen - 12:
                raise CaptureFormatError("truncated section header")
            interfaces = []  # interface ids are scoped to a section
            continue
        btype, blen = struct.unpack(endian + "II", bh)
        if blen < 12 or blen > MAX_FRAME or blen % 4:
            raise CaptureFormatError(f"corrupt block length {blen} after frame {index}")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            raise CaptureFormatError(f"truncated block after frame {index}")
        body = body[:-4]  # trailing block length
        if btype == 1:  # Interface Description Block
            if len(body) < 8:
                raise CaptureFormatError("truncated interface description block")
            linktype, _res, snaplen = struct.unpack(endian + "HHI", body[:8])
            opts = _parse_options(body[8:], endian)
            interfaces.append(_Interface(linktype, _tsresol(opts.get(9, b"")), snaplen))
        elif btype in (6, 2):  # Enhanced Packet Block / obsolete Packet Block
            if len(body) < 20:
                raise CaptureFormatError(f"truncated packet block in frame {index + 1}")
            if btype == 6:
                iface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", body[:20])
            else:
                iface_id, _drops, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "HHIIII", body[:20])
            data = body[20 : 20 + caplen]
            if len(data) < caplen:
                raise CaptureFormatError(f"truncated packet data in frame {index + 1}")
            if iface_id >= len(interfaces):
                raise CaptureFormatError(f"packet references unknown interface {iface_id}")
            iface = interfaces[iface_id]
            index += 1
            yield RawFrame(index, ((ts_hi << 32) | ts_lo) * iface.tsresol, iface.linktype, data, origlen)
        elif btype == 3:  # Simple Packet Block
            if not interfaces:
                raise CaptureFormatError("simple packet block without interface")
            if len(body) < 4:
                raise CaptureFormatError(f"truncated simple packet block in frame {index + 1}")
            (origlen,) = struct.unpack(endian + "I", body[:4])
            iface = interfaces[0]
            caplen = min(origlen, iface.snaplen) if iface.snaplen else origlen
            data = body[4 : 4 + caplen]
            index += 1
            yield RawFrame(index, 0.0, iface.linktype, data, origlen)
        # Other block types (name resolution, statistics, custom...) are skipped.


class PcapWriter:
    """Minimal classic-pcap writer (microsecond resolution). Used for fixtures and exports."""

    def __init__(self, fh: BinaryIO, linktype: int = 1, snaplen: int = 262144) -> None:
        self._fh = fh
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, linktype))

    def write(self, data: bytes, timestamp: float = 0.0, wirelen: int | None = None) -> None:
        sec = int(timestamp)
        usec = round((timestamp - sec) * 1e6)
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self._fh.write(struct.pack("<IIII", sec, usec, len(data), wirelen if wirelen is not None else len(data)))
        self._fh.write(data)


class PcapngWriter:
    """Minimal pcapng writer: one interface per link type, microsecond timestamps, and an
    optional comment per packet (shown by Wireshark as a packet comment)."""

    def __init__(self, fh: BinaryIO, application: str = "netcreds-ng", snaplen: int = 262144) -> None:
        self._fh = fh
        self._snaplen = snaplen
        self._interfaces: dict[int, int] = {}  # linktype -> interface id
        shb_opts = _option(4, application.encode("utf-8")) + _END_OF_OPTIONS
        self._block(PCAPNG_SHB, struct.pack("<IHHq", PCAPNG_BOM, 1, 0, -1) + shb_opts)

    def write(self, data: bytes, timestamp: float = 0.0, linktype: int = 1, wirelen: int | None = None,
              comment: str | None = None) -> None:  # fmt: skip
        iface = self._interfaces.get(linktype)
        if iface is None:
            iface = self._interfaces[linktype] = len(self._interfaces)
            self._block(0x00000001, struct.pack("<HHI", linktype, 0, self._snaplen))
        ts = round(timestamp * 1e6)
        body = struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF, len(data),
                           wirelen if wirelen is not None else len(data))  # fmt: skip
        body += data + b"\0" * (-len(data) % 4)
        if comment:
            body += _option(1, comment.encode("utf-8")) + _END_OF_OPTIONS
        self._block(0x00000006, body)

    def _block(self, btype: int, body: bytes) -> None:
        total = 12 + len(body)
        self._fh.write(struct.pack("<II", btype, total) + body + struct.pack("<I", total))


_END_OF_OPTIONS = b"\0\0\0\0"


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\0" * (-len(value) % 4)
