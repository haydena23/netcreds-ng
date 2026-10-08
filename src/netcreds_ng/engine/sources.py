"""Frame sources: capture files/directories and live interfaces."""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netcreds_ng.engine.pcapio import RawFrame, open_capture

log = logging.getLogger(__name__)

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".dmp", ".pcap.gz")


def expand_capture_paths(paths: list[str]) -> list[str]:
    """Files are taken as given; directories contribute their capture files (sorted, non-recursive)."""
    out: list[str] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            out.extend(str(c) for c in sorted(path.iterdir()) if c.is_file() and c.name.lower().endswith(CAPTURE_SUFFIXES))
        else:
            out.append(str(path))
    return out


def file_frames(path: str) -> Iterator[RawFrame]:
    return open_capture(path)


@dataclass
class InterfaceInfo:
    name: str
    description: str
    addresses: list[str]
    up: bool


def list_interfaces() -> list[InterfaceInfo]:
    import psutil

    stats = psutil.net_if_stats()
    out = []
    for name, addrs in sorted(psutil.net_if_addrs().items()):
        ips = [a.address for a in addrs if a.family.name in ("AF_INET", "AF_INET6")]
        st = stats.get(name)
        out.append(InterfaceInfo(name, "", ips, bool(st and st.isup)))
    return out


def default_interface() -> str | None:
    """Interface carrying the default route, as scapy sees it."""
    try:
        from scapy.config import conf

        iface = conf.iface
        return str(getattr(iface, "name", iface)) if iface else None
    except Exception as exc:  # noqa: BLE001 - scapy/platform specific failures
        log.debug("could not determine default interface: %s", exc)
        return None


def bpf_exclude(hosts: list[str], extra: str | None = None) -> str | None:
    parts = []
    if hosts:
        parts.append("not (" + " or ".join(f"host {h}" for h in hosts) + ")")
    if extra:
        parts.append(f"({extra})")
    return " and ".join(parts) or None


class LiveCapture:
    """Runs scapy's sniffer in a thread and exposes frames as an iterator."""

    def __init__(self, interface: str, bpf: str | None = None, max_queue: int = 100_000) -> None:
        self.interface = interface
        self.bpf = bpf
        self._queue: queue.Queue[RawFrame | None] = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.dropped = 0
        self.error: BaseException | None = None
        self._index = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="netcreds-capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        try:
            import logging as _logging

            _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
            from scapy.config import conf
            from scapy.sendrecv import sniff

            l2num = conf.l2types.layer2num

            def handle(pkt: Any) -> None:
                self._index += 1
                data = bytes(pkt)
                linktype = l2num.get(type(pkt), 1)
                frame = RawFrame(self._index, float(getattr(pkt, "time", 0.0)), int(linktype), data, len(data))
                try:
                    self._queue.put_nowait(frame)
                except queue.Full:
                    self.dropped += 1

            sniff(iface=self.interface, prn=handle, store=False, filter=self.bpf,
                  stop_filter=lambda _p: self._stop.is_set())  # fmt: skip
        except BaseException as exc:  # noqa: BLE001 - surfaced to the caller
            self.error = exc
        finally:
            self._queue.put(None)

    def frames(self) -> Iterator[RawFrame]:
        while True:
            try:
                item = self._queue.get(timeout=0.25)
            except queue.Empty:
                if self._stop.is_set():
                    return
                continue
            if item is None:
                if self.error is not None:
                    raise self.error
                return
            yield item
