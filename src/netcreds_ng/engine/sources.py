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

CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".dmp", ".pcap.gz", ".pcapng.gz")


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


#: Adapter names that are rarely the one to watch: hypervisor switches, VPN overlays, container bridges.
_VIRTUAL = ("vethernet", "virtualbox", "vmware", "vmnet", "docker", "br-", "veth", "virbr", "tailscale", "zerotier",
            "wireguard", "utun", "loopback", "npcap loopback")  # fmt: skip


def default_interface() -> str | None:
    """Interface carrying the default route, as scapy sees it; else the best-looking active interface."""
    found = _scapy_default_interface()
    if found:
        return found
    try:
        return pick_interface(list_interfaces())
    except Exception as exc:  # noqa: BLE001 - psutil failures
        log.debug("could not list interfaces: %s", exc)
        return None


def _scapy_default_interface() -> str | None:
    try:
        # scapy fills conf.iface only once its routing table is loaded; scapy.config alone leaves it None.
        import scapy.route  # noqa: F401
        from scapy.config import conf

        iface = conf.iface
        return str(getattr(iface, "name", iface)) if iface else None
    except Exception as exc:  # noqa: BLE001 - scapy/platform specific failures
        log.debug("could not determine default interface from scapy: %s", exc)
        return None


def pick_interface(interfaces: list[InterfaceInfo]) -> str | None:
    """First interface that is up with a routable IPv4 address, preferring physical adapters."""

    def routable(addr: str) -> bool:
        return "." in addr and not addr.startswith(("127.", "169.254.", "0."))

    candidates = [i for i in interfaces if i.up and any(routable(a) for a in i.addresses)]
    physical = [i for i in candidates if not i.name.lower().startswith(_VIRTUAL)]
    chosen = (physical or candidates)[:1]
    return chosen[0].name if chosen else None


def capture_permission_problem() -> str | None:
    """Why live capture cannot work for this user, or None if it should (or cannot be told in advance).

    Elevation is not always needed: Npcap lets ordinary users capture unless it was installed as
    "administrators only"; on Linux a non-root user may have CAP_NET_RAW; on macOS /dev/bpf* may be
    readable (Wireshark's ChmodBPF).
    """
    import os
    import sys

    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as key:
                try:
                    admin_only = int(winreg.QueryValueEx(key, "AdminOnly")[0])
                except OSError:
                    admin_only = 0  # not set: Npcap's default allows every user
        except OSError:
            return "live capture needs Npcap: install it from https://npcap.com and try again"
        if admin_only and not _is_windows_admin():
            return "Npcap is installed for administrators only: run netcreds-ng from an Administrator terminal"
        return None
    if os.geteuid() == 0:
        return None
    import socket

    if sys.platform.startswith("linux"):
        try:
            socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()  # type: ignore[attr-defined,unused-ignore]
        except PermissionError:
            return ("live capture needs root or the CAP_NET_RAW capability: run with sudo, or "
                    "sudo setcap cap_net_raw,cap_net_admin=eip on the Python interpreter")  # fmt: skip
        except OSError:
            return None
        return None
    if sys.platform == "darwin" and not os.access("/dev/bpf0", os.R_OK):
        return "live capture needs read access to /dev/bpf*: run with sudo, or install Wireshark's ChmodBPF"
    return None


def _is_windows_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined,unused-ignore]
    except Exception:  # noqa: BLE001
        return False


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
