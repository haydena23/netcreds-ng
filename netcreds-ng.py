#!/usr/bin/python

"""
To-Do:
* PCAP-NG Parsing
* Update function
* Multiple OS support
* Packet Parsing
* Rich for better dashboard
* Parse SNMP & Kerberos UDP/TCP
* TCP
* Telnet
* FTP
"""

from __future__ import annotations

import logging
import argparse
import platform
from subprocess import Popen, PIPE, DEVNULL
from typing import Optional, Sequence, List, ByteString
from os import geteuid # type: ignore
from scapy.all import PcapReader, sniff, conf, Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.snmp import SNMP

APP_NAME = "netcreds-ng"
__version__ = "1.0.0"

SUCCESS = 0
ERROR = 1
INTERRUPT = 130
ROOT = 0

class LoggingFormatter(logging.Formatter):
    def __init__(self, fmt_debug: str, fmt_info: str):
        super().__init__()
        self.fmt_debug = fmt_debug
        self.fmt_info = fmt_info

    def format(self, record: logging.LogRecord) -> str:
        if record.levelno == logging.DEBUG:
            self._style._fmt = self.fmt_debug
        else:
            self._style._fmt = self.fmt_info
        return super().format(record)

def update() -> None:
    """Check for the latest version. Update if requested."""
    
def interface_finder() -> Optional[str]:
    """Search for a valid interface, depending on the OS"""
    os = platform.system()
    if os == "Linux":
        ip_route = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DEVNULL)
        for line in ip_route.communicate()[0].splitlines():
            if b"default" in line:
                interface = line.split()[4]
                return interface.decode("utf-8")
    else:
        print(f"[!] Currently only Linux is supported")
        SystemExit(ERROR)

def bfp_filter(ips : List[str]) -> Optional[str]:
    """Build filter string containing IPs to exclude"""
    if not ips:
        return None
    return "Not Host(s): " + ", ".join(f"{ip}" for ip in ips)

def parse_packet(packet : Ether) -> None:
    """Parse a network packet"""

    load: Optional[ByteString] = None
    if packet.haslayer(Raw):
        load = packet[Raw].load
    
    """
    Drop Ethernet packets with just a raw load because these are usually network
    controls such as flow control
    """
    if (packet.haslayer(Ether)
        and packet.haslayer(Raw)
        and not packet.haslayer(IP)
        and not packet.haslayer(IPv6)):
        return
    
    if packet.haslayer(UDP) and packet.haslayer(IP):
        src_ip_port: str = str(packet[IP].src) + ":" + str(packet[UDP].sport)
        dst_ip_port: str = str(packet[IP].dst) + ':' + str(packet[UDP].dport)

        if packet.haslayer(SNMP):
            parse_snmp(src_ip_port, dst_ip_port, packet[SNMP])
            return
    
    logging.debug(load)

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=APP_NAME
    )

    parser.add_argument("-i", "--interface", help="Choose an interface")
    parser.add_argument("-p", "--pcap", help="Parse info from a pcap file")
    parser.add_argument("-u", "--update", help="Update to the latest version of netcreds-ng")

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("-f", "--filter", help="Do not sniff packets from host1,host2,...", type=str)
    filter_group.add_argument("-F", "--filterfile", help="Do not sniff packets new-line delimeted file", type=str)
    
    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument("-v", "--verbose", help="Display entire URLs and POST loads rather than truncating at 100 characters", action="store_true")
    verbose_group.add_argument("-q", "--quiet", help="Supress logging", action="store_true")
    
    args = parser.parse_args(argv)

    # Setup logging
    fmt_debug = "[%(asctime)s] [DEBUG] %(filename)s:%(lineno)d: %(message)s"
    fmt_info = "[%(levelname)s] %(message)s"

    handler = logging.StreamHandler()
    handler.setFormatter(LoggingFormatter(fmt_debug, fmt_info))
    log_level: int = (
        logging.DEBUG if args.verbose
        else logging.CRITICAL if args.quiet
        else logging.INFO
    )
    logging.basicConfig(
        handlers=[handler],
        level=log_level
    )

    if args.update:
        try:
            update()
            return SUCCESS
        except Exception as e:
            logging.error(f"[!] Error updating netcreds-ng: {e}")
            return ERROR

    if args.pcap is not None:
        try:
            for packet in PcapReader(args.pcap):
                parse_packet(packet)
        except IOError as e:
            logging.error(f"Could not open PCAP file: {e}")
            return ERROR
        except ImportError as e:
            logging.error(f"Scapy is required to examine PCAP files: {e}")
            return ERROR
    else:       
        if geteuid() is not ROOT:
           logging.error(f"Please run as root. Current UID: {geteuid()}")
           return ERROR
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = interface_finder()

        logging.info(f"Using Interface: {conf.iface}") # type: ignore

        filter_ips: List[str] = []
        if args.filter:
            filter_ips.extend([ip.strip() for ip in args.filter.split(",") if ip.strip()])
        elif args.filterfile:
            try:
                with open(args.filterfile, "r") as f:
                    filter_ips.extend([line.strip() for line in f if line.strip()])
            except IOError as e:
                logging.error(f"Could not open filter file: {e}")
                return ERROR 
        sniff(
            iface=conf.iface, # type: ignore
            prn=parse_packet, 
            store=0, 
            filter=bfp_filter(filter_ips)
        )

    return SUCCESS

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(INTERRUPT)
    except Exception:
        raise SystemExit(ERROR)