#!/usr/bin/python

"""
To-Do:
* PCAP-NG Parsing
* Update function
* Multiple OS support
* Packet Parsing
* Rich for better dashboard
"""

from __future__ import annotations

# import logging
import argparse
import sys
import platform
from subprocess import Popen, PIPE, DEVNULL
from typing import Optional, Sequence, List
from os import geteuid

APP_NAME = "netcreds-ng"
__version__ = "1.0.0"

SUCCESS = 0
ERROR = 1
INTERRUPT = 130
ROOT = 0

def update() -> None:
    """Check for the latest version. Update if requested."""
    
def interface_finder() -> Optional[bytes]:
    """Search for a valid interface, depending on the OS"""
    os = platform.system()
    if os == "Linux":
        ip_route = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DEVNULL)
        for line in ip_route.communicate()[0].splitlines():
            if b"default" in line:
                interface = line.split()[4]
                return interface
    else:
        print(f"[!] Currently only Linux is supported")
        SystemExit(ERROR)

def bfp_filter(ips : List[str]) -> Optional[str]:
    """Build filter string containing IPs to exclude"""
    if not ips:
        return None
    return ", ".join(f"Not Host(s): {ip}" for ip in ips)

def parse_packet() -> None:
    """Parse a network packet extracted from PCAP"""

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=APP_NAME
    )

    parser.add_argument("-i", "--interface", help="Choose an interface")
    parser.add_argument("-p", "--pcap", help="Parse info from a pcap file")
    parser.add_argument("-v", "--verbose", help="Display entire URLs and POST loads rather than truncating at 100 characters", action="store_true")
    parser.add_argument("-u", "--update", help="Update to the latest version of netcreds-ng")

    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("-f", "--filter", help="Do not sniff packets from host1,host2,...", type=str)
    filter_group.add_argument("-F", "--filterfile", help="Do not sniff packets new-line delimeted file", type=str)
    
    args = parser.parse_args(argv)

    if args.update:
        try:
            update()
            return SUCCESS
        except Exception as e:
            print(f"[!] Error updating netcreds-ng: {e}", file=sys.stderr)
            return ERROR

    if args.pcap is not None:
        try:
            # Lazy import of Scapy for performance
            from scapy.utils import PcapReader
            for packet in PcapReader(args.pcap):
                # packet_parser(packet)
                pass
        except IOError as e:
            print(f"[!] Could not open PCAP file: {e}", file=sys.stderr)
            return ERROR
        except ImportError as e:
            print(f"[!] Scapy is required to examine PCAP files: {e}", file=sys.stderr)
            return ERROR
    else:
        # Lazy import of Scapy for performance
        try:
            from scapy.config import conf
            from scapy.sendrecv import sniff
        except ImportError as e:
            print(f"[!] Scapy is required for live sniffing: {e}", file=sys.stderr)
            return ERROR
        
        if geteuid() is not ROOT:
           print(f"[!] Please run as root. Current UID: {geteuid()}")
           return ERROR
        
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = interface_finder()
        print(f"[*] Using Interface: {(conf.iface).decode()}") # type: ignore

        filter_ips: List[str] = []
        if args.filter:
            filter_ips.extend([ip.strip() for ip in args.filter.split(",") if ip.strip()])
        elif args.filterfile:
            try:
                with open(args.filterfile, "r") as f:
                    filter_ips.extend([line.strip() for line in f if line.strip()])
            except IOError as e:
                print(f"[!] Could not open filter file: {e}", file=sys.stderr)
                return ERROR 
            
        sniff(
            iface=conf.iface, # type: ignore
            prn=packet_parser, 
            store=0, 
            filter=bfp_filter(args.filterip | args.filterfile)
        )

    return SUCCESS

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(INTERRUPT)
    except Exception:
        raise SystemExit(ERROR)