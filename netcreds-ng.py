#!/usr/bin/env python3

"""
To-Do:
* PCAP-NG Parsing
* Update function
* Multiple OS support
* Packet Parsing
"""

# import logging
import argparse
import sys
import platform
# import subprocess
from typing import Optional, Sequence
from scapy.all import PcapReader, conf

APP_NAME = "netcreds-ng"
__version__ = "1.0.0"

SUCCESS = 0
ERROR = 1
INTERRUPT = 130
ROOT = 0

def update() -> None:
    """Check for the latest version. Update if requested."""
    
def interface_finder() -> str:
    """Search for a valid interface, depending on the OS"""
    os = platform.system()
    if os == "Linux":
        # TODO
        # Code to find interface
        # return interface
        pass
    else:
        print(f"[!] Currently only Linux is supported")
        SystemExit(ERROR)

def parse_packet() -> None:
    pass

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog=APP_NAME
    )

    parser.add_argument("-i", "--interface", help="Choose an interface")
    parser.add_argument("-p", "--pcap", help="Parse info from a pcap file")
    parser.add_argument("-f", "--filterip", help="Do not sniff packets from this IP address")
    parser.add_argument("-v", "--verbose", help="Display entire URLs and POST loads rather than truncating at 100 characters", action="store_true")
    
    update_group = parser.add_mutually_exclusive_group()
    update_group.add_argument("-u", "--update", help="Update to the latest version of netcreds-ng")

    is_no_args_run = (argv is None and len(sys.argv) == 1) or (argv is not None and not argv)
    if is_no_args_run:
        parser.print_usage(sys.stderr)
        print(f"\n[i] No arguemnts provided. Try `{APP_NAME} --help for a list of all options.", file=sys.stderr)
        return SUCCESS
    
    args = parser.parse_args(argv)
   
    if args.update:
        try:
            update()
            return SUCCESS
        except Exception as e:
            print(f"[!] Error updating netcreds-ng: {e}", file=sys.stderr)
            return ERROR

    if args.pcap:
        try:
            for packet in PcapReader(args.pcap):
                pass
                # parse_packet(packet)
        except IOError as e:
            print(f"[!] Could not open PCAP file: {e}", file=sys.stderr)
            return ERROR
    else:
        # Uncomment for Linux
        #if geteuid() is not ROOT:
        #    print(f"[-] Please run as root or with root privileges")
        #    return ERROR
        if args.interface:
            conf.iface = args.interface
        else:
            conf.iface = interface_finder()
        print(f"[*] Using Interface: {conf.iface}")
        

    return SUCCESS

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(INTERRUPT)
    except Exception:
        raise SystemExit(ERROR)