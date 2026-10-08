# -*- coding: utf-8 -*-
"""Run the UNMODIFIED original net-creds.py under Python 2 (the parity oracle).

Usage (Python 2.7 with scapy installed):
    python2 py2_oracle.py [--raw-tcp] /path/to/net-creds.py -p capture.pcap

Shims, all outside the original file:
* os.geteuid is POSIX-only and imported at module load; on Windows it is
  stubbed (it is never called in -p mode).
* --raw-tcp clears scapy's TCP payload bindings so every TCP payload is a Raw
  layer, as on the scapy 2.3 the original was written for. Newer scapy
  versions dissect SMB/NBT/etc. and hide those payloads from the original.
"""
import os
import runpy
import sys
import warnings

warnings.simplefilter("ignore")

if not hasattr(os, "geteuid"):
    os.geteuid = lambda: 0

args = sys.argv[1:]
raw_tcp = False
if args and args[0] == "--raw-tcp":
    raw_tcp = True
    args = args[1:]

if raw_tcp:
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    # Load every layer first: later imports would re-add their TCP bindings.
    import scapy.all  # noqa: F401
    from scapy.layers.inet import TCP

    TCP.payload_guess = []

script = args[0]
sys.argv = [script] + args[1:]
runpy.run_path(script, run_name="__main__")
