"""Throughput benchmark: build a large synthetic capture and time the analysis.

    python tools/bench.py --flows 5000 --out bench.pcap      # build + analyse
    python tools/bench.py --pcap existing.pcap --profile      # analyse an existing capture, cProfile top 25
    python tools/bench.py --pcap a.pcap --pcap b.pcap --jobs 2

The capture mixes credential-bearing protocols with bulk binary and HTTP traffic, all
synthetic (documentation addresses, fake values).
"""

from __future__ import annotations

import argparse
import cProfile
import os
import pstats
import random
import sys
import tempfile
import time

from netcreds_ng.engine.pcapio import PcapWriter
from netcreds_ng.plugins.registry import load_registry
from netcreds_ng.session import Session, SessionConfig
from netcreds_ng.testing.packets import TCPConversation, udp_frame
from netcreds_ng.testing.protocols import snmp_v1v2


def build(path: str, flows: int, seed: int = 7) -> int:
    rnd = random.Random(seed)
    frames = 0
    with open(path, "wb") as fh:
        w = PcapWriter(fh)
        t = 1_700_000_000.0
        for i in range(flows):
            client = f"192.0.2.{1 + i % 250}"
            server = f"198.51.100.{1 + (i * 7) % 250}"
            kind = i % 10
            c = TCPConversation(client, 20000 + i % 40000, server, 80, start=t, step=0.0005)
            if kind == 0:
                c.server_port = 21
                c.handshake().server(b"220 ftp\r\n").client(f"USER u{i}\r\nPASS Fake-{i}\r\n".encode())
                c.server(b"530 no\r\n" if i % 3 else b"230 ok\r\n")
            elif kind in (1, 2, 3):
                body = rnd.randbytes(200)
                c.handshake().client(f"GET /p/{i}?q=x HTTP/1.1\r\nHost: h{i}.example\r\nUser-Agent: bench\r\n\r\n".encode())
                c.server(b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n" + body)
            elif kind == 4:
                frames += 1
                w.write(udp_frame(client, 40000 + i % 20000, server, 161, snmp_v1v2(f"comm-{i % 13}")), t)
                t += 0.001
                continue
            else:  # bulk binary transfer (the common case on real networks)
                c.server_port = 8000 + kind
                c.handshake().client(rnd.randbytes(64)).server(rnd.randbytes(6000), segment=1448)
            c.close()
            for fr in c.frames:
                w.write(fr.data, fr.timestamp)
            frames += len(c.frames)
            t += 0.01
    return frames


def analyse(paths: list[str], jobs: int) -> tuple[int, int, float]:
    reg = load_registry(use_entry_points=False)
    session = Session(reg, SessionConfig(jobs=jobs))
    session.open()
    start = time.perf_counter()
    session.run_files(paths)
    session.close()
    return session.stats.frames, session.stats.findings, time.perf_counter() - start


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flows", type=int, default=5000)
    ap.add_argument("--out", help="where to write the generated capture (default: temp file)")
    ap.add_argument("--pcap", action="append", help="analyse existing capture(s) instead of generating one")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--profile", action="store_true")
    args = ap.parse_args(argv)
    paths = args.pcap or []
    if not paths:
        out = args.out or os.path.join(tempfile.mkdtemp(prefix="netcreds-bench-"), "bench.pcap")
        t = time.perf_counter()
        n = build(out, args.flows)
        print(f"built {out}: {n:,} frames, {os.path.getsize(out) / 1e6:.1f} MB in {time.perf_counter() - t:.1f}s")
        paths = [out]
    if args.profile:
        prof = cProfile.Profile()
        prof.enable()
    frames, findings, secs = analyse(paths, args.jobs)
    if args.profile:
        prof.disable()
        pstats.Stats(prof, stream=sys.stdout).sort_stats("cumulative").print_stats(25)
    size = sum(os.path.getsize(p) for p in paths) / 1e6
    print(f"analysed {frames:,} frames ({size:.1f} MB) -> {findings:,} findings in {secs:.2f}s: "
          f"{frames / secs:,.0f} frames/s, {size / secs:.1f} MB/s (jobs={args.jobs})")  # fmt: skip
    return 0


if __name__ == "__main__":
    sys.exit(main())
