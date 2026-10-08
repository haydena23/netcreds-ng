"""Record legacy-parity goldens by running the original net-creds under Python 2.

    python tools/make_goldens.py --py2 C:\\Python27\\python.exe --original ..\\net-creds\\net-creds.py

Writes:
* tests/golden/legacy/synthetic/<fixture>.stdout / .log - plaintext goldens (fixtures hold only fake values)
* tests/golden/legacy/real.json - SHA-256 digests only for the third-party captures in test/
All outputs are newline-normalised (Python 2 text mode on Windows wrote CRLF; CRLF -> LF is its exact inverse).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNTH = ROOT / "tests" / "fixtures" / "synthetic"
REAL = ROOT / "test"
GOLDEN = ROOT / "tests" / "golden" / "legacy"
ORACLE = ROOT / "tools" / "py2_oracle.py"
NL = b"\n"


def normalise(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def run(py2: str, original: str, capture: Path, raw_tcp: bool) -> tuple[bytes, bytes, int]:
    with tempfile.TemporaryDirectory() as cwd:
        cmd = [py2, "-W", "ignore", str(ORACLE)] + (["--raw-tcp"] if raw_tcp else []) + [original, "-p", str(capture)]
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=600)
        log_path = Path(cwd) / "credentials.txt"
        log = log_path.read_bytes() if log_path.exists() else b""
        return normalise(proc.stdout), normalise(log), proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--py2", required=True)
    ap.add_argument("--original", required=True)
    args = ap.parse_args()
    (GOLDEN / "synthetic").mkdir(parents=True, exist_ok=True)

    for cap in sorted(SYNTH.glob("*.pcap")):
        out, log, rc = run(args.py2, args.original, cap, raw_tcp=True)
        if rc != 0:
            print(f"!! {cap.name}: exit {rc}", file=sys.stderr)
        (GOLDEN / "synthetic" / f"{cap.stem}.stdout").write_bytes(out)
        (GOLDEN / "synthetic" / f"{cap.stem}.log").write_bytes(log)
        print(f"synthetic {cap.name}: {out.count(NL)} lines, exit {rc}")

    real: dict[str, dict[str, object]] = {}
    for cap in sorted(p for p in REAL.rglob("*") if p.suffix in (".pcap", ".pcapng", ".cap")):
        results = {}
        for mode in (False, True):
            out, log, rc = run(args.py2, args.original, cap, raw_tcp=mode)
            results[mode] = (out, log, rc)
        out, log, rc = results[True]
        same = results[False][:2] == results[True][:2]
        real[cap.relative_to(ROOT).as_posix()] = {
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "lines": out.count(b"\n"),
            "exit": rc,
            "raw_tcp_matches_default_scapy": same,
        }
        print(f"real {cap.name}: {out.count(NL)} lines, raw-tcp==default: {same}")
    (GOLDEN / "real.json").write_text(json.dumps(real, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
