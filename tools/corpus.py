"""Real-traffic validation (milestone M13): public sample captures, checked against tshark.

    python tools/corpus.py fetch                 # download tools/corpus.toml into the corpus directory
    python tools/corpus.py run                   # analyse every capture, compare with tshark, write a report
    python tools/corpus.py run --only ldap/      # only captures whose name contains "ldap/"
    python tools/corpus.py list                  # show the manifest

The captures are downloaded **outside the repository** (default ``%LOCALAPPDATA%/netcreds-ng/corpus``
or ``~/.cache/netcreds-ng/corpus``; override with ``--dir`` or ``NETCREDS_CORPUS``) and are never
committed. Each file is checked against the SHA-256 pinned in the manifest; a mismatch is an error.

``run`` analyses each capture with netcreds-ng (in-process, all built-in plugins, no
deduplication) and, when tshark is available, extracts the identities tshark's dissectors see:
login names (FTP USER, HTTP Basic/Digest, POP3, IMAP, SMTP AUTH, LDAP simple bind, Kerberos
AS exchange, NTLM AUTHENTICATE, MySQL, PostgreSQL, RADIUS, SIP, MQTT, RDP cookie, TDS, TNS,
TACACS+) and SNMP communities. They are compared case-insensitively:

- **matched**: netcreds-ng reports the same identity;
- **partial**: one contains the other (``DOMAIN\\user`` vs ``user``, a DN vs its CN);
- **missed**: tshark sees it, netcreds-ng does not. Each one is a lead to investigate, not
  automatically a bug (netcreds-ng deliberately ignores some, e.g. anonymous binds);
- **extra**: netcreds-ng reports an identity tshark does not. tshark dissects mostly by port,
  so extras on non-standard ports are expected; others may be false positives.

Secrets are never printed. Passwords are not compared at all; SNMP communities (which are the
secret) are compared by value but shown masked.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "corpus.toml"
TSHARK_DEFAULTS = (r"C:\Program Files\Wireshark\tshark.exe", "/usr/bin/tshark", "/usr/local/bin/tshark",
                   "/opt/homebrew/bin/tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark")  # fmt: skip

# tshark fields read in one pass. Order matters: rows are split on tabs in this order.
FIELDS = (
    "ftp.request.command", "ftp.request.arg",
    "http.authbasic", "http.authorization",
    "pop.request.command", "pop.request.parameter",
    "imap.request.username",
    "smtp.auth.username",
    "ldap.protocolOp", "ldap.name",
    "kerberos.msg_type", "kerberos.CNameString", "kerberos.crealm",
    "ntlmssp.messagetype", "ntlmssp.auth.username", "ntlmssp.auth.domain",
    "mysql.user",
    "pgsql.parameter_name", "pgsql.parameter_value",
    "radius.User_Name",
    "snmp.community", "snmp.msgUserName",
    "sip.auth.username",
    "mqtt.username",
    "rdp.rt_cookie",
    "http2.header.name", "http2.header.value",
    "tds.login.username",
    "tns.connect_data",
    "tacplus.user",
)  # fmt: skip
AGGREGATOR = "|"  # between several occurrences of one field (',' would split LDAP DNs)
SECRET_CATEGORIES = frozenset({"snmp-community"})
_DIGEST_USER = re.compile(r'(?i)\busername\s*=\s*"([^"]*)"')
_TNS_USER = re.compile(r"(?i)\(USER=([^)]*)\)")
_MSTSHASH = re.compile(r"(?i)mstshash=([^\r\n]+)")
#: netcreds-ng protocol labels that have a tshark reference above; identities from other
#: protocols (IRC, Telnet, Redis, VNC, the secrets scanner) are listed as "unreferenced".
REFERENCED_PROTOCOLS = frozenset({"FTP", "HTTP", "HTTP/2", "POP3", "IMAP", "SMTP", "LDAP", "Kerberos", "NTLM",
                                  "MySQL", "PostgreSQL", "RADIUS", "SNMP", "SIP", "MQTT", "RDP", "MSSQL",
                                  "Oracle", "TACACS+"})  # fmt: skip


# --- manifest and download -----------------------------------------------------------


def corpus_dir(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    if os.environ.get("NETCREDS_CORPUS"):
        return Path(os.environ["NETCREDS_CORPUS"])
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "netcreds-ng" / "corpus"


def load_manifest(path: Path = MANIFEST) -> list[dict[str, Any]]:
    with open(path, "rb") as fh:
        return list(tomllib.load(fh)["capture"])


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(entries: list[dict[str, Any]], root: Path) -> int:
    root_resolved = root.resolve()
    repo = HERE.parent.resolve()
    if root_resolved == repo or repo in root_resolved.parents:
        print(f"[ERROR] corpus directory {root} is inside the repository; choose another one", file=sys.stderr)
        return 1
    bad = 0
    for e in entries:
        dest = root / e["name"]
        if dest.is_file() and sha256(dest) == e["sha256"]:
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(e["url"], headers={"User-Agent": "netcreds-ng-corpus/1"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # fixed https URLs from the manifest
                data = resp.read()
        except OSError as exc:
            print(f"[FAIL] {e['name']}: {exc}", file=sys.stderr)
            bad += 1
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest != e["sha256"]:
            print(f"[FAIL] {e['name']}: SHA-256 mismatch (got {digest}); not saved", file=sys.stderr)
            bad += 1
            continue
        dest.write_bytes(data)
        print(f"[ok]   {e['name']} ({len(data):,} B)")
    print(f"{len(entries) - bad} of {len(entries)} captures present in {root}")
    return 1 if bad else 0


# --- tshark side ----------------------------------------------------------------------


def find_tshark(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    found = shutil.which("tshark")
    if found:
        return found
    return next((p for p in TSHARK_DEFAULTS if os.path.isfile(p)), None)


def tshark_rows(tshark: str, capture: Path, keylog: Path | None = None) -> list[dict[str, list[str]]]:
    cmd = [tshark, "-n", "-r", str(capture)]
    if keylog is not None:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
           "-E", f"aggregator={AGGREGATOR}", "-E", "quote=n"]  # fmt: skip
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, check=False, timeout=600)
    rows = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        cols = line.split("\t")
        if not any(cols):
            continue
        cols += [""] * (len(FIELDS) - len(cols))
        rows.append({f: [_unescape(v) for v in c.split(AGGREGATOR) if v != ""]
                     for f, c in zip(FIELDS, cols, strict=False)})  # fmt: skip
    return rows


_ESCAPES = {"\\": "\\", '"': '"', "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_HEX = frozenset("0123456789abcdefABCDEF")


def _unescape(value: str) -> str:
    r"""Undo tshark's C-style escaping in -T fields output (\\, \a, \t, ..., \xNN)."""
    if "\\" not in value:
        return value
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        nxt = value[i + 1] if i + 1 < len(value) else ""
        if ch == "\\" and nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        if ch == "\\" and nxt == "x" and len(value) >= i + 4 and set(value[i + 2 : i + 4]) <= _HEX:
            out.append(chr(int(value[i + 2 : i + 4], 16)))
            i += 4
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _b64_text(value: str) -> str:
    """SMTP AUTH LOGIN usernames are base64 on the wire, and tshark shows them that way."""
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return value
    return decoded if decoded and decoded.isprintable() else value


def identities_from_rows(rows: list[dict[str, list[str]]]) -> set[tuple[str, str]]:
    """(category, value) pairs tshark's dissectors expose. Values are never passwords."""
    out: set[tuple[str, str]] = set()

    def add(cat: str, value: str | None) -> None:
        value = (value or "").strip()
        if value and value.upper() != "NULL":
            out.add((cat, value))

    for r in rows:
        cmds, args = r["ftp.request.command"], r["ftp.request.arg"]
        for cmd, arg in zip(cmds, args, strict=False):
            if cmd.upper() == "USER":
                add("ftp", arg)
        for basic in r["http.authbasic"]:
            add("http-basic", basic.split(":", 1)[0])
        for auth in r["http.authorization"]:
            m = _DIGEST_USER.search(auth)
            if auth.lower().startswith("digest") and m:
                add("http-digest", m.group(1))
        for cmd, arg in zip(r["pop.request.command"], r["pop.request.parameter"], strict=False):
            if cmd.upper() == "USER":
                add("pop3", arg)
        for user in r["imap.request.username"]:
            add("imap", user.strip('"'))
        for user in r["smtp.auth.username"]:
            add("smtp", _b64_text(user))
        if "0" in r["ldap.protocolOp"]:  # bindRequest
            for name in r["ldap.name"]:
                add("ldap-bind", name)
        if {"10", "11"} & set(r["kerberos.msg_type"]):  # AS-REQ / AS-REP
            for name in r["kerberos.CNameString"]:
                add("kerberos", name)
        if "0x00000003" in r["ntlmssp.messagetype"] or "3" in r["ntlmssp.messagetype"]:
            for user in r["ntlmssp.auth.username"]:
                add("ntlm", user)
        for user in r["mysql.user"]:
            add("mysql", user)
        for name, value in zip(r["pgsql.parameter_name"], r["pgsql.parameter_value"], strict=False):
            if name == "user":
                add("postgres", value)
        for user in r["radius.User_Name"]:
            add("radius", user)
        for community in r["snmp.community"]:
            add("snmp-community", community)
        for user in r["snmp.msgUserName"]:
            add("snmpv3", user)
        for user in r["sip.auth.username"]:
            add("sip", user.strip('"'))
        for user in r["mqtt.username"]:
            add("mqtt", user)
        for name, value in zip(r["http2.header.name"], r["http2.header.value"], strict=False):
            if name.lower() == "authorization" and value.lower().startswith("basic "):
                user = _b64_text(value[6:].strip())
                if user != value[6:].strip():
                    add("http2-basic", user.split(":", 1)[0])
        for cookie in r["rdp.rt_cookie"]:
            m = _MSTSHASH.search(cookie)
            if m:
                add("rdp", m.group(1))
        for user in r["tds.login.username"]:
            add("mssql", user)
        for data in r["tns.connect_data"]:
            for m in _TNS_USER.finditer(data):
                add("oracle-connect", m.group(1))
        for user in r["tacplus.user"]:
            add("tacacs", user)
    return out


# --- netcreds-ng side -------------------------------------------------------------------


@dataclass
class NgResult:
    findings: list[Any]
    stats: Any
    health: dict[str, Any]
    errors: list[str]


def run_netcreds(capture: Path, keylog: Path | None = None) -> NgResult:
    from netcreds_ng.health import assess
    from netcreds_ng.plugins.registry import load_registry
    from netcreds_ng.session import Session, SessionConfig

    found: list[Any] = []
    session = Session(load_registry(use_entry_points=False), SessionConfig(dedup="off", tls_keylog=str(keylog) if keylog else None), listeners=[found.append])
    session.open()
    session.run_files([str(capture)])
    session.close()
    return NgResult(found, session.stats, assess(session.stats), list(session.errors))


def ng_identities(findings: list[Any]) -> list[tuple[str, frozenset[str]]]:
    """Identities netcreds-ng reported, as (protocol, lower-cased aliases).

    Aliases of one identity: the username, ``DOMAIN\\user`` and ``user@domain``; SNMP communities;
    the Oracle client OS user (``os_user``, which tshark shows as the connect descriptor's USER).
    """
    out: dict[tuple[str, frozenset[str]], None] = {}
    for f in findings:
        aliases: set[str] = set()
        if f.username:
            aliases.add(f.username.lower())
            if f.domain:
                aliases.add(f"{f.domain}\\{f.username}".lower())
                aliases.add(f"{f.username}@{f.domain}".lower())
        if f.kind.value == "community" and f.secret:
            aliases.add(f.secret.lower())
        if aliases:
            out[(f.protocol, frozenset(aliases))] = None
        os_user = f.extra.get("os_user") if isinstance(f.extra, dict) else None
        if os_user:
            out[(f.protocol, frozenset({str(os_user).lower()}))] = None
    return list(out)


# --- comparison and report ------------------------------------------------------------


def _mask(value: str) -> str:
    from netcreds_ng.output.masking import mask_value

    return mask_value(value) or ""


def show(category: str, value: str) -> str:
    return _mask(value) if category in SECRET_CATEGORIES else value


@dataclass
class Comparison:
    matched: list[tuple[str, str]] = field(default_factory=list)
    partial: list[tuple[str, str, str]] = field(default_factory=list)  # (category, tshark value, ng value)
    missed: list[tuple[str, str]] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)  # protocols tshark has a reference for
    unreferenced: list[str] = field(default_factory=list)  # protocols with no tshark reference here


def compare(
    tshark_ids: set[tuple[str, str]],
    ng_ids: list[tuple[str, frozenset[str]]],
    ng_secret_ids: set[str] | None = None,
) -> Comparison:
    """Compare tshark (category, value) identities with netcreds-ng's identities (protocol, aliases)."""
    ng_secret_ids = ng_secret_ids or set()
    cmp = Comparison()
    used: set[int] = set()
    for cat, value in sorted(tshark_ids):
        v = value.lower()
        exact = [i for i, (_, aliases) in enumerate(ng_ids) if v in aliases]
        if exact:
            cmp.matched.append((cat, value))
            used.update(exact)
            continue
        near = sorted((min(aliases, key=len), i) for i, (_, aliases) in enumerate(ng_ids)
                      if any(len(a) >= 3 and len(v) >= 3 and (a in v or v in a) for a in aliases))  # fmt: skip
        if near:
            cmp.partial.append((cat, value, near[0][0]))
            used.update(i for _, i in near)
            continue
        cmp.missed.append((cat, value))
    for i, (proto, aliases) in enumerate(ng_ids):
        if i in used:
            continue
        name = min(aliases, key=len)
        shown = _mask(name) if name in ng_secret_ids else name
        (cmp.extra if proto in REFERENCED_PROTOCOLS else cmp.unreferenced).append(f"{proto}: {shown}")
    cmp.extra.sort()
    cmp.unreferenced.sort()
    return cmp


def analyse(entry: dict[str, Any], root: Path, tshark: str | None) -> dict[str, Any]:
    path = root / entry["name"]
    keylog = root / entry["keylog"] if entry.get("keylog") else None
    ng = run_netcreds(path, keylog)
    ids = ng_identities(ng.findings)
    secret_ids = {f.secret.lower() for f in ng.findings if f.kind.value == "community" and f.secret}
    row: dict[str, Any] = {
        "name": entry["name"],
        "expected_plugins": entry.get("plugins", []),
        "notes": entry.get("notes", ""),
        "findings": len(ng.findings),
        "by_plugin": dict(Counter(f.plugin for f in ng.findings)),
        "by_kind": dict(Counter(f.kind.value for f in ng.findings)),
        "plugin_errors": dict(ng.stats.plugin_errors),
        "source_errors": list(ng.stats.source_errors),
        "errors": ng.errors[:10],
        "health": {
            "status": ng.health["status"],
            "issues": [i["code"] for i in ng.health["issues"]],
            "verdict": ng.health["verdict"],
        },
        "frames": ng.stats.frames,
        "tls": {"sessions": ng.stats.tls_sessions, "decrypted": ng.stats.tls_decrypted,
                "no_key": ng.stats.tls_no_key, "failed": ng.stats.tls_failed + ng.stats.tls_unsupported}
        if keylog else None,
    }
    if tshark:
        cmp = compare(identities_from_rows(tshark_rows(tshark, path, keylog)), ids, secret_ids)
        row["tshark"] = {
            "matched": [f"{c}: {show(c, v)}" for c, v in cmp.matched],
            "partial": [f"{c}: {show(c, v)} ~ {_mask(n) if n in secret_ids else n}" for c, v, n in cmp.partial],
            "missed": [f"{c}: {show(c, v)}" for c, v in cmp.missed],
            "extra": cmp.extra,
            "unreferenced": cmp.unreferenced,
        }
    return row


def write_report(rows: list[dict[str, Any]], out_dir: Path, plugins: list[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "corpus-report.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    fired: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        for p in r["by_plugin"]:
            fired[p].append(r["name"])
    lines = ["# netcreds-ng corpus report", "", "## Plugin coverage", "",
             "| Plugin | Captures with findings |", "| --- | --- |"]  # fmt: skip
    for p in plugins:
        lines.append(f"| {p} | {len(fired.get(p, []))} |")
    totals = Counter()
    for r in rows:
        t = r.get("tshark", {})
        for k in ("matched", "partial", "missed", "extra", "unreferenced"):
            totals[k] += len(t.get(k, []))
    lines += ["", "## Totals", "", f"- captures: {len(rows)}",
              f"- tshark identities: {totals['matched']} matched, {totals['partial']} partial, "
              f"{totals['missed']} missed; {totals['extra']} reported only by netcreds-ng; "
              f"{totals['unreferenced']} in protocols without a tshark reference",
              f"- plugin errors: {sum(sum(r['plugin_errors'].values()) for r in rows)}",
              f"- capture health: {dict(Counter(r['health']['status'] for r in rows))}",
              "", "## Captures", ""]  # fmt: skip
    for r in rows:
        t = r.get("tshark", {})
        lines.append(f"### {r['name']}")
        lines.append("")
        lines.append(f"- expected plugins: {', '.join(r['expected_plugins']) or '-'}; "
                     f"findings: {r['findings']} {r['by_plugin'] or ''}")  # fmt: skip
        lines.append(f"- capture health: {r['health']['verdict']}")
        if r["tls"]:
            lines.append(f"- TLS with key log: {r['tls']}")
        if r["notes"]:
            lines.append(f"- notes: {r['notes']}")
        if r["plugin_errors"] or r["source_errors"]:
            lines.append(f"- **errors**: {r['plugin_errors']} {r['source_errors']} {r['errors'][:3]}")
        for k in ("matched", "partial", "missed", "extra", "unreferenced"):
            if t.get(k):
                lines.append(f"- {k}: " + "; ".join(t[k]))
        lines.append("")
    path = out_dir / "corpus-report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=("fetch", "run", "list"))
    ap.add_argument("--dir", help="corpus directory (default: outside the repository, see module docs)")
    ap.add_argument("--only", action="append", default=[], help="only captures whose name contains this text")
    ap.add_argument("--tshark", help="path to tshark (default: PATH, then common install locations)")
    ap.add_argument("--no-tshark", action="store_true", help="skip the tshark comparison")
    ap.add_argument("--out", help="report directory (default: <corpus dir>/report)")
    args = ap.parse_args(argv)
    entries = load_manifest()
    if args.only:
        entries = [e for e in entries if any(o in e["name"] for o in args.only)]
    root = corpus_dir(args.dir)
    if args.command == "list":
        for e in entries:
            print(f"{e['name']:<60} {e['size']:>9,} B  {', '.join(e.get('plugins', []))}")
        return 0
    if args.command == "fetch":
        return fetch(entries, root)
    entries = [e for e in entries if e.get("kind", "capture") == "capture"]  # key logs are inputs, not captures
    needed = [e["name"] for e in entries] + [e["keylog"] for e in entries if e.get("keylog")]
    missing = [name for name in needed if not (root / name).is_file()]
    if missing:
        print(f"[ERROR] {len(missing)} captures missing in {root}; run 'fetch' first", file=sys.stderr)
        return 1
    tshark = None if args.no_tshark else find_tshark(args.tshark)
    if not args.no_tshark and tshark is None:
        print("[WARN] tshark not found: running without the tshark comparison", file=sys.stderr)
    rows = []
    for e in entries:
        if sha256(root / e["name"]) != e["sha256"]:
            print(f"[ERROR] {e['name']}: SHA-256 mismatch; run 'fetch' again", file=sys.stderr)
            return 1
        row = analyse(e, root, tshark)
        rows.append(row)
        t = row.get("tshark", {})
        status = "ERR " if row["plugin_errors"] else "    "
        tls = row["tls"]
        print(f"{status}{row['name']:<58} findings {row['findings']:>4}  health {row['health']['status']:<8}"
              + (f"  match {len(t['matched'])} part {len(t['partial'])} miss {len(t['missed'])} extra {len(t['extra'])}"
                 if t else "")
              + (f"  tls {tls['decrypted']}/{tls['sessions']} decrypted" if tls else ""))  # fmt: skip
    from netcreds_ng.plugins.registry import load_registry

    plugins = sorted(n for n, i in load_registry(use_entry_points=False).plugins.items() if i.kind == "protocol")
    report = write_report(rows, Path(args.out) if args.out else root / "report", plugins)
    print(f"report: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
