"""Filter expressions for the dashboard (and anything else that wants them).

Space-separated terms, all of which must match (AND). A term is either free text,
matched case-insensitively against protocol, kind, endpoints, user, domain, value and
tags, or ``field:value``:

========== =====================================================================
proto      protocol contains value                 ``proto:ftp``
kind       kind equals value                       ``kind:credential``
risk       risk equals value, or at least it with + ``risk:high``, ``risk:medium+``
host       source or destination IP contains value  ``host:192.0.2.``
src / dst  that endpoint ("ip:port") contains value ``dst::21``
port       source or destination port equals value  ``port:3306``
user       username (or domain\\user) contains value ``user:admin``
tag        a tag contains value                     ``tag:weak``
plugin     plugin name equals value                 ``plugin:ldap``
========== =====================================================================

Prefix any term with ``-`` to negate it: ``-proto:http -tag:heuristic``.
"""

from __future__ import annotations

from collections.abc import Callable

from netcreds_ng.model import Finding

Predicate = Callable[[Finding], bool]
RISKS = ("info", "low", "medium", "high")
FIELDS = ("proto", "protocol", "kind", "risk", "host", "src", "dst", "port", "user", "tag", "plugin")


class FilterError(ValueError):
    pass


def _haystack(f: Finding) -> str:
    parts = (f.protocol, f.kind.value, f.src, f.dst, f.username, f.domain, f.display, *f.tags)
    return " ".join(str(x) for x in parts if x).lower()


def _text(needle: str) -> Predicate:
    return lambda f: needle in _haystack(f)


def _term(field: str, value: str) -> Predicate:
    v = value.lower()
    if field in ("proto", "protocol"):
        return lambda f: v in f.protocol.lower()
    if field == "kind":
        return lambda f: f.kind.value == v or f.kind.value.replace("_", "-") == v
    if field == "risk":
        at_least = v.endswith("+")
        name = v.rstrip("+")
        if name not in RISKS:
            raise FilterError(f"unknown risk {value!r} (info, low, medium, high)")
        level = RISKS.index(name)
        if at_least:
            return lambda f: RISKS.index(f.risk) >= level if f.risk in RISKS else False
        return lambda f: f.risk == name
    if field == "host":
        return lambda f: v in f.src.ip.lower() or v in f.dst.ip.lower()
    if field == "src":
        return lambda f: v in str(f.src).lower()
    if field == "dst":
        return lambda f: v in str(f.dst).lower()
    if field == "port":
        if not v.isdigit():
            raise FilterError(f"port must be a number, got {value!r}")
        port = int(v)
        return lambda f: port in (f.src.port, f.dst.port)
    if field == "user":
        return lambda f: v in (f"{f.domain}\\{f.username}" if f.domain else (f.username or "")).lower()
    if field == "tag":
        return lambda f: any(v in t.lower() for t in f.tags)
    if field == "plugin":
        return lambda f: f.plugin.lower() == v
    raise FilterError(f"unknown field {field!r}")


def parse_filter(text: str) -> Predicate:
    """Compile a filter expression; raises :class:`FilterError` on a bad field or value."""
    preds: list[tuple[bool, Predicate]] = []
    for raw in text.split():
        negate = raw.startswith("-") and len(raw) > 1
        term = raw[1:] if negate else raw
        field, sep, value = term.partition(":")
        if sep and field.lower() in FIELDS:
            if not value:
                continue  # still being typed
            pred = _term(field.lower(), value)
        else:
            pred = _text(term.lower())
        preds.append((negate, pred))
    return lambda f: all(p(f) != neg for neg, p in preds)
