"""Secret masking for screen output, reports and sinks."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from netcreds_ng.model import Finding

# Values of secret-looking fields embedded in free text (URLs, POST bodies, JSON, headers).
_SECRET_KEYS = (
    r"pass(?:word|wd|wrd|wort|code)?|pwd|pw|senha|contrasena|secret|token|access_token|auth_token|api[_-]?key"
    r"|apikey|session(?:id)?|sid|jsessionid|phpsessid|authorization|cookie|credentials?"
)
_KV = re.compile(r"(?i)((?:^|[?&;,\s\"'{])(?:[\w\[\]-]*?(?:" + _SECRET_KEYS + r"))\s*=\s*)([^&;,\s\"']+)")
_JSON = re.compile(r'(?i)("(?:[\w-]*?(?:' + _SECRET_KEYS + r'))"\s*:\s*")((?:[^"\\]|\\.)*)(")')
_HEADER = re.compile(r"(?i)((?:authorization|proxy-authorization|cookie|x-api-key)\s*:\s*)(.+)")


def mask_value(value: str | None) -> str | None:
    """Keep only the length and the first/last character: ``s****t (6)``."""
    if value is None:
        return None
    n = len(value)
    if n == 0:
        return ""
    if n <= 2:
        return "*" * n + f" ({n})"
    return f"{value[0]}{'*' * min(n - 2, 12)}{value[-1]} ({n})"


def redact_text(text: str) -> str:
    """Mask secret-looking values embedded in free text (form bodies, URLs, JSON, header lines)."""
    text = _JSON.sub(lambda m: m.group(1) + (mask_value(m.group(2)) or "") + m.group(3), text)
    text = _HEADER.sub(lambda m: m.group(1) + (mask_value(m.group(2)) or ""), text)
    return _KV.sub(lambda m: m.group(1) + (mask_value(m.group(2)) or ""), text)


def _redact_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj


def masked(finding: Finding) -> Finding:
    """A copy of ``finding`` with secret material masked, including secrets embedded in values and extras."""
    return replace(
        finding,
        secret=mask_value(finding.secret),
        value=redact_text(finding.value) if finding.value else finding.value,
        extra=_redact_obj(dict(finding.extra)),
        tags=list(finding.tags),
    )
