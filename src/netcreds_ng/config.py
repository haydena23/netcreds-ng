"""TOML configuration (``netcreds-ng.toml``).

Example::

    [plugins]
    select = ["databases", "ftp", "mine"]   # like --plugins; omit to run every non-opt-in plugin
    disable = ["keyvalue"]

    [plugins.http]
    cookies = "all"           # session | all | off
    urls = true

    [sets]                    # your own plugin sets, usable anywhere a set name is
    mine = ["telnet", "remote-access", "snmp"]

    [output]
    dedup = "run"             # off | run | persistent
    jsonl = "findings.jsonl"

    [output.webhook]
    url = "https://siem.example/hook"
    min_risk = "high"
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any

DEFAULT_NAMES = ("netcreds-ng.toml", ".netcreds-ng.toml")


def user_config_path() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / "netcreds-ng" / "config.toml"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "netcreds-ng" / "config.toml"


def find_config(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit)
    for name in DEFAULT_NAMES:
        if Path(name).is_file():
            return Path(name)
    up = user_config_path()
    return up if up.is_file() else None


def load_config(explicit: str | None) -> tuple[dict[str, Any], Path | None]:
    path = find_config(explicit)
    if path is None:
        return {}, None
    with open(path, "rb") as fh:
        return tomllib.load(fh), path


def parse_option(text: str) -> tuple[str, str, Any]:
    """Parse ``plugin.key=value`` (value parsed as TOML scalar when possible)."""
    key, sep, raw = text.partition("=")
    if not sep or "." not in key:
        raise ValueError(f"expected plugin.key=value, got {text!r}")
    plugin, _, opt = key.partition(".")
    try:
        value: Any = tomllib.loads(f"v = {raw}")["v"]
    except tomllib.TOMLDecodeError:
        value = raw
    return plugin.strip(), opt.strip(), value
