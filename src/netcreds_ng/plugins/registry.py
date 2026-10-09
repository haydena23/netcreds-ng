"""Plugin discovery and selection.

Sources, in order (later sources cannot shadow earlier names):
1. built-in plugins shipped with netcreds-ng
2. installed packages exposing the ``netcreds_ng.plugins`` entry-point group
3. ``*.py`` files in plugin directories (``--plugin-dir``, config, user dir)
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import sys
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType
from typing import Any

from netcreds_ng.plugins.api import PLUGIN_API, EnricherPlugin, ProtocolPlugin, SinkPlugin

log = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "netcreds_ng.plugins"

BUILTIN_MODULES = (
    "netcreds_ng.plugins.protocols.ftp",
    "netcreds_ng.plugins.protocols.telnet",
    "netcreds_ng.plugins.protocols.irc",
    "netcreds_ng.plugins.protocols.mail",
    "netcreds_ng.plugins.protocols.http",
    "netcreds_ng.plugins.protocols.http2",
    "netcreds_ng.plugins.protocols.keyvalue",
    "netcreds_ng.plugins.protocols.ntlm",
    "netcreds_ng.plugins.protocols.kerberos",
    "netcreds_ng.plugins.protocols.snmp",
    "netcreds_ng.plugins.protocols.ldap",
    "netcreds_ng.plugins.protocols.mysql",
    "netcreds_ng.plugins.protocols.postgres",
    "netcreds_ng.plugins.protocols.redis",
    "netcreds_ng.plugins.protocols.sip",
    "netcreds_ng.plugins.protocols.vnc",
    "netcreds_ng.plugins.protocols.mqtt",
    "netcreds_ng.plugins.protocols.radius",
    "netcreds_ng.plugins.protocols.tacacs",
    "netcreds_ng.plugins.protocols.rdp",
    "netcreds_ng.plugins.protocols.secrets",
    "netcreds_ng.plugins.protocols.mssql",
    "netcreds_ng.plugins.protocols.oracle",
    "netcreds_ng.plugins.enrichers.analytics",
    "netcreds_ng.plugins.enrichers.detection",
    "netcreds_ng.plugins.sinks.files",
    "netcreds_ng.plugins.sinks.sqlite",
    "netcreds_ng.plugins.sinks.html",
    "netcreds_ng.plugins.sinks.webhook",
    "netcreds_ng.plugins.sinks.evidence",
    "netcreds_ng.plugins.sinks.siem",
)

PluginClass = type[ProtocolPlugin] | type[EnricherPlugin] | type[SinkPlugin]


@dataclass
class PluginInfo:
    cls: Any
    source: str  # "builtin", "entry-point:<dist>", "file:<path>"

    @property
    def name(self) -> str:
        return str(self.cls.name)

    @property
    def kind(self) -> str:
        if issubclass(self.cls, ProtocolPlugin):
            return "protocol"
        if issubclass(self.cls, EnricherPlugin):
            return "enricher"
        return "sink"


@dataclass
class Registry:
    plugins: dict[str, PluginInfo] = field(default_factory=dict)
    load_errors: list[str] = field(default_factory=list)

    def add(self, cls: Any, source: str) -> None:
        name = getattr(cls, "name", "")
        if not name:
            self.load_errors.append(f"{source}: {cls.__name__} has no name")
            return
        if getattr(cls, "api_version", None) != PLUGIN_API:
            self.load_errors.append(
                f"{source}: plugin {name!r} targets API {getattr(cls, 'api_version', None)}, need {PLUGIN_API}"
            )
            return
        if name in self.plugins:
            if self.plugins[name].cls is not cls:
                self.load_errors.append(f"{source}: plugin name {name!r} already provided by {self.plugins[name].source}")
            return
        self.plugins[name] = PluginInfo(cls, source)

    def add_module(self, module: ModuleType, source: str) -> None:
        for _, obj in sorted(inspect.getmembers(module, inspect.isclass)):
            if obj.__module__ != module.__name__:
                continue
            if obj in (ProtocolPlugin, EnricherPlugin, SinkPlugin):
                continue
            if issubclass(obj, (ProtocolPlugin, EnricherPlugin, SinkPlugin)) and bool(getattr(obj, "name", None)):
                self.add(obj, source)

    def of_kind(self, kind: str) -> list[PluginInfo]:
        return sorted((p for p in self.plugins.values() if p.kind == kind), key=lambda p: p.name)

    def select_protocols(
        self,
        enable: list[str] | None = None,
        disable: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> list[ProtocolPlugin]:
        return self._select("protocol", enable, disable, options)

    def select_enrichers(
        self,
        enable: list[str] | None = None,
        disable: list[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> list[EnricherPlugin]:
        return self._select("enricher", enable, disable, options)

    def _select(
        self,
        kind: str,
        enable: list[str] | None,
        disable: list[str] | None,
        options: dict[str, Any] | None,
    ) -> list[Any]:
        enable_set = set(enable or [])
        disable_set = set(disable or [])
        all_enabled = "all" in enable_set
        unknown = (enable_set | disable_set) - set(self.plugins) - {"all"}
        if unknown:
            raise KeyError(f"unknown plugin(s): {', '.join(sorted(unknown))}")
        chosen = []
        for info in self.of_kind(kind):
            if info.name in disable_set:
                continue
            if info.cls.opt_in and not (all_enabled or info.name in enable_set):
                continue
            chosen.append(info.cls((options or {}).get(info.name, {})))
        return sorted(chosen, key=lambda p: (p.priority, p.name))

    def sink_class(self, name: str) -> Any:
        info = self.plugins.get(name)
        if info is None or info.kind != "sink":
            raise KeyError(f"unknown output format {name!r}")
        return info.cls


def user_plugin_dir() -> Path:
    if sys.platform == "win32":
        import os

        base = Path(os.environ.get("APPDATA", Path.home()))
        return base / "netcreds-ng" / "plugins"
    return Path.home() / ".config" / "netcreds-ng" / "plugins"


def load_registry(plugin_dirs: list[str] | None = None, use_entry_points: bool = True) -> Registry:
    reg = Registry()
    for modname in BUILTIN_MODULES:
        try:
            reg.add_module(importlib.import_module(modname), "builtin")
        except Exception as exc:  # noqa: BLE001
            reg.load_errors.append(f"builtin {modname}: {type(exc).__name__}: {exc}")
    if use_entry_points:
        for ep in sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda e: e.name):
            dist = getattr(getattr(ep, "dist", None), "name", "?")
            try:
                obj = ep.load()
            except Exception as exc:  # noqa: BLE001
                reg.load_errors.append(f"entry-point {ep.name} ({dist}): {type(exc).__name__}: {exc}")
                continue
            source = f"entry-point:{dist}"
            if inspect.ismodule(obj):
                reg.add_module(obj, source)
            else:
                reg.add(obj, source)
    dirs = [Path(d) for d in (plugin_dirs or [])]
    default_dir = user_plugin_dir()
    if default_dir.is_dir():
        dirs.append(default_dir)
    for directory in dirs:
        if not directory.is_dir():
            reg.load_errors.append(f"plugin directory not found: {directory}")
            continue
        for path in sorted(directory.glob("*.py")):
            modname = f"netcreds_ng_userplugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(modname, path)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot create module spec")
                module = importlib.util.module_from_spec(spec)
                sys.modules[modname] = module
                spec.loader.exec_module(module)
            except Exception as exc:  # noqa: BLE001
                reg.load_errors.append(f"file {path}: {type(exc).__name__}: {exc}")
                continue
            reg.add_module(module, f"file:{path}")
    for err in reg.load_errors:
        log.warning("plugin load: %s", err)
    return reg
