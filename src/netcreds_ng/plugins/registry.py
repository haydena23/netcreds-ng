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
    "netcreds_ng.plugins.sinks.webhook",
    "netcreds_ng.plugins.sinks.evidence",
    "netcreds_ng.plugins.sinks.siem",
)

PluginClass = type[ProtocolPlugin] | type[EnricherPlugin] | type[SinkPlugin]

#: What the built-in sets are for (shown by ``--list-plugins``). Members come from each plugin's ``sets``.
SET_DESCRIPTIONS = {
    "all": "every protocol plugin, opt-in ones included",
    "default": "every protocol plugin that is not opt-in (what runs without --plugins)",
    "legacy": "what the original net-creds looked for",
    "web": "HTTP/1.x and HTTP/2",
    "email": "SMTP, POP3, IMAP",
    "file-transfer": "FTP",
    "remote-access": "Telnet, VNC, RDP",
    "databases": "MySQL, PostgreSQL, MSSQL, Oracle, Redis",
    "directory": "Windows/AD authentication: NTLM, Kerberos, LDAP",
    "aaa": "RADIUS, TACACS+",
    "network": "network-device management: SNMP, RADIUS, TACACS+",
    "chat": "IRC",
    "iot": "MQTT",
    "voip": "SIP",
    "generic": "pattern scanners over any cleartext stream: key=value credentials, cloud/API keys",
}


def _declared_sets(cls: type) -> tuple[str, ...]:
    """A plugin's ``sets``; a plain string (a common slip for a 1-tuple) is one set name, not its letters."""
    sets = getattr(cls, "sets", ())
    if isinstance(sets, str):
        return (sets,)
    return tuple(s for s in sets if isinstance(s, str))


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

    def plugin_sets(self, user_sets: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
        """Named sets of protocol plugins: ``all``, ``default``, the sets plugins declare, and ``user_sets``.

        A user set lists plugin names and/or other set names (user sets may refer to each other).
        Set names must not clash with plugin names. Raises ``KeyError`` on an unknown member, a
        clash, or a cycle.
        """
        protos = self.of_kind("protocol")
        sets: dict[str, set[str]] = {
            "all": {i.name for i in protos},
            "default": {i.name for i in protos if not i.cls.opt_in},
        }
        for info in protos:
            for name in _declared_sets(info.cls):
                if name in self.plugins or name in ("all", "default"):
                    continue  # reported by check_sets(); the plugin stays usable by name
                sets.setdefault(name, set()).add(info.name)
        user = dict(user_sets or {})
        for name in user:
            if name in self.plugins:
                raise KeyError(f"set {name!r} has the same name as a plugin")
            if name in ("all", "default"):
                raise KeyError(f"set {name!r} is built in and cannot be redefined")

        done: dict[str, set[str]] = {}

        def resolve(name: str, stack: tuple[str, ...]) -> set[str]:
            if name in stack:
                raise KeyError(f"sets refer to each other in a cycle: {' -> '.join((*stack, name))}")
            if name in done:  # shared sub-sets are resolved once (no exponential blow-up)
                return done[name]
            out: set[str] = set(sets.get(name, set()))  # a user set may extend a built-in set of the same name
            for member in user[name]:
                if member in user and member != name:
                    out |= resolve(member, (*stack, name))
                elif member in sets:
                    out |= sets[member]
                elif member in self.plugins and self.plugins[member].kind == "protocol":
                    out.add(member)
                else:
                    raise KeyError(f"set {name!r}: unknown protocol plugin or set {member!r}")
            done[name] = out
            return out

        resolved = {name: resolve(name, ()) for name in user}
        sets.update(resolved)
        return {k: sorted(v) for k, v in sorted(sets.items())}

    def check_sets(self) -> list[str]:
        """Problems with sets declared by plugins (a set named like a plugin, or like a reserved set)."""
        problems = []
        for info in self.of_kind("protocol"):
            if isinstance(getattr(info.cls, "sets", ()), str):
                problems.append(f"plugin {info.name!r} declares sets as a string; read as one set name "
                                "(use a tuple)")  # fmt: skip
            for name in _declared_sets(info.cls):
                if name in self.plugins or name in ("all", "default"):
                    problems.append(f"plugin {info.name!r} declares set {name!r}, which clashes with a "
                                    "plugin or built-in set name; ignored")  # fmt: skip
        return problems

    def expand(self, names: list[str], user_sets: dict[str, list[str]] | None = None) -> set[str]:
        """Plugin names for a list of plugin and set names. Raises ``KeyError`` naming unknown entries."""
        sets = self.plugin_sets(user_sets)
        out: set[str] = set()
        unknown = []
        for name in names:
            if name in sets:
                out |= set(sets[name])
            elif name in self.plugins:
                out.add(name)
            else:
                unknown.append(name)
        if unknown:
            raise KeyError(f"unknown plugin(s) or set(s): {', '.join(sorted(unknown))}")
        return out

    def select_protocols(
        self,
        enable: list[str] | None = None,
        disable: list[str] | None = None,
        options: dict[str, Any] | None = None,
        only: list[str] | None = None,
        user_sets: dict[str, list[str]] | None = None,
    ) -> list[ProtocolPlugin]:
        """The protocol plugins to run.

        Start from ``only`` (plugin and set names) if given, else every plugin that is not
        opt-in; add ``enable``; remove ``disable``. All three accept plugin and set names.
        """
        kind_names = {i.name for i in self.of_kind("protocol")}
        if only:
            chosen = self.expand(only, user_sets)
            other = sorted(chosen - kind_names)
            if other:
                raise KeyError(f"not protocol plugins: {', '.join(other)} (--plugins selects protocol plugins "
                               "and sets; turn enrichers off with --disable)")  # fmt: skip
        else:
            chosen = set(self.plugin_sets()["default"])
        chosen |= self.expand(enable or [], user_sets) & kind_names
        chosen -= self.expand(disable or [], user_sets)
        return self._instantiate("protocol", chosen, options)

    def select_enrichers(
        self,
        enable: list[str] | None = None,
        disable: list[str] | None = None,
        options: dict[str, Any] | None = None,
        user_sets: dict[str, list[str]] | None = None,
    ) -> list[EnricherPlugin]:
        """Every enricher that is not opt-in, plus ``enable`` (``all`` turns on opt-in ones), minus ``disable``."""
        enable_names = set(enable or [])
        disable_set = self.expand(list(disable or []), user_sets)
        self.expand(list(enable_names), user_sets)  # validate names
        chosen = {
            i.name for i in self.of_kind("enricher")
            if i.name not in disable_set and (not i.cls.opt_in or "all" in enable_names or i.name in enable_names)
        }  # fmt: skip
        return self._instantiate("enricher", chosen, options)

    def _instantiate(self, kind: str, names: set[str], options: dict[str, Any] | None) -> list[Any]:
        chosen = [info.cls((options or {}).get(info.name, {})) for info in self.of_kind(kind) if info.name in names]
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
