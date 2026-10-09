"""Command line interface."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from typing import Any

from netcreds_ng import APP_NAME, __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_WARNINGS = 3  # --strict and analysis warnings occurred
EXIT_INTERRUPT = 130

RISKS = ("info", "low", "medium", "high")

EPILOG = """\
examples:
  netcreds-ng -p capture.pcap                     analyse a capture file
  netcreds-ng -p captures/ --html report.html     analyse a directory, write an HTML audit report
  netcreds-ng -p cap.pcapng --jsonl out.jsonl     findings as JSON lines (SIEM ingestion)
  sudo netcreds-ng -i eth0                        live interactive dashboard
  sudo netcreds-ng -i eth0 --no-tui -f 10.0.0.5   live, plain output, ignore a host
  netcreds-ng --legacy -p capture.pcap            original net-creds output, byte for byte
  netcreds-ng --list-plugins                      show available plugins

exit codes: 0 ok, 1 error, 2 usage, 3 warnings with --strict, 130 interrupted
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Find credentials and weak authentication exposed in network traffic.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_argument_group("sources")
    src.add_argument("-p", "--pcap", action="append", metavar="PATH",
                     help="capture file or directory (pcap/pcapng); repeatable")  # fmt: skip
    src.add_argument("-i", "--interface", metavar="IFACE", help="live capture interface (default: auto-detect)")
    src.add_argument("-f", "--filterip", "--filter", dest="filter", metavar="HOSTS",
                     help="ignore traffic to/from these hosts (comma separated)")  # fmt: skip
    src.add_argument("-F", "--filterfile", metavar="FILE", help="file with hosts to ignore, one per line")
    src.add_argument("--bpf", metavar="EXPR", help="additional BPF filter for live capture")

    out = p.add_argument_group("output")
    out.add_argument("-v", "--verbose", action="store_true", help="do not truncate long values on screen")
    out.add_argument("-q", "--quiet", action="store_true", help="no console output (outputs/files only)")
    out.add_argument("--tui", dest="tui", action="store_true", default=None, help="interactive dashboard")
    out.add_argument("--no-tui", dest="tui", action="store_false", help="plain console output")
    out.add_argument("--mask", action="store_true", help="mask secrets on screen and in outputs")
    out.add_argument("--no-browsing", action="store_true", help="hide URL/POST/search findings on screen")
    out.add_argument("--min-risk", choices=RISKS, default="info", help="lowest risk shown on screen")
    for fmt, helptext in (
        ("jsonl", "append findings as JSON lines"), ("csv", "append findings as CSV"),
        ("log", "append findings as log lines"), ("sqlite", "store findings in a SQLite database"),
        ("html", "write an HTML audit report"),
        ("evidence", "write the packets behind each finding to a pcapng file (raw packets, secrets included)"),
        ("cef", "append findings as ArcSight CEF lines"),
    ):  # fmt: skip
        out.add_argument(f"--{fmt}", metavar="PATH", help=helptext)
    out.add_argument("--webhook", metavar="URL", help="POST findings to a webhook (secrets masked)")
    out.add_argument("--webhook-format", choices=("generic", "slack", "teams", "discord"),
                     help="webhook payload style (default generic JSON)")  # fmt: skip
    out.add_argument("--syslog", metavar="URL", help="send findings to syslog, udp://host:514 or tcp://host:514 "
                     "(CEF body; secrets masked)")  # fmt: skip
    out.add_argument("-o", "--output", action="append", default=[], metavar="FORMAT:PATH",
                     help="generic output, e.g. jsonl:out.jsonl or a plugin-provided format; repeatable")  # fmt: skip
    out.add_argument("--legacy", action="store_true",
                     help="reproduce the original net-creds output (stdout + ./credentials.txt) exactly")  # fmt: skip

    an = p.add_argument_group("analysis")
    an.add_argument("-j", "--jobs", type=int, default=1, metavar="N",
                    help="analyse up to N capture files in parallel (default 1)")  # fmt: skip
    an.add_argument("--tls-keylog", metavar="FILE",
                    help="decrypt TLS sessions found in this NSS key-log file (SSLKEYLOGFILE); needs netcreds-ng[tls]")  # fmt: skip
    an.add_argument("--dedup", choices=("off", "run", "persistent"), default=None, help="duplicate suppression")
    an.add_argument("--dedup-db", metavar="PATH", help="state file for --dedup persistent")
    an.add_argument("--enable", action="append", default=[], metavar="PLUGINS",
                    help="enable plugins (comma separated; 'all' includes opt-in plugins)")  # fmt: skip
    an.add_argument("--disable", action="append", default=[], metavar="PLUGINS", help="disable plugins")
    an.add_argument("--option", action="append", default=[], metavar="PLUGIN.KEY=VALUE", help="plugin option")
    an.add_argument("--plugin-dir", action="append", default=[], metavar="DIR", help="load plugins from directory")
    an.add_argument("--config", metavar="FILE", help="TOML config file (default: ./netcreds-ng.toml)")
    an.add_argument("--strict", action="store_true", help="exit 3 if any plugin/source warnings occurred")
    an.add_argument("--strict-heuristics", action="store_true",
                    help="fewer false positives: heuristic plugins need strong protocol evidence "
                         "(telnet: Telnet port or option negotiation); disables keyvalue")  # fmt: skip

    misc = p.add_argument_group("information")
    misc.add_argument("--list-plugins", action="store_true", help="list plugins and exit")
    misc.add_argument("--list-interfaces", action="store_true", help="list network interfaces and exit")
    misc.add_argument("--debug", action="store_true", help="debug logging to stderr")
    misc.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return p


def _csv(values: list[str]) -> list[str]:
    return [v.strip() for item in values for v in item.split(",") if v.strip()]


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined,unused-ignore]
    except Exception:  # noqa: BLE001
        return False


def _hosts(args: argparse.Namespace) -> list[str]:
    hosts = _csv([args.filter]) if args.filter else []
    if args.filterfile:
        with open(args.filterfile, encoding="utf-8") as fh:
            hosts += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return hosts


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.ERROR,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return _dispatch(parser, args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_INTERRUPT


def _dispatch(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    from netcreds_ng.config import load_config, parse_option
    from netcreds_ng.plugins.registry import load_registry

    if args.list_interfaces:
        return _list_interfaces()
    try:
        config, _config_path = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] cannot read config: {exc}", file=sys.stderr)
        return EXIT_ERROR

    plugin_cfg: dict[str, Any] = dict(config.get("plugins", {}))
    registry = load_registry(plugin_dirs=args.plugin_dir + list(plugin_cfg.get("dirs", [])))
    if args.list_plugins:
        return _list_plugins(registry)

    try:
        hosts = _hosts(args)
    except OSError as exc:
        print(f"[ERROR] cannot read filter file: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.legacy:
        return _run_legacy(args, hosts)

    # plugin options: config tables, then --option overrides
    plugin_options: dict[str, dict[str, Any]] = {
        k: dict(v) for k, v in plugin_cfg.items() if isinstance(v, dict)
    }
    out_cfg: dict[str, Any] = dict(config.get("output", {}))
    for name, value in out_cfg.items():
        if isinstance(value, dict):
            plugin_options.setdefault(name, {}).update({k: v for k, v in value.items() if k != "url"})
    try:
        for opt in args.option:
            plugin, key, value = parse_option(opt)
            plugin_options.setdefault(plugin, {})[key] = value
    except ValueError as exc:
        parser.error(str(exc))
    if args.strict_heuristics:
        plugin_options.setdefault("telnet", {}).setdefault("strict", True)

    outputs: list[tuple[str, str]] = []
    for fmt in ("jsonl", "csv", "log", "sqlite", "html", "evidence", "cef"):
        target = getattr(args, fmt) or (out_cfg.get(fmt) if isinstance(out_cfg.get(fmt), str) else None)
        if target:
            outputs.append((fmt, target))
    wh_cfg = out_cfg.get("webhook")
    webhook = args.webhook or (wh_cfg.get("url") if isinstance(wh_cfg, dict) else wh_cfg if isinstance(wh_cfg, str) else None)
    if webhook:
        outputs.append(("webhook", webhook))
        if args.webhook_format:
            plugin_options.setdefault("webhook", {})["format"] = args.webhook_format
    sl_cfg = out_cfg.get("syslog")
    syslog = args.syslog or (sl_cfg.get("url") if isinstance(sl_cfg, dict) else sl_cfg if isinstance(sl_cfg, str) else None)
    if syslog:
        outputs.append(("syslog", syslog))
    for spec in args.output:
        fmt, sep, target = spec.partition(":")
        if not sep or not target:
            parser.error(f"--output expects FORMAT:PATH, got {spec!r}")
        outputs.append((fmt, target))
    for fmt, _ in outputs:
        try:
            registry.sink_class(fmt)
        except KeyError as exc:
            parser.error(str(exc.args[0]))

    from netcreds_ng.session import SessionConfig

    enable = _csv(args.enable) + list(plugin_cfg.get("enable", []))
    disable = _csv(args.disable) + list(plugin_cfg.get("disable", []))
    if args.strict_heuristics and "keyvalue" in registry.plugins:
        disable.append("keyvalue")
    mask = args.mask or bool(out_cfg.get("mask", False))
    scfg = SessionConfig(
        enable=enable,
        disable=disable,
        plugin_options=plugin_options,
        outputs=outputs,
        mask_outputs=mask,
        dedup=args.dedup or str(out_cfg.get("dedup", "run")),
        dedup_db=args.dedup_db or out_cfg.get("dedup_db"),
        exclude_hosts=set(hosts),
        source_label=", ".join(args.pcap) if args.pcap else (args.interface or "live"),
        tls_keylog=args.tls_keylog or out_cfg.get("tls_keylog") or plugin_cfg.get("tls_keylog"),
        jobs=max(1, args.jobs),
        plugin_dirs=args.plugin_dir + list(plugin_cfg.get("dirs", [])),
    )
    if args.pcap:
        return _run_files(args, registry, scfg, mask)
    return _run_live(args, registry, scfg, mask, hosts)


# --- modes --------------------------------------------------------------------


def _list_plugins(registry: Any) -> int:
    from rich.console import Console
    from rich.table import Table

    t = Table(title="netcreds-ng plugins")
    for col in ("Name", "Kind", "Default", "Source", "Description"):
        t.add_column(col)
    for info in sorted(registry.plugins.values(), key=lambda i: (i.kind, i.name)):
        default = "opt-in" if getattr(info.cls, "opt_in", False) else ("on" if info.kind != "sink" else "output")
        t.add_row(info.name, info.kind, default, info.source, info.cls.description)
    console = Console()
    console.print(t)
    for err in registry.load_errors:
        console.print(f"[yellow]load error:[/] {err}")
    return EXIT_OK


def _list_interfaces() -> int:
    from netcreds_ng.engine.sources import default_interface, list_interfaces

    default = default_interface()
    for iface in list_interfaces():
        mark = "*" if iface.name == default else " "
        state = "up" if iface.up else "down"
        print(f"{mark} {iface.name:<30} {state:<5} {', '.join(iface.addresses)}")
    return EXIT_OK


def _run_files(args: argparse.Namespace, registry: Any, scfg: Any, mask: bool) -> int:
    from netcreds_ng.engine.sources import expand_capture_paths
    from netcreds_ng.output.console import ConsoleRenderer
    from netcreds_ng.session import Session

    paths = expand_capture_paths(args.pcap)
    missing = [p for p in paths if not os.path.isfile(p)]
    if missing:
        print(f"[ERROR] capture not found: {', '.join(missing)}", file=sys.stderr)
        return EXIT_ERROR
    if not paths:
        print("[ERROR] no capture files found", file=sys.stderr)
        return EXIT_ERROR

    if args.tui:
        from netcreds_ng.tui.app import run_tui

        return run_tui(registry, scfg, files=paths, verbose=args.verbose, mask=mask)

    renderer = ConsoleRenderer(verbose=args.verbose, mask=mask, browsing=not args.no_browsing, quiet=args.quiet)
    min_risk = RISKS.index(args.min_risk)

    def show(f: Any) -> None:
        if RISKS.index(f.risk) >= min_risk:
            renderer.finding(f)

    try:
        session = Session(registry, scfg, listeners=[show])
        session.open()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_ERROR
    session.run_files(paths)
    session.close()
    renderer.summary(session.stats, session.summary(), session.errors)
    if args.strict and (session.stats.total_plugin_errors or session.stats.source_errors):
        return EXIT_WARNINGS
    if session.stats.source_errors and session.stats.frames == 0:
        return EXIT_ERROR
    return EXIT_OK


def _run_live(args: argparse.Namespace, registry: Any, scfg: Any, mask: bool, hosts: list[str]) -> int:
    from netcreds_ng.engine.sources import LiveCapture, bpf_exclude, default_interface
    from netcreds_ng.output.console import ConsoleRenderer
    from netcreds_ng.session import Session

    if not is_admin():
        print("[ERROR] live capture needs root/administrator privileges", file=sys.stderr)
        return EXIT_ERROR
    iface = args.interface or default_interface()
    if not iface:
        print("[ERROR] could not find an active interface; specify one with -i", file=sys.stderr)
        return EXIT_ERROR
    bpf = bpf_exclude(hosts, args.bpf)
    use_tui = args.tui if args.tui is not None else (sys.stdout.isatty() and not args.quiet)
    if use_tui:
        from netcreds_ng.tui.app import run_tui

        return run_tui(registry, scfg, interface=iface, bpf=bpf, verbose=args.verbose, mask=mask)

    renderer = ConsoleRenderer(verbose=args.verbose, mask=mask, browsing=not args.no_browsing, quiet=args.quiet)
    min_risk = RISKS.index(args.min_risk)
    def show(f: Any) -> None:
        if RISKS.index(f.risk) >= min_risk:
            renderer.finding(f)

    try:
        session = Session(registry, scfg, listeners=[show])
        session.open()
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_ERROR
    capture = LiveCapture(iface, bpf)
    if not args.quiet:
        print(f"[*] Capturing on {iface}" + (f" (filter: {bpf})" if bpf else "") + " - Ctrl+C to stop", file=sys.stderr)
    capture.start()
    try:
        session.feed(capture.frames())
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # noqa: BLE001 - capture backend errors (permissions, missing Npcap/libpcap)
        print(f"[ERROR] capture failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        capture.stop()
        session.close()
        if capture.dropped:
            session.stats.source_errors.append(f"{capture.dropped} packets dropped (analysis slower than capture)")
        renderer.summary(session.stats, session.summary(), session.errors)
    return EXIT_WARNINGS if args.strict and (session.stats.total_plugin_errors or session.stats.source_errors) else EXIT_OK


def _run_legacy(args: argparse.Namespace, hosts: list[str]) -> int:
    from netcreds_ng.engine.pcapio import CaptureFormatError, open_capture
    from netcreds_ng.legacy import LegacyAbort, LegacyNetCreds

    if args.pcap:
        if hosts:
            print("note: -f applies only to live capture in --legacy mode (original behaviour)", file=sys.stderr)
        engine = LegacyNetCreds(verbose=args.verbose)
        for path in args.pcap:
            read = 0
            try:
                for frame in open_capture(path):
                    read += 1
                    engine.process_frame(frame)
            except OSError:
                print(f"[-] Could not open {path}", file=sys.stderr)
                return EXIT_ERROR
            except CaptureFormatError as exc:
                print(f"[-] {path}: {exc}", file=sys.stderr)
                # Unreadable files failed in the original (exit 1); a truncated tail after readable
                # frames was silently ignored there (exit 0). Either way it is reported on stderr here.
                if read == 0 and not str(exc).startswith(("truncated record", "truncated frame")):
                    return EXIT_ERROR
            except LegacyAbort as exc:
                print(f"[-] aborted (as the original would): {exc}", file=sys.stderr)
                return EXIT_ERROR
        return EXIT_OK

    from netcreds_ng.engine.sources import LiveCapture, bpf_exclude, default_interface

    if not is_admin():
        sys.exit("[-] Please run as root")
    iface = args.interface or default_interface()
    if not iface:
        sys.exit("[-] Could not find an internet active interface; please specify one with -i <interface>")
    sys.stdout.write(f"[*] Using interface: {iface}\n")
    sys.stdout.flush()
    engine = LegacyNetCreds(verbose=args.verbose)
    capture = LiveCapture(iface, bpf_exclude(hosts[:1]))
    capture.start()
    try:
        for frame in capture.frames():
            engine.process_frame(frame)
    except KeyboardInterrupt:
        pass
    except LegacyAbort as exc:
        print(f"[-] aborted (as the original would): {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        capture.stop()
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
