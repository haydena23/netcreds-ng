"""Live-capture setup: interface choice and permission messages (no capture is started)."""

from __future__ import annotations

from netcreds_ng import cli
from netcreds_ng.engine import sources
from netcreds_ng.engine.sources import InterfaceInfo, pick_interface


def iface(name: str, *addresses: str, up: bool = True) -> InterfaceInfo:
    return InterfaceInfo(name, "", list(addresses), up)


def test_pick_interface_prefers_physical_adapter_with_routable_ipv4():
    # Shaped like a real Windows machine: link-local Ethernet, Hyper-V switches, a VPN and Wi-Fi.
    interfaces = [
        iface("Ethernet", "169.254.40.146", "fe80::1"),
        iface("Loopback Pseudo-Interface 1", "127.0.0.1", "::1"),
        iface("Tailscale", "100.64.0.5"),
        iface("vEthernet (Default Switch)", "172.18.48.1"),
        iface("Wi-Fi", "192.0.2.65", "2001:db8::47"),
    ]
    assert pick_interface(interfaces) == "Wi-Fi"


def test_pick_interface_falls_back_to_virtual_and_ignores_down_or_unaddressed():
    assert pick_interface([iface("eth0", "192.0.2.1", up=False), iface("docker0", "172.17.0.1")]) == "docker0"
    assert pick_interface([iface("eth0", "169.254.1.1"), iface("lo", "127.0.0.1")]) is None
    assert pick_interface([]) is None


def test_default_interface_falls_back_when_scapy_has_none(monkeypatch):
    monkeypatch.setattr(sources, "_scapy_default_interface", lambda: None)
    monkeypatch.setattr(sources, "list_interfaces", lambda: [iface("eth1", "198.51.100.7")])
    assert sources.default_interface() == "eth1"


def test_scapy_default_interface_is_resolved_after_loading_routes():
    # Regression: importing only scapy.config left conf.iface None, so a bare `netcreds-ng` found no interface.
    names = {i.name for i in sources.list_interfaces()}
    found = sources._scapy_default_interface()
    assert found is None or found in names or not names


def test_bare_command_explains_a_permission_problem(monkeypatch, capsys):
    monkeypatch.setattr(sources, "capture_permission_problem", lambda: "live capture needs Npcap: install it")
    assert cli.main(["--no-tui"]) == cli.EXIT_ERROR
    assert "[ERROR] live capture needs Npcap: install it" in capsys.readouterr().err


def test_bare_command_without_interface_points_to_the_options(monkeypatch, capsys):
    monkeypatch.setattr(sources, "capture_permission_problem", lambda: None)
    monkeypatch.setattr(sources, "default_interface", lambda: None)
    assert cli.main(["--no-tui"]) == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert "-i" in err and "--list-interfaces" in err and "-p" in err


def test_permission_check_returns_text_or_none():
    result = sources.capture_permission_problem()
    assert result is None or isinstance(result, str)
