"""Risk analytics: weak passwords, password reuse, default communities, per-host exposure profile."""

from __future__ import annotations

import hashlib
import hmac
import os
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any

from netcreds_ng.model import Finding, Kind
from netcreds_ng.plugins.api import EnricherPlugin

CLEARTEXT_PROTOCOLS = {"FTP", "Telnet", "HTTP", "POP3", "IMAP", "SMTP", "Mail", "IRC", "SNMP", "Cleartext",
                       "LDAP", "Redis", "MQTT", "MySQL", "PostgreSQL"}  # fmt: skip
_RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def load_weak_passwords() -> frozenset[str]:
    try:
        raw = files("netcreds_ng").joinpath("data/weak_passwords.txt").read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return frozenset()
    return frozenset(line.strip().lower() for line in raw.splitlines() if line.strip() and not line.startswith("#"))


@dataclass
class HostProfile:
    ip: str
    exposed_as_client: int = 0
    exposed_to_server: int = 0
    protocols: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    max_risk: str = "info"


class AnalyticsEnricher(EnricherPlugin):
    name = "analytics"
    description = "Weak-password and password-reuse detection, risk escalation, host exposure profiles"
    priority = 10

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.weak = load_weak_passwords()
        self._key = os.urandom(32)  # per-run key: fingerprints are not comparable across runs
        self._secret_users: dict[str, set[tuple[str, str]]] = defaultdict(set)
        self.hosts: dict[str, HostProfile] = {}
        self.weak_count = 0
        self.reused: Counter[str] = Counter()
        self.risk_counts: Counter[str] = Counter()

    def fingerprint(self, secret: str) -> str:
        return hmac.new(self._key, secret.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()[:16]

    def enrich(self, finding: Finding) -> Iterator[Finding]:
        tags = finding.tags
        if finding.protocol in CLEARTEXT_PROTOCOLS and finding.kind.is_secret and "cleartext" not in tags:
            tags.append("cleartext")
        if finding.kind in (Kind.CREDENTIAL, Kind.PASSWORD) and finding.secret:
            secret = finding.secret
            if secret.lower() in self.weak or len(secret) < 6:
                if "weak-password" not in tags:
                    tags.append("weak-password")
                    self.weak_count += 1
            fp = self.fingerprint(secret)
            finding.extra.setdefault("secret_fingerprint", fp)
            who = (finding.username or "", f"{finding.protocol}@{finding.dst.ip}")
            users = self._secret_users[fp]
            users.add(who)
            if len({u for u, _ in users}) > 1 or len({w for _, w in users}) > 1:
                if "password-reuse" not in tags:
                    tags.append("password-reuse")
                self.reused[fp] = len(users)
        if finding.kind is Kind.COMMUNITY and "default-community" in tags:
            finding.risk = "high"
        if "weak-password" in tags and finding.risk != "high":
            finding.risk = "high"
        self._profile(finding)
        return iter(())

    def _profile(self, f: Finding) -> None:
        if f.kind in (Kind.URL, Kind.SEARCH, Kind.POST, Kind.INFO):
            return
        self.risk_counts[f.risk] += 1
        client = self.hosts.setdefault(f.src.ip, HostProfile(f.src.ip))
        server = self.hosts.setdefault(f.dst.ip, HostProfile(f.dst.ip))
        if f.kind is Kind.AUTH_RESULT:
            return
        client.exposed_as_client += 1
        server.exposed_to_server += 1
        for h in (client, server):
            h.protocols.add(f.protocol)
            if f.username:
                h.accounts.add(f.username if not f.domain else f"{f.domain}\\{f.username}")
            if _RISK_ORDER.get(f.risk, 0) > _RISK_ORDER.get(h.max_risk, 0):
                h.max_risk = f.risk

    def summary(self) -> dict[str, Any]:
        return {
            "weak_passwords": self.weak_count,
            "reused_secrets": len(self.reused),
            "risk_counts": dict(self.risk_counts),
            "hosts": sorted(
                (
                    {
                        "ip": h.ip,
                        "as_client": h.exposed_as_client,
                        "as_server": h.exposed_to_server,
                        "protocols": sorted(h.protocols),
                        "accounts": sorted(h.accounts),
                        "max_risk": h.max_risk,
                    }
                    for h in self.hosts.values()
                    if h.exposed_as_client or h.exposed_to_server
                ),
                key=lambda d: (-_RISK_ORDER.get(str(d["max_risk"]), 0), -(int(d["as_client"]) + int(d["as_server"]))),  # type: ignore[call-overload]
            ),
        }
