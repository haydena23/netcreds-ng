"""Behavioural detection over login results, plus a service inventory and host risk scores.

Detections (each raised once per source/target per run as an ``ALERT`` finding):

* **brute force**: one client fails ``bruteforce`` times (default 5) against one service
  within ``window`` seconds (default 300), trying few distinct accounts;
* **password spraying**: one client fails against ``spray`` (default 5) or more distinct
  accounts on one service within the window;
* **targeted account**: one account on one service fails from ``targeted`` (default 5)
  or more distinct clients within the window (distributed guessing);
* **login after failures**: a success that follows a brute-force or spraying burst from
  the same client.

Time is capture time (``Finding.timestamp``), so results are the same for a capture file
analysed now or traffic seen live. Windows assume findings arrive roughly in capture order
(true within a file; give multiple files in chronological order). Accounts are compared
case-insensitively and without their domain. For RADIUS and TACACS+ the "client" is the
NAS / AAA client, so many users behind one access point can look like spraying; those
alerts say so in ``extra["note"]``. Thresholds are plugin options, e.g.
``--option detection.bruteforce=10``.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from netcreds_ng.model import Endpoint, Finding, Kind
from netcreds_ng.plugins.api import EnricherPlugin

ServiceKey = tuple[str, int, str]  # (server ip, server port, protocol)
_RISK_POINTS = {"high": 10, "medium": 4, "low": 1, "info": 0}
_ALERT_POINTS = 15


@dataclass
class _Attempt:
    ts: float
    user: str
    client: str
    frame: int


@dataclass
class Service:
    ip: str
    port: int
    protocol: str
    findings: int = 0
    cleartext: bool = False
    accounts: set[str] = field(default_factory=set)
    clients: set[str] = field(default_factory=set)
    failures: int = 0
    successes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


def _account(f: Finding) -> str:
    user = f.username or ""
    return f"{f.domain}\\{user}" if f.domain and user else user


def _same_account(name: str) -> str:
    """Key for counting distinct accounts: case-insensitive, domain stripped (DOM\\bob == bob == Bob)."""
    return name.rpartition("\\")[2].lower()


class DetectionEnricher(EnricherPlugin):
    name = "detection"
    description = "Brute-force / password-spraying / targeted-account alerts, service inventory, host risk scores"
    priority = 20  # after analytics, so tags such as "cleartext" are already set

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.window = float(self.options.get("window", 300))
        self.bruteforce = int(self.options.get("bruteforce", 5))
        self.spray = int(self.options.get("spray", 5))
        self.targeted = int(self.options.get("targeted", 5))
        self._by_pair: dict[tuple[str, ServiceKey], deque[_Attempt]] = defaultdict(deque)
        self._by_account: dict[tuple[str, ServiceKey], deque[_Attempt]] = defaultdict(deque)
        self._raised: set[tuple[str, ...]] = set()
        # (client, service) -> (detection that fired, capture time of the latest failure)
        self._burst: dict[tuple[str, ServiceKey], tuple[str, float]] = {}
        self.alerts: list[Finding] = []
        self.services: dict[ServiceKey, Service] = {}
        self.account_services: dict[str, set[str]] = defaultdict(set)
        self.host_points: dict[str, int] = defaultdict(int)

    # enrichment ------------------------------------------------------------------------

    def observe(self, finding: Finding) -> None:
        """Account for an already-enriched finding without raising alerts.

        Rebuilds the service inventory and host scores from stored findings (the dashboard's
        ``--attach`` mode). Stored alerts of this plugin count towards host scores as they did
        when they were raised.
        """
        if finding.kind is Kind.ALERT:
            if finding.plugin == self.name and "detection" in finding.extra:
                self.alerts.append(finding)
                self._alert_points(finding)
            return
        if finding.kind not in (Kind.URL, Kind.SEARCH, Kind.POST):
            self._inventory(finding)

    def enrich(self, finding: Finding) -> Iterator[Finding]:
        if finding.kind is Kind.ALERT:
            return iter(())
        if finding.kind in (Kind.URL, Kind.SEARCH, Kind.POST):
            return iter(())
        self._inventory(finding)
        if finding.kind is not Kind.AUTH_RESULT:
            return iter(())
        outcome = finding.outcome
        if outcome == "failure":
            return iter(self._failure(finding))
        if outcome == "success":
            return iter(self._success(finding))
        return iter(())

    def _inventory(self, f: Finding) -> None:
        key = (f.dst.ip, f.dst.port, f.protocol)
        svc = self.services.get(key)
        if svc is None:
            svc = self.services[key] = Service(f.dst.ip, f.dst.port, f.protocol, first_ts=f.timestamp)
        svc.findings += 1
        svc.last_ts = max(svc.last_ts, f.timestamp)
        svc.clients.add(f.src.ip)
        account = _account(f)
        if account:
            svc.accounts.add(account)
            self.account_services[account.lower()].add(f"{f.protocol}@{f.dst}")
        decrypted = "tls-decrypted" in f.tags
        if f.kind.is_secret and not decrypted and ("cleartext" in f.tags or f.kind in (Kind.CREDENTIAL, Kind.PASSWORD)):
            svc.cleartext = True
        if f.kind is Kind.AUTH_RESULT:
            if f.outcome == "failure":
                svc.failures += 1
            elif f.outcome == "success":
                svc.successes += 1
        else:
            points = _RISK_POINTS.get(f.risk, 0)
            self.host_points[f.src.ip] += points
            self.host_points[f.dst.ip] += points

    def _prune(self, q: deque[_Attempt], now: float) -> None:
        while q and now - q[0].ts > self.window:
            q.popleft()

    def _failure(self, f: Finding) -> list[Finding]:
        svc: ServiceKey = (f.dst.ip, f.dst.port, f.protocol)
        attempt = _Attempt(f.timestamp, _account(f), f.src.ip, f.frame)
        out: list[Finding] = []

        pair = self._by_pair[(f.src.ip, svc)]
        pair.append(attempt)
        self._prune(pair, f.timestamp)
        users = {_same_account(a.user) for a in pair if a.user}
        burst = self._burst.get((f.src.ip, svc))
        if burst is not None:
            self._burst[(f.src.ip, svc)] = (burst[0], f.timestamp)
        if len(users) >= self.spray:
            out += self._raise("password-spraying", (f.src.ip, *map(str, svc)), f, pair,
                               f"Password spraying: {len(users)} accounts failed from {f.src.ip} "
                               f"in {self._span(pair)}", users=sorted(users))  # fmt: skip
            self._burst[(f.src.ip, svc)] = ("password-spraying", f.timestamp)
        elif len(pair) >= self.bruteforce:
            who = f" for '{next(iter(users))}'" if len(users) == 1 else ""
            out += self._raise("brute-force", (f.src.ip, *map(str, svc)), f, pair,
                               f"Brute force: {len(pair)} failed logins{who} from {f.src.ip} "
                               f"in {self._span(pair)}", users=sorted(users))  # fmt: skip
            self._burst.setdefault((f.src.ip, svc), ("brute-force", f.timestamp))

        if attempt.user:
            acct = self._by_account[(_same_account(attempt.user), svc)]
            acct.append(attempt)
            self._prune(acct, f.timestamp)
            clients = {a.client for a in acct}
            if len(clients) >= self.targeted:
                out += self._raise("targeted-account", (_same_account(attempt.user), *map(str, svc)), f, acct,
                                   f"Account '{attempt.user}' failed from {len(clients)} clients "
                                   f"in {self._span(acct)}", clients=sorted(clients))  # fmt: skip
        return out

    def _success(self, f: Finding) -> list[Finding]:
        svc: ServiceKey = (f.dst.ip, f.dst.port, f.protocol)
        entry = self._burst.get((f.src.ip, svc))
        if entry is None or f.timestamp - entry[1] > self.window:
            return []  # no burst, or the burst ended long before this login (review L1)
        burst = entry[0]
        pair = self._by_pair.get((f.src.ip, svc), deque())
        user = _account(f)
        return self._raise("login-after-failures", (f.src.ip, *map(str, svc)), f, pair,
                           f"Successful login{f' as {user!r}' if user else ''} after {burst.replace('-', ' ')} "
                           f"from {f.src.ip}", preceded_by=burst)  # fmt: skip

    def _span(self, attempts: deque[_Attempt]) -> str:
        secs = attempts[-1].ts - attempts[0].ts if attempts else 0.0
        return f"{secs:.0f}s" if secs >= 1 else "under 1s"

    def _raise(self, kind: str, key: tuple[str, ...], f: Finding, attempts: deque[_Attempt], text: str,
               **extra: Any) -> list[Finding]:  # fmt: skip
        if (kind, *key) in self._raised:
            return []
        self._raised.add((kind, *key))
        alert = Finding(
            protocol=f.protocol,
            kind=Kind.ALERT,
            # Client IP only: the attempts span many connections, so a source port would mislead.
            # For a targeted account this is the latest client (all of them are in extra["clients"]).
            src=Endpoint(f.src.ip, 0),
            dst=f.dst,
            timestamp=f.timestamp,
            frame=f.frame,
            value=text,
            risk="high",
            plugin=self.name,
            tags=[kind],
            extra={
                "detection": kind,
                "attempts": len(attempts),
                "window_seconds": self.window,
                "frames": [a.frame for a in list(attempts)[-50:]],
                **extra,
            },
        )
        if f.protocol in ("RADIUS", "TACACS+"):
            alert.extra["note"] = "source is the NAS/AAA client; failures of several users behind it are aggregated"
        self.alerts.append(alert)
        self._alert_points(alert)
        return [alert]

    def _alert_points(self, alert: Finding) -> None:
        self.host_points[alert.dst.ip] += _ALERT_POINTS
        if alert.extra.get("detection") != "targeted-account":
            self.host_points[alert.src.ip] += _ALERT_POINTS

    # reporting ---------------------------------------------------------------------------

    def host_score(self, ip: str) -> int:
        """0-100 exposure score: weighted findings (high 10, medium 4, low 1) plus 15 per alert."""
        return min(100, self.host_points.get(ip, 0))

    def summary(self) -> dict[str, Any]:
        services = sorted(self.services.values(), key=lambda s: (not s.cleartext, -s.findings, s.ip, s.port))
        return {
            "alerts": [
                {"detection": a.extra["detection"], "src": str(a.src), "dst": str(a.dst), "protocol": a.protocol,
                 "value": a.value, "attempts": a.extra["attempts"], "frame": a.frame}
                for a in self.alerts
            ],
            "services": [
                {"server": str(Endpoint(s.ip, s.port)), "protocol": s.protocol, "cleartext": s.cleartext,
                 "findings": s.findings, "accounts": sorted(s.accounts)[:50], "clients": len(s.clients),
                 "failures": s.failures, "successes": s.successes}
                for s in services
            ],
            "shared_accounts": sorted(
                ({"account": acct, "services": sorted(svcs)} for acct, svcs in self.account_services.items()
                 if len(svcs) > 1),
                key=lambda d: (-len(d["services"]), d["account"]),
            ),
            "host_scores": {ip: self.host_score(ip) for ip in sorted(self.host_points) if self.host_points[ip]},
        }
