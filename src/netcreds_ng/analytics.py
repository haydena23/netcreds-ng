from __future__ import annotations
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Dict, Set, Any

from netcreds_ng import state
from netcreds_ng import analytics_configs

# --- Constants for Analysis ---
CLEARTEXT_PROTOCOLS = analytics_configs.GetClearTextProtocols()

WEAK_PASSWORDS = analytics_configs.GetWeakPasswords()

@dataclass
class HostProfile:
    ip_address: str
    creds_as_source: int = 0
    creds_as_dest: int = 0
    protocols_used: Set[str] = field(default_factory=set) # type: ignore

class AnalyticsTracker:
    def __init__(self, is_pcap: bool = False, pcap_size: int = 0):
        self.start_time = time.time()
        self.total_packets = 0
        self.interesting_packets = 0
        self.creds_found = 0

        self.protocol_counts: Dict[str, int] = Counter()
        self.protocols_seen: Dict[str, int] = Counter()
        self.cleartext_creds: Dict[str, int] = Counter()

        self.unique_hosts: Set[str] = set()
        self.host_profiles: Dict[str, HostProfile] = {}

        self.password_reuse: Dict[str, int] = Counter()
        self.weak_passwords_found: int = 0

        self._last_update_time = self.start_time
        self._last_packet_count = 0
        self.packets_per_second = 0.0
        self.pps_history: deque[float] = deque(maxlen=60)

        self.is_pcap = is_pcap
        self.pcap_size = pcap_size
        self.bytes_processed = 0

    def get_or_create_host(self, ip: str) -> HostProfile:
        if ip not in self.host_profiles:
            self.host_profiles[ip] = HostProfile(ip_address=ip)
        return self.host_profiles[ip]

    def increment_packets(self, src_ip: str, dst_ip: str):
        self.total_packets += 1
        self.unique_hosts.add(src_ip)
        self.unique_hosts.add(dst_ip)

    def increment_interesting(self, protocol: str):
        self.interesting_packets += 1
        self.protocols_seen[protocol] += 1

    def add_credential(self, result: Dict[str, Any]):
        protocol = result.get("protocol", "Unknown")
        cred_type = result.get("type", "").lower()
        credential = result.get("credential", "").strip()

        if "password" in cred_type or "hash" in cred_type or "key" in cred_type or "string" in cred_type:
            self.creds_found += 1
            self.protocol_counts[protocol] += 1

            if protocol in CLEARTEXT_PROTOCOLS and "hash" not in cred_type:
                self.cleartext_creds[protocol] += 1
                if "password" in cred_type and credential:
                    self.password_reuse[credential] += 1
                    if credential.lower() in WEAK_PASSWORDS:
                        self.weak_passwords_found += 1
        
        src_ip = result.get("source", "N/A").split(":")[0]
        dst_ip = result.get("destination", "N/A").split(":")[0]
        if src_ip != "N/A":
            source_host = self.get_or_create_host(src_ip)
            source_host.creds_as_source += 1
            source_host.protocols_used.add(protocol)
        if dst_ip != "N/A":
            dest_host = self.get_or_create_host(dst_ip)
            dest_host.creds_as_dest += 1
            dest_host.protocols_used.add(protocol)
    
    def update_pcap_progress(self, bytes_read: int):
        self.bytes_processed = bytes_read

    def update_pps(self):
        now = time.time()
        time_delta = now - self._last_update_time
        if time_delta >= 1:
            packet_delta = self.total_packets - self._last_packet_count
            self.packets_per_second = packet_delta / time_delta
            self.pps_history.append(self.packets_per_second)
            self._last_update_time = now
            self._last_packet_count = self.total_packets

    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
        
    @property
    def tracked_conversations(self) -> int:
        return len(state.telnet_prompts) + len(state.mail_auths) + len(state.ntlm_challenges)
    