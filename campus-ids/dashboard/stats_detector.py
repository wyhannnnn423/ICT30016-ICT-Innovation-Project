"""
stats_detector.py
------------------------
Simple per-source-IP statistical detector (no ML, no training data needed).

Looks at connection attempts from each source IP inside a sliding time window:
  - Port scan       : many different destination ports on the SAME destination host
  - Connection flood: a very high number of connections from one source
"""

import time
from collections import Counter, defaultdict, deque


class ScanFloodDetector:
    def __init__(self, window=10, scan_ports=15, flood_flows=150, cooldown=30):
        self.window = window            # seconds of history to keep per source IP
        self.scan_ports = scan_ports    # distinct ports on one host -> port scan
        self.flood_flows = flood_flows  # connections in the window -> flood
        self.cooldown = cooldown        # seconds before the same source+type alerts again
        self.events = defaultdict(deque)   # src_ip -> deque[(time, dest_ip, dest_port)]
        self.last_alert = {}               # (src_ip, kind) -> time
        self._calls = 0

    def add(self, src_ip, dest_ip, dest_port, now=None, proto=None):
        """Record one connection attempt. Returns a list of alert dicts (usually empty)."""
        if not src_ip:
            return []
        now = time.time() if now is None else now

        q = self.events[src_ip]
        q.append((now, dest_ip, dest_port, proto))
        while q and now - q[0][0] > self.window:
            q.popleft()

        self._calls += 1
        if self._calls % 2000 == 0:
            self._cleanup(now)

        # Port scan: distinct ports hit on the same destination host
        ports = {p for (_, d, p, _pr) in q if d == dest_ip and p is not None}
        if len(ports) >= self.scan_ports:
            kind = "scan"
            detail = f"Port scan: {len(ports)}+ different ports on {dest_ip} within {self.window}s"
            severity = "Medium"
            target, target_proto = dest_ip, proto
        elif len(q) >= self.flood_flows:
            kind = "flood"
            # name the host and protocol that received most of the connections, not just the last one
            target = Counter(d for (_, d, _p, _pr) in q).most_common(1)[0][0]
            target_proto = Counter(pr for (_, _d, _p, pr) in q).most_common(1)[0][0]
            detail = f"Connection flood: {len(q)}+ connections within {self.window}s, most to {target}"
            severity = "High"
        else:
            return []

        last = self.last_alert.get((src_ip, kind))
        if last is not None and now - last < self.cooldown:
            return []
        self.last_alert[(src_ip, kind)] = now
        return [{"kind": kind, "detail": detail, "severity": severity, "dest_ip": target, "proto": target_proto}]

    def _cleanup(self, now):
        for src in [s for s, q in self.events.items() if not q or now - q[-1][0] > self.window]:
            del self.events[src]
        for key in [k for k, t in self.last_alert.items() if now - t > self.cooldown]:
            del self.last_alert[key]
