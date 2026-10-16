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


class _Source:
    """What we remember about ONE source IP inside the window.
    Besides the list of connections it keeps running counts, so that each new connection costs a
    few dictionary updates instead of a pass over every connection of the last few seconds.
    (The old version re-read the whole window for every flow, which froze on floods of 100,000+ flows.)"""
    __slots__ = ("q", "ports", "dests", "protos")

    def __init__(self):
        self.q = deque()          # (time, dest_ip, dest_port, proto)
        self.ports = {}           # dest_ip -> {dest_port: how many times}
        self.dests = Counter()    # dest_ip -> connections
        self.protos = Counter()   # proto   -> connections

    def push(self, item):
        _, d, p, pr = item
        self.q.append(item)
        self.dests[d] += 1
        self.protos[pr] += 1
        if p is not None:
            by_port = self.ports.setdefault(d, {})
            by_port[p] = by_port.get(p, 0) + 1

    def pop(self):
        _, d, p, pr = self.q.popleft()
        self.dests[d] -= 1
        if self.dests[d] <= 0:
            del self.dests[d]
        self.protos[pr] -= 1
        if self.protos[pr] <= 0:
            del self.protos[pr]
        if p is not None:
            by_port = self.ports[d]
            by_port[p] -= 1
            if by_port[p] <= 0:
                del by_port[p]
                if not by_port:
                    del self.ports[d]


class ScanFloodDetector:
    def __init__(self, window=10, scan_ports=15, flood_flows=150, cooldown=30):
        self.window = window            # seconds of history to keep per source IP
        self.scan_ports = scan_ports    # distinct ports on one host -> port scan
        self.flood_flows = flood_flows  # connections in the window -> flood
        self.cooldown = cooldown        # seconds before the same source+type alerts again
        self.events = defaultdict(_Source)   # src_ip -> what we remember about it
        self.last_alert = {}                 # (src_ip, kind) -> time
        self._calls = 0

    def add(self, src_ip, dest_ip, dest_port, now=None, proto=None):
        """Record one connection attempt. Returns a list of alert dicts (usually empty)."""
        if not src_ip:
            return []
        now = time.time() if now is None else now

        src = self.events[src_ip]
        src.push((now, dest_ip, dest_port, proto))
        while src.q and now - src.q[0][0] > self.window:
            src.pop()

        self._calls += 1
        if self._calls % 2000 == 0:
            self._cleanup(now)

        # Port scan: distinct ports hit on the same destination host
        n_ports = len(src.ports.get(dest_ip, ()))
        if n_ports >= self.scan_ports:
            kind = "scan"
        elif len(src.q) >= self.flood_flows:
            kind = "flood"
        else:
            return []

        last = self.last_alert.get((src_ip, kind))
        if last is not None and now - last < self.cooldown:
            return []
        self.last_alert[(src_ip, kind)] = now

        if kind == "scan":
            detail = f"Port scan: {n_ports}+ different ports on {dest_ip} within {self.window}s"
            severity = "Medium"
            target, target_proto = dest_ip, proto
        else:
            # name the host and protocol that received most of the connections, not just the last one
            target = src.dests.most_common(1)[0][0]
            target_proto = src.protos.most_common(1)[0][0]
            detail = f"Connection flood: {len(src.q)}+ connections within {self.window}s, most to {target}"
            severity = "High"
        return [{"kind": kind, "detail": detail, "severity": severity, "dest_ip": target, "proto": target_proto}]

    def _cleanup(self, now):
        for src in [s for s, st in self.events.items() if not st.q or now - st.q[-1][0] > self.window]:
            del self.events[src]
        for key in [k for k, t in self.last_alert.items() if now - t > self.cooldown]:
            del self.last_alert[key]
