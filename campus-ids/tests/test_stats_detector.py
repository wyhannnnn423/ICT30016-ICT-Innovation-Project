"""
Tests for dashboard/stats_detector.py.

The detector keeps running counts so that each flow costs a few dictionary updates. These tests check
that it gives exactly the same alerts as the plain "re-read the whole window for every flow" way of
counting, and that a flood of 100,000+ flows is handled quickly.

Run from the project root:
    python tests/test_stats_detector.py
"""

import random
import sys
import time
import unittest
from collections import Counter, defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "dashboard"))
from stats_detector import ScanFloodDetector  # noqa: E402


class SimpleReference:
    """The obvious (slow) way: look at every connection of the window again for every new one."""

    def __init__(self, window, scan_ports, flood_flows, cooldown):
        self.window, self.scan_ports, self.flood_flows, self.cooldown = window, scan_ports, flood_flows, cooldown
        self.events = defaultdict(deque)
        self.last_alert = {}

    def add(self, src_ip, dest_ip, dest_port, now, proto):
        q = self.events[src_ip]
        q.append((now, dest_ip, dest_port, proto))
        while q and now - q[0][0] > self.window:
            q.popleft()
        ports = {p for (_, d, p, _pr) in q if d == dest_ip and p is not None}
        if len(ports) >= self.scan_ports:
            kind, detail = "scan", f"Port scan: {len(ports)}+ different ports on {dest_ip} within {self.window}s"
        elif len(q) >= self.flood_flows:
            kind = "flood"
            detail = f"Connection flood: {len(q)}+ connections within {self.window}s"
        else:
            return []
        last = self.last_alert.get((src_ip, kind))
        if last is not None and now - last < self.cooldown:
            return []
        self.last_alert[(src_ip, kind)] = now
        return [(kind, detail)]


class StatsDetectorTests(unittest.TestCase):
    def test_same_alerts_as_simple_counting(self):
        rnd = random.Random(7)
        for _ in range(60):
            kw = dict(window=rnd.choice([5, 10, 20]), scan_ports=rnd.choice([3, 5, 15]),
                      flood_flows=rnd.choice([20, 60, 150]), cooldown=rnd.choice([0, 1, 30]))
            fast, slow = ScanFloodDetector(**kw), SimpleReference(**kw)
            t = 0.0
            sources = [f"s{i}" for i in range(rnd.randint(1, 4))]
            for _ in range(rnd.randint(200, 800)):
                t += rnd.choice([0.001, 0.01, 0.05, 0.5, 2.0])
                src, dest = rnd.choice(sources), rnd.choice(["d1"] * 6 + ["d2", "d3"])
                port = rnd.choice([None] + list(range(rnd.choice([3, 10, 200]))))
                proto = rnd.choice(["TCP", "UDP"])
                got = [(a["kind"], a["detail"].split(", most to")[0]) for a in fast.add(src, dest, port, now=t, proto=proto)]
                self.assertEqual(got, slow.add(src, dest, port, t, proto))

    def test_flood_target_and_protocol_are_the_majority(self):
        det = ScanFloodDetector(window=10, scan_ports=15, flood_flows=50, cooldown=0)
        out = []
        for i in range(120):
            out += det.add("atk", "victim" if i % 4 else "other", 80, now=i * 0.01, proto="UDP" if i % 4 else "TCP")
        self.assertTrue(out)
        self.assertEqual({a["dest_ip"] for a in out}, {"victim"})
        self.assertEqual({a["proto"] for a in out}, {"UDP"})

    def test_huge_flood_is_fast(self):
        det = ScanFloodDetector(window=10, scan_ports=15, flood_flows=150, cooldown=0)
        start = time.time()
        for i in range(200_000):                      # 200,000 flows inside one 10-second window
            det.add("k", "v", i % 60000, now=i * 0.00002, proto="UDP")
        self.assertLess(time.time() - start, 10)

    def test_old_sources_are_forgotten(self):
        det = ScanFloodDetector(window=10)
        for i in range(2500):
            det.add(f"ip{i}", "v", 80, now=i * 0.01)
        det.add("late", "v", 80, now=1000.0)
        det._cleanup(1000.0)
        self.assertEqual(list(det.events), ["late"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
