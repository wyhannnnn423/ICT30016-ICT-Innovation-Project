"""
Tests for the Design 2 live Random Forest layer (dashboard/rf_detector.py).

They use made-up Suricata flow events and a small Random Forest trained on them, so they need
neither Suricata nor the real model.

Run from the project root:
    python tests/test_rf_detector.py
"""

import random
import sys
import tempfile
import unittest
from pathlib import Path

import joblib
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "dashboard"))
sys.path.insert(0, str(ROOT / "design2"))

from aggregate import aggregate, FEATURES                       # noqa: E402
from detection import Detector                                   # noqa: E402
from rf_detector import RFDetector                               # noqa: E402
from train_rf import make_model, DEFAULT_FEATURES               # noqa: E402

T0 = pd.Timestamp("2026-10-14 10:00:00", tz="UTC").timestamp()   # a multiple of 10 s


def iso(epoch):
    return pd.Timestamp(epoch, unit="s", tz="UTC").strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def flow(src, start, port, pkts=2, nbytes=120, rst=True, dest="192.168.50.190", logged=None):
    """One eve.json flow event. `logged` = when Suricata wrote it (default: start + 1 s)."""
    logged = start + 1 if logged is None else logged
    return {"event_type": "flow", "timestamp": iso(logged), "src_ip": src, "dest_ip": dest,
            "dest_port": port, "proto": "TCP",
            "flow": {"start": iso(start), "pkts_toserver": pkts // 2 or 1, "pkts_toclient": pkts - (pkts // 2 or 1),
                     "bytes_toserver": nbytes // 2, "bytes_toclient": nbytes - nbytes // 2},
            "tcp": {"syn": True, "rst": rst}}


def make_events(n_windows=60, seed=1):
    """Benign browsing from 15 hosts, plus one scan and one flood."""
    rnd = random.Random(seed)
    ev = []
    for w in range(n_windows):
        base = T0 + 10 * w
        for h in range(15):
            for _ in range(rnd.randint(1, 4)):
                ev.append(flow(f"10.0.0.{h + 1}", base + rnd.uniform(0, 9), rnd.choice([80, 443]),
                               pkts=rnd.randint(8, 40), nbytes=rnd.randint(2000, 90000), rst=False))
        if w in (10, 11, 30, 31, 45):                       # scans from .200
            for p in range(60):
                ev.append(flow("10.0.0.200", base + p * 0.1, 1000 + p))
        if w in (20, 21, 50):                               # floods from .201
            for _ in range(200):
                ev.append(flow("10.0.0.201", base + rnd.uniform(0, 9), 80, pkts=6, nbytes=360))
    ev.sort(key=lambda e: e["timestamp"])
    return ev


def train_small_model(events, path):
    from aggregate import parse_flow_event
    flows = pd.DataFrame([parse_flow_event(e) for e in events])
    table = aggregate(flows, "10s")
    table["is_attack"] = table["src_ip"].isin(["10.0.0.200", "10.0.0.201"]).astype(int)
    table = table[(table["is_attack"] == 0) | (table["conn_count"] >= 5)]
    model = make_model().fit(table[DEFAULT_FEATURES], table["is_attack"])
    joblib.dump({"model": model, "features": DEFAULT_FEATURES}, path)
    return table


def replay(det, events):
    """Feed events in order, with the 'wall clock' following the event time. Returns all alerts."""
    out = []
    for e in events:
        now = pd.Timestamp(e["timestamp"]).timestamp()
        out += det.add(e, now)
    return out


class RFDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.model_path = str(Path(cls.tmp.name) / "rf.joblib")
        cls.events = make_events()
        cls.table = train_small_model(cls.events, cls.model_path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_live_matches_offline(self):
        """Live windows must give the same predictions as aggregate.py + the model on the same flows."""
        det = RFDetector(self.model_path, cooldown=0)
        alerts = replay(det, self.events)
        alerts += det.tick(T0 + 10_000)                       # end of data: flush the last windows
        live = {(a["src_ip"], a["timestamp"]) for a in alerts}

        offline = self.table.copy()
        model = joblib.load(self.model_path)["model"]
        offline["p"] = model.predict_proba(offline[DEFAULT_FEATURES])[:, 1]
        hit = offline[(offline["p"] >= 0.5) & (offline["conn_count"] >= 5)]
        expected = {(r.src_ip, iso(r.window.timestamp() + 10)[:19]) for r in hit.itertuples()}
        got = {(ip, pd.Timestamp(ts).strftime("%Y-%m-%dT%H:%M:%S")) for ip, ts in live}
        self.assertEqual(got, {(ip, ts) for ip, ts in expected})
        self.assertEqual(len(alerts), len(hit))

    def test_scan_and_flood_flagged_benign_quiet(self):
        det = RFDetector(self.model_path, cooldown=0)
        alerts = replay(det, self.events) + det.tick(T0 + 10_000)
        by_ip = {a["src_ip"] for a in alerts}
        self.assertIn("10.0.0.200", by_ip)
        self.assertIn("10.0.0.201", by_ip)
        self.assertFalse([a for a in alerts if a["src_ip"].startswith("10.0.0.") and a["src_ip"] not in ("10.0.0.200", "10.0.0.201")])
        a = alerts[0]
        self.assertEqual(a["source"], "RF")
        self.assertIn(a["severity"], ("High", "Medium"))
        self.assertTrue(0.5 <= a["score"] <= 1.0)

    def test_cooldown_limits_repeats(self):
        det = RFDetector(self.model_path, cooldown=30)
        alerts = replay(det, self.events) + det.tick(T0 + 10_000)
        scans = [a for a in alerts if a["src_ip"] == "10.0.0.200"]
        self.assertLess(len(scans), 5)           # 5 scan windows, but windows 10 and 11 are 10 s apart

    def test_window_closes_after_grace_only(self):
        det = RFDetector(self.model_path, cooldown=0, grace=5)
        got = []
        for p in range(60):                                     # scan inside window [T0, T0+10)
            got += det.add(flow("10.0.0.200", T0 + p * 0.1, 1000 + p), T0 + p * 0.1 + 1)
        self.assertEqual(got, [])
        self.assertEqual(det.tick(T0 + 11), [])                 # window over, but still inside the grace period
        self.assertTrue(det.tick(T0 + 16.5))                    # now it is scored

    def test_late_flow_is_dropped_not_crash(self):
        det = RFDetector(self.model_path, cooldown=0)
        det.add(flow("10.0.0.5", T0 + 1, 80, pkts=20), T0 + 2)
        det.tick(T0 + 100)
        det.add(flow("10.0.0.5", T0 + 2, 80, pkts=20, logged=T0 + 99), T0 + 100)
        self.assertEqual(det.late_dropped, 1)

    def test_non_flow_events_ignored(self):
        det = RFDetector(self.model_path)
        self.assertEqual(det.add({"event_type": "alert", "src_ip": "1.2.3.4"}), [])
        self.assertEqual(det.add({"event_type": "dns"}), [])

    def test_wrong_model_file_is_rejected(self):
        bad = str(Path(self.tmp.name) / "bad.joblib")
        joblib.dump({"nothing": 1}, bad)
        with self.assertRaises(ValueError):
            RFDetector(bad)


class DetectorIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.model_path = str(Path(cls.tmp.name) / "rf.joblib")
        cls.events = make_events()
        train_small_model(cls.events, cls.model_path)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_detector(self, **kw):
        det = Detector(rf_model_path=self.model_path, **kw)
        out = []
        for e in self.events:
            out += det.process(e, now=pd.Timestamp(e["timestamp"]).timestamp())
        return det, out + det.tick(T0 + 10_000)

    def test_rf_alerts_appear_next_to_stats(self):
        det, out = self.run_detector()
        self.assertTrue(det.rf_enabled)
        self.assertTrue([a for a in out if a["source"] == "RF" and a["src_ip"] == "10.0.0.200"])
        self.assertTrue([a for a in out if a["source"] == "Stats" and a["src_ip"] == "10.0.0.200"])

    def test_trusted_source_is_skipped(self):
        _, out = self.run_detector(trusted_ips=["10.0.0.200"])
        self.assertFalse([a for a in out if a["source"] == "RF" and a["src_ip"] == "10.0.0.200"])
        self.assertTrue([a for a in out if a["source"] == "RF" and a["src_ip"] == "10.0.0.201"])

    def test_rf_is_off_by_default(self):
        det = Detector()
        self.assertFalse(det.rf_enabled)
        self.assertEqual(det.tick(), [])

    def test_missing_model_switches_rf_off_without_crash(self):
        det = Detector(rf_model_path=str(Path(self.tmp.name) / "nope.joblib"))
        self.assertFalse(det.rf_enabled)
        self.assertTrue(det.rf_error)
        self.assertEqual(det.process(self.events[0], now=T0), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
