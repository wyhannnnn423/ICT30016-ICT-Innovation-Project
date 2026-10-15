"""
rf_detector.py  (Design 2, live)
--------------------------------
Real-time version of design2/aggregate.py + the Random Forest from design2/train_rf.py.

Every Suricata flow event is put into a bucket "(10-second window, source IP)". When a window is
over, its features are computed with the SAME code as in training (design2/aggregate.py), the
Random Forest scores each source IP, and an alert is returned for every source it calls an attack.

Why a window only closes a few seconds after it ends:
    Suricata writes a flow record when the flow ENDS, but training groups flows by when they
    STARTED. So the detector waits `grace` seconds after the end of a window for late records.
    Expected delay between an attack and its "RF" alert: window (10 s) + grace (5 s) at most.

Typical use (done for you by detection.Detector when the dashboard starts with --rf):
    rf = RFDetector("model/rf_model.joblib")
    for event in eve_json_lines:
        alerts = rf.add(event, now)      # usually []
    alerts = rf.tick(now)                # call about once a second so quiet networks still flush
"""

import sys
import time
from pathlib import Path

import joblib
import pandas as pd

# design2/aggregate.py lives next to this folder
_DESIGN2 = Path(__file__).resolve().parent.parent / "design2"
if str(_DESIGN2) not in sys.path:
    sys.path.insert(0, str(_DESIGN2))

from aggregate import aggregate, parse_flow_event  # noqa: E402


def _epoch(value):
    """ISO timestamp string -> UTC epoch seconds (None if it cannot be read)."""
    t = pd.to_datetime(value, errors="coerce", utc=True)
    return None if pd.isnull(t) else t.timestamp()


class RFDetector:
    def __init__(self, model_path, window=10, grace=5, threshold=0.5, min_flows=5, cooldown=30):
        bundle = joblib.load(model_path)
        if not isinstance(bundle, dict) or "model" not in bundle or "features" not in bundle:
            raise ValueError("expected a file made by design2/train_rf.py (a dict with 'model' and 'features')")
        self.model = bundle["model"]
        self.features = list(bundle["features"])
        self.window = int(window)          # seconds, must match the --window used in training (10)
        self.grace = float(grace)          # seconds to wait for late flow records
        self.threshold = float(threshold)  # attack probability needed for an alert
        self.min_flows = int(min_flows)    # same idea as aggregate.py --min-attack-flows: 1-2 flows are not an attack
        self.cooldown = float(cooldown)    # seconds before the same source raises another RF alert (0 = every window)
        self._pos = list(self.model.classes_).index(1)

        self.buffers = {}        # window start (epoch) -> list of flow rows
        self.arrived = {}        # window start -> wall-clock time of the newest row
        self.closed = set()      # windows already scored (late rows for them are dropped)
        self.clock = 0.0         # newest event time seen (epoch)
        self.last_alert = {}     # src_ip -> window start of its last alert
        self.late_dropped = 0
        self.debug = False       # True: print every scored window with 2+ flows (see app.py --rf-debug)
        self.windows_scored = 0

    # ------------------------------------------------------------------
    def add(self, event, now=None):
        """Feed one parsed eve.json line. Returns a list of alert dicts (usually empty)."""
        row = parse_flow_event(event)
        if row is None or not row["src_ip"]:
            return []
        now = time.time() if now is None else now

        start = _epoch(row["start"])
        stamp = _epoch(row["timestamp"])
        if start is None:
            start = stamp
        if start is None:
            return []
        if stamp is not None:
            self.clock = max(self.clock, stamp)

        bucket = (start // self.window) * self.window
        if bucket in self.closed:
            self.late_dropped += 1
        else:
            self.buffers.setdefault(bucket, []).append(row)
            self.arrived[bucket] = now
        return self._close_ready(now)

    def tick(self, now=None):
        """Close windows whose time is up even when no new event arrives (quiet network)."""
        return self._close_ready(time.time() if now is None else now)

    # ------------------------------------------------------------------
    def _close_ready(self, now):
        alerts = []
        for bucket in sorted(self.buffers):
            # 1) the newest event time is already past the window + grace (normal case, also when replaying a file)
            # 2) quiet network: the window is over and nothing new arrived for it during the grace period
            by_event_clock = bucket + self.window + self.grace <= self.clock
            by_quiet = now >= bucket + self.window and now - self.arrived[bucket] > self.grace
            if by_event_clock or by_quiet:
                alerts += self._score(bucket, self.buffers.pop(bucket))
                self.arrived.pop(bucket, None)
                self.closed.add(bucket)
        if len(self.closed) > 500:                       # keep memory small
            keep = sorted(self.closed)[-100:]
            self.closed = set(keep)
        return alerts

    def _score(self, bucket, rows):
        flows = pd.DataFrame(rows)
        table = aggregate(flows, f"{self.window}s")
        if table.empty:
            return []
        self.windows_scored += len(table)
        proba = self.model.predict_proba(table[self.features])[:, self._pos]

        end_iso = pd.Timestamp(bucket + self.window, unit="s", tz="UTC").isoformat()
        alerts = []
        for (_, r), p in zip(table.iterrows(), proba):
            if self.debug and r["conn_count"] >= 2:
                print(f"[RF debug] {r['src_ip']}  window {pd.Timestamp(bucket, unit='s', tz='UTC'):%H:%M:%S}Z  flows={int(r['conn_count'])} "
                      f"ports={int(r['distinct_ports'])} rst={r['rst_ratio']:.2f} avg_pkts={r['avg_pkts']:.1f}  p(attack)={p:.2f}"
                      + ("" if r["conn_count"] >= self.min_flows else "  (fewer than min_flows: never alerts)"))
            if p < self.threshold or r["conn_count"] < self.min_flows:
                continue
            ip = r["src_ip"]
            last = self.last_alert.get(ip)
            if last is not None and bucket - last < self.cooldown:
                continue
            self.last_alert[ip] = bucket

            mine = flows[flows["src_ip"] == ip]
            dest = mine["dest_ip"].mode()
            proto = mine["proto"].mode()
            alerts.append({
                "timestamp": end_iso,
                "src_ip": ip,
                "dest_ip": dest.iloc[0] if len(dest) else "-",
                "proto": proto.iloc[0] if len(proto) else "Unknown",
                "source": "RF",
                "detail": (f"Random Forest: {int(r['conn_count'])} flows, {int(r['distinct_ports'])} ports, "
                           f"{r['rst_ratio']:.0%} resets in {self.window}s"),
                "severity": "High" if p >= 0.8 else "Medium",
                "score": round(float(p), 3),
            })
        return alerts
