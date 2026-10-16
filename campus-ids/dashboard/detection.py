"""
detection.py
------------------------
The detection logic of the Campus IDS, kept separate from Flask so it can be
tested without a web server.

Detector.process(event) takes ONE parsed line of Suricata's eve.json and returns
a list of alert dicts (usually empty). Three layers:
  - "Rule"  : Suricata signature alerts (event_type == "alert")
  - "Stats" : per-source-IP port-scan / connection-flood counting (event_type == "flow")
  - "ML"    : Design 1 uses Isolation Forest per completed flow; Design 2 uses
               a Random Forest classifier over rolling per-source flow aggregates.

If the ML model cannot be loaded, the Rule and Stats layers still work.
"""

import time
import warnings
from collections import defaultdict, deque

import pandas as pd

from ids_settings import IpMatcher
from stats_detector import ScanFloodDetector

SEVERITY_LABEL = {1: "High", 2: "Medium", 3: "Low"}


class Detector:
    def __init__(self, model_path=None, scaler_path=None, design2=False,
                 own_ips=(), trusted_ips=(), auto_own_ip=False,
                 min_pkts=15, scan_ports=15, flood_flows=150,
                 window=10, cooldown=30, dedup_seconds=5):
        self.auto_own_ip = auto_own_ip         # True: own IP follows the detected network address
        self.started = time.time()
        self.last_event = None                 # when Suricata last delivered any event
        self.last_own_seen = None              # ... and when one of them involved this PC
        self.own = IpMatcher(own_ips)          # the monitored PC itself
        self.trusted = IpMatcher(trusted_ips)  # other trusted sources (single IPs or ranges)
        self.min_pkts = min_pkts          # Design 1 only looks at flows with at least this many packets
        self.design2 = bool(design2)
        self.rf_window_seconds = max(10, int(window))
        self._rf_flows = defaultdict(deque)  # source IP -> recent flow feature rows
        self._rf_last_alert = {}
        self.dedup_seconds = dedup_seconds
        self._recent_rule_alerts = {}     # (src, dest, signature_id) -> last time emitted
        self.stats = ScanFloodDetector(window=window, scan_ports=scan_ports,
                                       flood_flows=flood_flows, cooldown=cooldown)
        self.model = None
        self.scaler = None
        self.rf_features = ["conn_count", "distinct_ports", "rst_ratio", "avg_pkts", "total_bytes"]
        self.ml_error = None
        self._load_model(model_path, scaler_path)

    # ---------- ML model ----------
    def _load_model(self, model_path, scaler_path):
        if not model_path or (not self.design2 and not scaler_path):
            self.ml_error = "no model path given"
            return
        try:
            import joblib
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                loaded = joblib.load(model_path)
                if self.design2:
                    if isinstance(loaded, dict) and "model" in loaded:
                        self.model = loaded["model"]
                        self.rf_features = list(loaded.get("features", self.rf_features))
                    else:
                        self.model = loaded
                    self.scaler = None
                else:
                    self.model = loaded
                    self.scaler = joblib.load(scaler_path)
        except Exception as e:   # missing file, version mismatch, corrupt file ...
            self.model = None
            self.scaler = None
            self.ml_error = f"{type(e).__name__}: {e}"

    @property
    def ml_enabled(self):
        return self.model is not None

    # ---------- settings that can be changed while running ----------
    def is_ignored(self, ip):
        """True if Rule and Stats alerts from this source IP must be hidden."""
        return self.own.matches(ip) or self.trusted.matches(ip)

    def get_settings(self):
        return {
            "auto_own_ip": self.auto_own_ip,
            "own_ips": self.own.to_list(),
            "trusted_ips": self.trusted.to_list(),
            "scan_ports": self.stats.scan_ports,
            "flood_flows": self.stats.flood_flows,
            "window": self.stats.window,
            "cooldown": self.stats.cooldown,
        }

    def apply_settings(self, s):
        """Apply already-validated settings (see ids_settings.validate) immediately."""
        self.auto_own_ip = bool(s.get("auto_own_ip", self.auto_own_ip))
        self.own = IpMatcher(s["own_ips"])
        self.trusted = IpMatcher(s["trusted_ips"])
        self.stats.scan_ports = s["scan_ports"]
        self.stats.flood_flows = s["flood_flows"]
        self.stats.window = s["window"]
        self.stats.cooldown = s["cooldown"]

    @staticmethod
    def _features(flow):
        start_ts = pd.to_datetime(flow.get("start"), errors="coerce")
        end_ts = pd.to_datetime(flow.get("end"), errors="coerce")
        duration = (end_ts - start_ts).total_seconds() if pd.notnull(start_ts) and pd.notnull(end_ts) else 0.0

        pts, ptc = flow.get("pkts_toserver", 0), flow.get("pkts_toclient", 0)
        bts, btc = flow.get("bytes_toserver", 0), flow.get("bytes_toclient", 0)
        total_pkts, total_bytes = pts + ptc, bts + btc
        bytes_per_pkt = total_bytes / (total_pkts if total_pkts > 0 else 1)

        return pd.DataFrame([[pts, ptc, bts, btc, duration, total_pkts, total_bytes, bytes_per_pkt]],
                            columns=["pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
                                     "duration_seconds", "total_pkts", "total_bytes", "bytes_per_pkt"])

    def refresh_own_ip(self, detected_ip):
        """Automatic mode: follow the PC's current LAN IP. Returns True if it changed."""
        if not self.auto_own_ip or not detected_ip:
            return False
        if self.own.to_list() == [detected_ip]:
            return False
        self.own = IpMatcher([detected_ip])
        return True

    def capture_status(self, now=None, window=60):
        """Is Suricata delivering traffic that involves this PC? (a hint for the dashboard banner)"""
        now = time.time() if now is None else now
        mine = ", ".join(self.own.to_list())
        if not self.own.addresses:
            return {"state": "unknown", "message": "No IP address is set for this PC, so the capture check is off."}
        if self.last_event is None or now - self.last_event > window:
            if self.last_event is None and now - self.started <= window:
                return {"state": "starting", "message": "Waiting for the first events from Suricata..."}
            return {"state": "idle", "message": "No new events from Suricata in the last minute. "
                    "Is Suricata running? (The network may also just be quiet.)"}
        if self.last_own_seen is not None and now - self.last_own_seen <= window:
            return {"state": "ok", "message": f"Capturing: traffic for {mine} is arriving."}
        return {"state": "other_traffic", "message": f"Suricata is delivering events, but none involve this PC ({mine}). "
                "It may be listening on another network. Restart it with scripts\\start_suricata.ps1, "
                "which picks the active network by itself."}

    # ---------- the three layers ----------
    def _rule_alert(self, event, now):
        if self.is_ignored(event.get("src_ip")):
            return []
        alert = event.get("alert", {})
        key = (event.get("src_ip"), event.get("dest_ip"), alert.get("signature_id"))
        last = self._recent_rule_alerts.get(key)
        if last is not None and now - last < self.dedup_seconds:
            return []
        self._recent_rule_alerts[key] = now
        if len(self._recent_rule_alerts) > 5000:      # keep the cache small
            self._recent_rule_alerts = {k: t for k, t in self._recent_rule_alerts.items()
                                        if now - t < self.dedup_seconds}
        return [{
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "proto": event.get("proto", "Unknown"),
            "source": "Rule",
            "detail": alert.get("signature", "Suricata rule alert"),
            "severity": SEVERITY_LABEL.get(alert.get("severity"), "-"),
            "score": None,
        }]

    def _stats_alert(self, event, now):
        if self.is_ignored(event.get("src_ip")):
            return []
        out = []
        for a in self.stats.add(event.get("src_ip"), event.get("dest_ip"), event.get("dest_port"), now=now,
                                   proto=event.get("proto")):
            out.append({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": a.get("dest_ip") or event.get("dest_ip"),
                "proto": a.get("proto") or event.get("proto", "Unknown"),
                "source": "Stats",
                "detail": a["detail"],
                "severity": a["severity"],
                "score": None,
            })
        return out

    def _ml_alert(self, event, now=None):
        if not self.ml_enabled:
            return []
        now = time.time() if now is None else now
        flow = event.get("flow", {})

        if self.design2:
            # The supplied Random Forest was trained on source-level rolling aggregates,
            # not the eight individual-flow features used by Design 1.
            src = event.get("src_ip")
            if not src:
                return []
            pts = float(flow.get("pkts_toserver", 0) or 0)
            ptc = float(flow.get("pkts_toclient", 0) or 0)
            bts = float(flow.get("bytes_toserver", 0) or 0)
            btc = float(flow.get("bytes_toclient", 0) or 0)
            port = event.get("dest_port")
            try:
                port = int(port) if port is not None else None
            except (TypeError, ValueError):
                port = None
            row = {"time": now, "port": port, "pkts": pts + ptc,
                   "bytes": bts + btc, "rst": 1.0 if str(flow.get("state", "")).upper().startswith("R") else 0.0}
            rows = self._rf_flows[src]
            rows.append(row)
            cutoff = now - self.rf_window_seconds
            while rows and rows[0]["time"] < cutoff:
                rows.popleft()
            if len(rows) < 2:
                return []
            ports = {r["port"] for r in rows if r["port"] is not None}
            features = {
                "conn_count": float(len(rows)),
                "distinct_ports": float(len(ports)),
                "rst_ratio": sum(r["rst"] for r in rows) / len(rows),
                "avg_pkts": sum(r["pkts"] for r in rows) / len(rows),
                "total_bytes": float(sum(r["bytes"] for r in rows)),
            }
            try:
                x = pd.DataFrame([[features.get(name, 0.0) for name in self.rf_features]], columns=self.rf_features)
                prediction = int(self.model.predict(x)[0])
                if prediction != 1:
                    return []
                last = self._rf_last_alert.get(src)
                if last is not None and now - last < self.dedup_seconds:
                    return []
                self._rf_last_alert[src] = now
                return [{
                    "timestamp": event.get("timestamp"), "src_ip": src,
                    "dest_ip": event.get("dest_ip"), "proto": event.get("proto", "Unknown"),
                    "source": "ML", "detail": "Random Forest: suspicious source traffic window",
                    "severity": "-", "score": None,
                }]
            except Exception as e:
                self.model = None
                self.ml_error = f"{type(e).__name__}: {e}"
                return []

        if flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0) < self.min_pkts:
            return []
        try:
            x = self.scaler.transform(self._features(flow))
            if self.model.predict(x)[0] != -1:
                return []
            score = float(self.model.decision_function(x)[0])
        except Exception as e:
            self.model = None
            self.ml_error = f"{type(e).__name__}: {e}"
            return []
        return [{
            "timestamp": event.get("timestamp"), "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"), "proto": event.get("proto", "Unknown"),
            "source": "ML", "detail": "Isolation Forest: abnormal flow volume/size",
            "severity": "-", "score": round(score, 4),
        }]

    def process(self, event, now=None):
        """Return a list of alert dicts for one eve.json event."""
        now = time.time() if now is None else now
        self.last_event = now
        if self.own.addresses and (self.own.matches(event.get("src_ip")) or self.own.matches(event.get("dest_ip"))):
            self.last_own_seen = now
        etype = event.get("event_type")
        if etype == "alert":
            return self._rule_alert(event, now)
        if etype == "flow":
            # Stats first and on EVERY flow: scans are made of tiny flows that the ML filter would drop.
            return self._stats_alert(event, now) + self._ml_alert(event, now)
        return []

