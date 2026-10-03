"""
app.py
------------------------
Flask Real-Time Dashboard Backend (hybrid detection).

Tails Suricata's eve.json and pushes three kinds of alerts to the dashboard:
  1. "Rule"  : Suricata signature alerts (event_type == "alert")
  2. "ML"    : Isolation Forest anomalies on completed flows (event_type == "flow")
  3. "Stats" : per-source-IP port-scan / connection-flood detection (event_type == "flow")
"""

import eventlet
eventlet.monkey_patch()

import json
import os
import time
import pandas as pd
import joblib
from flask import Flask, render_template
from flask_socketio import SocketIO
from stats_detector import ScanFloodDetector

MODEL_PATH = "../model/ids_model.joblib"
SCALER_PATH = "../model/ids_scaler.joblib"
EVE_JSON_PATH = r"C:\Program Files\Suricata\log\eve.json"
MIN_PKTS = 15            # must match the filter in read_suricata_flows.py (training)
DEDUP_SECONDS = 5        # same src/dest/signature within this window = one alert

# Statistical detector thresholds (tune these during testing)
STATS_WINDOW_SEC = 10     # look-back window per source IP
SCAN_PORTS = 15           # distinct ports on ONE host inside the window -> port scan
FLOOD_FLOWS = 150         # connections from one source inside the window -> flood
STATS_COOLDOWN_SEC = 30   # do not repeat the same alert for the same source sooner than this

# IPs of the machine running Suricata + this dashboard. Its own outgoing traffic
# (browsing, updates) is not an attack on itself, so Rule/Stats alerts from these
# source IPs are skipped. Add your own LAN IP here.
OWN_IPS = {"192.168.50.190"}

SEVERITY_LABEL = {1: "High", 2: "Medium", 3: "Low"}

print("[*] Loading AI Model and Scaler...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

_recent_rule_alerts = {}   # (src, dest, signature_id) -> last time emitted
stats_detector = ScanFloodDetector(
    window=STATS_WINDOW_SEC, scan_ports=SCAN_PORTS,
    flood_flows=FLOOD_FLOWS, cooldown=STATS_COOLDOWN_SEC)


def calculate_features(flow):
    start_ts = pd.to_datetime(flow.get("start"), errors="coerce")
    end_ts = pd.to_datetime(flow.get("end"), errors="coerce")

    if pd.notnull(start_ts) and pd.notnull(end_ts):
        duration_sec = (end_ts - start_ts).total_seconds()
    else:
        duration_sec = 0.0

    pkts_toserver = flow.get("pkts_toserver", 0)
    pkts_toclient = flow.get("pkts_toclient", 0)
    bytes_toserver = flow.get("bytes_toserver", 0)
    bytes_toclient = flow.get("bytes_toclient", 0)

    total_pkts = pkts_toserver + pkts_toclient
    total_bytes = bytes_toserver + bytes_toclient
    bytes_per_pkt = total_bytes / (total_pkts if total_pkts > 0 else 1)

    return pd.DataFrame([[
        pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient,
        duration_sec, total_pkts, total_bytes, bytes_per_pkt
    ]], columns=[
        "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
        "duration_seconds", "total_pkts", "total_bytes", "bytes_per_pkt"
    ])


def handle_rule_alert(event):
    """Suricata signature alert -> dashboard payload (with simple de-duplication)."""
    if event.get("src_ip") in OWN_IPS:
        return
    alert = event.get("alert", {})
    key = (event.get("src_ip"), event.get("dest_ip"), alert.get("signature_id"))
    now = time.time()

    last = _recent_rule_alerts.get(key)
    if last is not None and now - last < DEDUP_SECONDS:
        return
    _recent_rule_alerts[key] = now

    # keep the cache small
    if len(_recent_rule_alerts) > 5000:
        cutoff = now - DEDUP_SECONDS
        for k in [k for k, t in _recent_rule_alerts.items() if t < cutoff]:
            del _recent_rule_alerts[k]

    payload = {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dest_ip": event.get("dest_ip"),
        "proto": event.get("proto", "Unknown"),
        "source": "Rule",
        "detail": alert.get("signature", "Suricata rule alert"),
        "severity": SEVERITY_LABEL.get(alert.get("severity"), "-"),
        "score": None,
    }
    print(f"[RULE ] {payload['src_ip']} -> {payload['dest_ip']} | {payload['detail']}")
    socketio.emit('new_alert', payload)


def handle_stats(event):
    """Every flow (including tiny ones) -> per-source-IP scan/flood detector."""
    if event.get("src_ip") in OWN_IPS:
        return
    for a in stats_detector.add(event.get("src_ip"), event.get("dest_ip"), event.get("dest_port")):
        payload = {
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "proto": event.get("proto", "Unknown"),
            "source": "Stats",
            "detail": a["detail"],
            "severity": a["severity"],
            "score": None,
        }
        print(f"[STATS] {payload['src_ip']} -> {payload['dest_ip']} | {payload['detail']}")
        socketio.emit('new_alert', payload)


def handle_flow(event):
    """Completed flow -> Isolation Forest -> dashboard payload if anomalous."""
    flow_data = event.get("flow", {})
    if flow_data.get("pkts_toserver", 0) + flow_data.get("pkts_toclient", 0) < MIN_PKTS:
        return

    features_df = calculate_features(flow_data)
    features_scaled = scaler.transform(features_df)
    prediction = model.predict(features_scaled)[0]

    if prediction == -1:
        anomaly_score = float(model.decision_function(features_scaled)[0])
        payload = {
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "proto": event.get("proto", "Unknown"),
            "source": "ML",
            "detail": "Isolation Forest: abnormal flow volume/size",
            "severity": "-",
            "score": round(anomaly_score, 4),
        }
        print(f"[ML   ] {payload['src_ip']} -> {payload['dest_ip']} (Score: {payload['score']})")
        socketio.emit('new_alert', payload)


def tail_and_detect():
    if not os.path.exists(EVE_JSON_PATH):
        print(f"[!] Error: Cannot find {EVE_JSON_PATH}")
        return

    with open(EVE_JSON_PATH, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        print("[*] Background detection engine started (rules + ML + stats). Monitoring traffic...")

        while True:
            line = f.readline()
            if not line:
                socketio.sleep(0.1)
                continue

            try:
                event = json.loads(line.strip())
                event_type = event.get("event_type")
                if event_type == "alert":
                    handle_rule_alert(event)
                elif event_type == "flow":
                    handle_stats(event)   # must run BEFORE the MIN_PKTS filter: scans are tiny flows
                    handle_flow(event)

            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[!] Detection Engine Error: {e}")


@app.route('/')
def index():
    return render_template('dashboard.html')


if __name__ == '__main__':
    socketio.start_background_task(tail_and_detect)
    print("[*] Starting Campus IDS Dashboard on http://127.0.0.1:5000")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=False)
