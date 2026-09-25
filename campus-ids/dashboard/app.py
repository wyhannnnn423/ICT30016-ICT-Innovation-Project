"""
app.py
------------------------
Flask Real-Time Dashboard: Reads anomaly detection results from CSV,
displaying the traffic flow list and flagged anomaly alerts on a web page.

Future Extensions:
    - Implement true real-time push updates via Flask-SocketIO (currently re-reads the CSV on page refresh)
    - Integrate a database to replace CSV files and support historical queries

Usage:
    python app.py
    Then open http://127.0.0.1:5000 in your browser
"""

import eventlet
# Monkey patch must be called before importing other libraries for SocketIO threading
eventlet.monkey_patch()

import json
import os
import pandas as pd
import joblib
from flask import Flask, render_template
from flask_socketio import SocketIO

# 1. Configuration (Use 'r' prefix to fix the SyntaxWarning for \P)
MODEL_PATH = "../model/ids_model.joblib"
SCALER_PATH = "../model/ids_scaler.joblib"
EVE_JSON_PATH = r"C:\Program Files\Suricata\log\eve.json"

print("[*] Loading AI Model and Scaler...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

app = Flask(__name__)
# Enable eventlet async mode for high-performance real-time streaming
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

def calculate_features(flow):
    """
    Replicates the logic from read_suricata_flows.py dynamically in memory.
    """
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

    # Must exactly match the FEATURE_COLUMNS order from train_model.py
    return pd.DataFrame([[
        pkts_toserver, pkts_toclient, bytes_toserver, bytes_toclient,
        duration_sec, total_pkts, total_bytes, bytes_per_pkt
    ]], columns=[
        "pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
        "duration_seconds", "total_pkts", "total_bytes", "bytes_per_pkt"
    ])

def tail_and_detect():
    """
    Background engine: Tails the log file, runs AI inference, and emits alerts.
    """
    if not os.path.exists(EVE_JSON_PATH):
        print(f"[!] Error: Cannot find {EVE_JSON_PATH}")
        return

    with open(EVE_JSON_PATH, "r", encoding="utf-8") as f:
        # Jump to the end of the file to only process new live traffic
        f.seek(0, os.SEEK_END)
        print("[*] Background AI detection engine started. Monitoring traffic...")

        while True:
            line = f.readline()
            if not line:
                # Crucial: Use socketio.sleep instead of time.sleep to avoid blocking the web server
                socketio.sleep(0.1)
                continue

            try:
                event = json.loads(line.strip())
                if event.get("event_type") == "flow":
                    flow_data = event.get("flow", {})
                    
                    # Step A: Extract live features
                    features_df = calculate_features(flow_data)
                    
                    # Step B: AI Prediction
                    features_scaled = scaler.transform(features_df)
                    prediction = model.predict(features_scaled)[0]
                    
                    # Step C: Alert Trigger (-1 indicates an anomaly in Isolation Forest)
                    if prediction == -1:
                        anomaly_score = float(model.decision_function(features_scaled)[0])
                        
                        alert_payload = {
                            "timestamp": event.get("timestamp"),
                            "src_ip": event.get("src_ip"),
                            "dest_ip": event.get("dest_ip"),
                            "proto": event.get("proto", "Unknown"),
                            "score": round(anomaly_score, 4)
                        }
                        
                        print(f"[ALERT] Threat Detected! {alert_payload['src_ip']} -> {alert_payload['dest_ip']} (Score: {alert_payload['score']})")
                        
                        # Push the JSON payload to the browser instantly via WebSocket
                        socketio.emit('new_alert', alert_payload)

            except json.JSONDecodeError:
                pass # Ignore incomplete JSON lines written mid-flush by Suricata
            except Exception as e:
                print(f"[!] Detection Engine Error: {e}")

@app.route('/')
def index():
    return render_template('dashboard.html')

if __name__ == '__main__':
    # Start the continuous monitoring loop as an asynchronous background task
    socketio.start_background_task(tail_and_detect)
    print("[*] Starting Campus IDS Dashboard on http://127.0.0.1:5000")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=False)