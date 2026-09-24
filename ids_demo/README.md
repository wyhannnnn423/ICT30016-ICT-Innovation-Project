# ids_demo — Learning Prototypes (NOT the final system)

This folder is **not** the final Campus IDS system. It's a set of small, standalone prototypes built while learning the core technologies (Isolation Forest, live packet capture, real-time alert push), before writing the real production pipeline driven by industrial network engines.

This matches the "Integration of Learning Issues" section of our report — these scripts represent the "small-scale trials" and "basic prototypes" designed to test technical feasibility and explore engineering bottlenecks.

## What's in here

| File | What it does | Which report goal it relates to |
|---|---|---|
| `isolation_forest_demo.py` | Loads the NSL-KDD static dataset, trains an Isolation Forest model, checks how well it guesses normal vs. attack | Goal 2 — first trial, no tuning |
| `isolation_forest_demo_v2.py` | Same idea, but adds feature scaling and tries a few different `contamination` values on a small sample first, before applying the best one to the full dataset | Goal 2 — parameter tuning practice |
| `capture_prototype.py` | **Early standalone prototype utilizing Scapy to capture live traffic and manually aggregate packets into flows. Testing this script revealed the heavy CPU limitations and packet-dropping rates of pure Python parsing under high throughput, validating our architectural decision to upgrade to a multi-threaded Suricata core for the final deployment.** | Goal 1 — Early exploratory prototyping and performance stress-test |
| `alert_dashboard_demo/app.py` + `templates/index.html` | A minimal Flask-SocketIO web page — click a button, an alert appears instantly with no page refresh | Goal 3 — real-time push, no ML connected yet |

None of these are wired together yet. Each one proves that a piece of the puzzle works on its own — the real production system integrates these concepts into a much more powerful, high-performance architecture.

## How to run each one

### Isolation Forest demos (need `NSL_KDD_Train.csv` in the same folder):
```bash
pip install pandas scikit-learn
python3 isolation_forest_demo.py
python3 isolation_forest_demo_v2.py
```

### Legacy live capture prototype (needs admin/root — it's reading real network traffic using Scapy):
```bash
pip install scapy
sudo python3 capture_prototype.py      # Mac/Linux
# On Windows, open terminal as Administrator instead
```

### Alert dashboard prototype:
```bash
pip install flask flask-socketio
cd alert_dashboard_demo
python3 app.py
```
Then open `http://127.0.0.1:5000` in a browser and click "Send Test Alert".

## What's next for the Final Production System

- **Transition Ingestion Layer to Suricata**: Abandon the high-overhead Python-layer packet capture (`capture_prototype.py`) and replace it with a production-ready ingestion engine that consumes live, multi-threaded `EVE JSON` telemetry streams from Suricata.
- **Connect Feature Pipeline with ML**: Stream Suricata's highly optimized flow metrics (such as `pkt_rate`, `total_bytes`, and `duration`) directly into the trained unsupervised Isolation Forest model for line-speed anomaly classification.
- **Live Anomaly Alerting**: Wire the real-time Isolation Forest prediction outputs into the Flask-SocketIO dashboard to push live, dynamic threat alerts (under 500ms latency) instead of simulated test buttons.
