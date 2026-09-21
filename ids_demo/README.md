# ids_demo — Learning Prototypes (NOT the final system)

This folder is **not** the final Campus IDS system. It's a set of small,
standalone prototypes built while learning the core technologies
(Isolation Forest, live packet capture, real-time alert push), before
writing the real `capture_live.py` / `train_model.py` / dashboard.

This matches the "Integration of Learning Issues" section of our report —
these scripts are the "small-scale trials" and "basic prototype" mentioned
there.

## What's in here

| File | What it does | Which report goal it relates to |
|---|---|---|
| `isolation_forest_demo.py` | Loads the NSL-KDD static dataset, trains an Isolation Forest model, checks how well it guesses normal vs. attack | Goal 2 — first trial, no tuning |
| `isolation_forest_demo_v2.py` | Same idea, but adds feature scaling and tries a few different `contamination` values on a small sample first, before applying the best one to the full dataset | Goal 2 — parameter tuning practice |
| `capture_prototype.py` | Captures live network traffic and groups it into flows (by src IP, dst IP, ports, protocol), printing basic stats like packet count and average size | Goal 1 — flow-based capture, standalone test |
| `alert_dashboard_demo/app.py` + `templates/index.html` | A minimal Flask-SocketIO web page — click a button, an alert appears instantly with no page refresh | Goal 3 — real-time push, no ML connected yet |

None of these are wired together yet. Each one proves that a piece of the
puzzle works on its own — the real system still needs to connect them.

## How to run each one

**Isolation Forest demos** (need `NSL_KDD_Train.csv` in the same folder):
```
pip install pandas scikit-learn
python3 isolation_forest_demo.py
python3 isolation_forest_demo_v2.py
```

**Live capture prototype** (needs admin/root — it's reading real network
traffic):
```
pip install scapy
sudo python3 capture_prototype.py      # Mac/Linux
# On Windows, open terminal as Administrator instead
```

**Alert dashboard prototype**:
```
pip install flask flask-socketio
cd alert_dashboard_demo
python3 app.py
```
Then open `http://127.0.0.1:5000` in a browser and click "Send Test Alert".

## What's next

- Connect `capture_prototype.py`'s flow output into the actual feature
  extraction / model pipeline instead of just printing it
- Connect the Isolation Forest model's predictions into the dashboard's
  alert push, instead of the dashboard sending fake test alerts
- Replace these standalone scripts with the real `capture_live.py`,
  `feature_extraction.py`, `train_model.py`, `predict.py` once the team
  is ready to build the actual pipeline
