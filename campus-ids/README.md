# Campus IDS — ICT30016 ICT Innovation Project

A lightweight, lab-tested Intrusion Detection System (IDS) prototype for campus-network scenarios. Suricata supplies traffic events, a shared sliding-window statistics detector identifies scans/floods, and a Flask-SocketIO dashboard presents alerts in real time. Two alternative ML designs can be selected at launch.

> **Scope and safety:** The project is evaluated in a controlled lab using a Kali VM and/or supplied datasets. It is not claimed to be validated on a live campus network. Model metrics should only be reported alongside the dataset and test method used.

## Dashboard

![Campus IDS Real-Time Alerts Dashboard](assets/dashboard.jpg)

Start the app and open **http://127.0.0.1:5000**.

- Status bar for capture state, ignored IPs and current thresholds.
- Alert charts, source summaries, filtering and CSV export.
- Settings for the monitored PC, trusted IPs, scan/flood thresholds, time window and cooldown.
- Live alerts from the shared Rule and Stats layers and the selected ML design.

![Campus IDS Settings Panel](assets/settings.jpg)

## System Designs Overview

Both designs share the **Suricata Rule Layer**, **Sliding-Window Stats Layer**, and **Flask Dashboard**. They differ in the ML layer and its input representation.

| Feature | Design 1 — Default | Design 2 — `--design2` |
|---|---|---|
| ML algorithm | Isolation Forest (unsupervised) | Random Forest (supervised) |
| Input | Individual completed flow features | Rolling source-IP traffic aggregates |
| Model artifacts | `design1/model/ids_model.joblib` and `ids_scaler.joblib` | `design2/model/rf_model.joblib` |
| Intended use | Flag unusual flows without attack labels | Classify known traffic patterns learned from labelled data |
| Launch command | `python dashboard/app.py` | `python dashboard/app.py --design2` |
| Details | [`design1/README.md`](design1/README.md) | [`design2/README.md`](design2/README.md) |

Design 1 scales eight per-flow features and flags flows predicted as outliers by Isolation Forest. Design 2 loads a saved Random Forest classifier and derives the five features expected by that model (`conn_count`, `distinct_ports`, `rst_ratio`, `avg_pkts`, `total_bytes`) from recent flow events grouped by source IP. Design 2 is an alternative ML approach, not “Version 2” of the whole application.

## Shared Detection Layers

| Layer | What it detects | Implementation |
|---|---|---|
| Rule | Patterns matching configured signatures | `suricata/rules/campus-ids.rules` and Suricata alerts |
| Stats | Port scans and connection floods within a sliding window | `dashboard/stats_detector.py` |
| ML | Design-specific flow anomaly/classification | `dashboard/detection.py` and selected model artifact |

The Stats layer defaults to 15 different destination ports for a scan and 150 connections for a flood within a 10-second window. These are starting thresholds, not universal definitions of attacks.

## Results and Limitations

The repository includes CIC-IDS2017 evaluation outputs under `evaluation/`. Treat those figures as the recorded results of the specific evaluation run, not as guaranteed performance of both designs. The existing CIC-IDS evaluation script evaluates Design 1's Isolation Forest model; it does not establish Design 2's accuracy.

Preliminary lab notes recorded Rule/Stats alerts for ping, an nmap SYN scan, and an hping3 SYN flood. Results depend on the test setup, Suricata rules, traffic capture interface and thresholds.

Known limitations:
- The ML designs use different feature representations and should not be compared by headline accuracy alone without a common labelled test set.
- The Random Forest's training pipeline and feature-label semantics must be verified before reporting formal detection metrics.
- A single flow may not contain enough context to identify a scan or flood; this is why the shared Stats layer is included.
- Alerts are currently held in the running dashboard and are not persisted as a database history.
- This prototype has not been validated on a live campus network.

## Team Members

- **Jane Yan Zhen YU** (Team Leader)
- **Yan Han WONG**
- **Neville Zi Yang**
- **Bruce Gee Yick WONG**

## Architecture

```text
Network traffic -> Suricata -> eve.json -> Flask-SocketIO dashboard
                                      |-> Rule layer (Suricata signatures)
                                      |-> Stats layer (rolling scan/flood counters)
                                      |-> Design 1: Isolation Forest per-flow anomaly detection
                                      '-- Design 2: Random Forest on rolling source-IP aggregates
```

## Prerequisites

- Python 3.10+ recommended (use the version compatible with the installed scikit-learn/joblib model artifacts).
- Suricata on Windows and Npcap in WinPcap API-compatible mode, if following the Windows lab setup.
- Suricata `eve-log` configured to emit `flow` and `alert` events, with `suricata/rules/campus-ids.rules` loaded.
- Optional Kali Linux VM for controlled lab tests.

## Installation

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If a saved model reports a scikit-learn version warning/error, install the compatible version used to create that artifact or retrain it with the current environment. Do not assume that a model file is portable across arbitrary scikit-learn versions.

## Run the System

### 1. Configure Suricata (first time only)

Copy `suricata/rules/campus-ids.rules` to the Suricata rules directory, add it under `rule-files:` in `suricata.yaml`, then test the configuration from an Administrator PowerShell:

```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -T -c suricata.yaml
```

### 2. Start Suricata

From an Administrator PowerShell at the repository root:

```powershell
.\scripts\start_suricata.ps1
```

The default Windows EVE log path is `C:\Program Files\Suricata\log\eve.json`.

### 3. Optional: refresh baseline features and train Design 1

```powershell
python suricata/read_suricata_flows.py --input "C:\Program Files\Suricata\log\eve.json" --output data/suricata_flow_features.csv
python design1/model/train_model.py --input data/suricata_flow_features.csv --model_out design1/model/ids_model.joblib --scaler_out design1/model/ids_scaler.joblib
```

Only use representative normal baseline traffic to train the unsupervised Design 1 model. Do not train on an attack capture if the goal is to model normal behaviour.

### 4. Launch either design

Design 1 (default):

```powershell
python dashboard/app.py
```

Design 2 (Random Forest):

```powershell
python dashboard/app.py --design2
```

Optional arguments include `--eve <path>` to select an EVE log, `--own-ip <IP>` to override automatic local-IP detection, `--host 0.0.0.0` to allow other devices to view the dashboard, and `--port 5000` to change the port. Use `--model <path>` to override the selected design's model path; `--scaler <path>` applies to Design 1.

### 5. Controlled lab test examples

Run from the Kali VM only against a lab target you own or are authorised to test:

```bash
ping -c 4 <TARGET_IP>
sudo nmap -sS -p 1-1000 <TARGET_IP>
sudo hping3 -S -p 80 -i u10000 -c 500 <TARGET_IP>
```

### 6. Evaluate Design 1 on CIC-IDS2017

```powershell
python evaluation/evaluate_cicids.py --input evaluation/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv evaluation/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --model design1/model/ids_model.joblib --scaler design1/model/ids_scaler.joblib --out evaluation/cicids_evaluation.csv
```

This command is for Design 1 only. It does not evaluate the Random Forest model.

## Settings Reference

| Setting | Meaning | Default |
|---|---|---|
| This PC's IP | Rule/Stats alerts sourced from this PC are hidden | Auto-detected |
| Trusted IPs or ranges | Additional source addresses excluded from Rule/Stats alerts | None |
| Port scan threshold | Distinct destination ports in the time window | 15 |
| Flood threshold | Connections from one source in the time window | 150 |
| Time window | Stats look-back period | 10 seconds |
| Cooldown | Minimum time before repeating a Stats alert | 30 seconds |

Settings are saved to `data/settings.json` and apply to new traffic.

## Tests

```powershell
python tests/test_settings.py
```

These tests cover settings validation, IP matching, live setting changes, automatic IP handling, capture status and the settings API. They do not prove ML accuracy.

## Project Structure

```text
campus-ids/
├── dashboard/                 Shared Flask dashboard and detection logic
├── suricata/                  Suricata rules and flow feature extraction
├── design1/                   Design 1: Isolation Forest
│   ├── model/                 Model, scaler, training script and benchmark artifacts
│   └── evaluation/            Reserved for Design 1-specific evaluation artifacts
├── design2/                   Design 2: Random Forest
│   └── model/                 Active model and retained historical variants
├── evaluation/                Shared benchmark datasets, evaluation scripts and results
├── data/                      Captured flow features and settings
├── scripts/                   Suricata startup and lab simulation scripts
├── docs/                      Setup and settings documentation
├── tests/                     Automated settings tests
└── assets/                    Dashboard screenshots
```

## Shutdown

1. Stop the dashboard with `Ctrl+C` in its terminal.
2. Stop Suricata with `Ctrl+C` in the Administrator terminal and wait for it to shut down.

## Troubleshooting

- **Permission denied:** run Suricata commands from an Administrator terminal.
- **No alerts:** confirm Suricata is running, `eve.json` is updating, and Kali is connected to the correct lab network.
- **Capture banner says no events involve this PC:** Suricata may be listening on another interface; restart it using `scripts/start_suricata.ps1`.
- **ML disabled:** check that the selected model exists and that scikit-learn/joblib versions are compatible. Rule and Stats layers can still operate if ML loading fails.
- **Settings cannot be saved:** make changes from a browser on the machine running the dashboard.
