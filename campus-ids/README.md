# Campus IDS

ICT30016 (ICT Innovation Project) — Campus Network Intrusion Detection System.

A lightweight, AI-driven Intrusion Detection System designed for campus networks: captures network traffic, aggregates features based on IPv4 flows, performs unsupervised anomaly detection using Isolation Forest, and displays alerts in real time through a Flask dashboard.

## Team

- Jane Yan Zhen YU (Team Lead)
- Yan Han WONG (Han)
- Neville
- Bruce Gee Yick WONG

## Project Structure

campus-ids/
├── suricata/           # Parses Suricata logs and extracts flow features
│   └── read_suricata_flows.py
├── model/              # Anomaly detection model training and inference
│   ├── train_model.py
│   └── predict.py
├── data/               # Flow features / detection results CSV (ignored by git, see .gitignore)
└── dashboard/          # Flask real-time dashboard
├── app.py
└── templates/
└── dashboard.html

## Workflow

1. **Extract Flow Features** (Requires Suricata configured with `eve-log` flow output enabled)
   ```bash
   python suricata/read_suricata_flows.py --input /var/log/suricata/eve.json --output data/suricata_flow_features.csv
Train Model

Bash
python model/train_model.py --input data/suricata_flow_features.csv --model_out model/ids_model.joblib
Detect Anomalies

Bash
python model/predict.py --input data/suricata_flow_features.csv \
                        --model model/ids_model.joblib \
                        --scaler model/ids_scaler.joblib \
                        --output data/flagged_anomalies.csv
Launch Dashboard

Bash
cd dashboard
python app.py
Open http://127.0.0.1:5000 in your browser.

Installation
Bash
pip install -r requirements.txt
Git Workflow
The main branch is reserved for stable releases.

Feature branches (e.g., feature/suricata-parser) should be used for ongoing development.

Merges must pass a Pull Request code review before integration.

Notes
This repository serves as the official production codebase. Prototype and demo implementations are maintained separately in the ids_demo repository.
