# Design 1 — Isolation Forest

Design 1 is the unsupervised machine-learning option for Campus IDS. It uses the shared
Suricata Rule layer and sliding-window Stats layer, plus an Isolation Forest model that
flags unusual individual flows without requiring attack labels.

## Files
- `model/train_model.py` — train the model from baseline flow features.
- `model/ids_model.joblib` — trained Isolation Forest model.
- `model/ids_scaler.joblib` — feature scaler used by the model.
- `model/cicids_benchmark_*` — separate benchmark artifacts; not used by the live dashboard.

## Train (from the repository root)
```powershell
python suricata/read_suricata_flows.py --input "C:\Program Files\Suricata\log\eve.json" --output data/suricata_flow_features.csv
python design1/model/train_model.py --input data/suricata_flow_features.csv --model_out design1/model/ids_model.joblib --scaler_out design1/model/ids_scaler.joblib
```

## Run
```powershell
python dashboard/app.py
```

Design 1's ML layer evaluates each completed flow after the minimum-packet filter.
