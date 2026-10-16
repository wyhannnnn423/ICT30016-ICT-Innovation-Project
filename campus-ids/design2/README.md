# Design 2 — Random Forest

Design 2 is the supervised machine-learning option. It uses the same Suricata Rule layer,
sliding-window Stats layer and Flask dashboard as Design 1, but replaces the Isolation
Forest flow detector with a Random Forest classifier.

The included `model/rf_model.joblib` is a dictionary containing a trained classifier and
its expected feature list: `conn_count`, `distinct_ports`, `rst_ratio`, `avg_pkts`,
and `total_bytes`. The live detector aggregates flow events per source IP over a rolling
window before asking the classifier to predict. A class label of `1` is treated as an
attack/anomalous window; this interpretation should be confirmed against the training
script and evaluation labels before reporting performance.

## Run
From the repository root:
```powershell
python dashboard/app.py --design2
```

## Model notes
- `model/rf_model.joblib` is the active Random Forest artifact.
- `model/rf_model_nobytes.joblib` and `model/rf_model_original.joblib` are retained as
  historical variants and are not loaded by the dashboard.
- Re-train/re-evaluate the model before making quantitative claims about detection rate
  or false-positive rate.
