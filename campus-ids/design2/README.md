# Design 2 — Random Forest layer

Design 2 = Design 1 (Rule + Stats + Isolation Forest) **plus** a supervised Random Forest layer (purple "RF" alerts).

- Input: recent flows of one source IP (10 s window).
- Features: `conn_count`, `distinct_ports`, `rst_ratio`, `avg_pkts`, `total_bytes`.
- Model: `model/rf_model.joblib` (class 1 = attack window).
- Alert detail shows flows, ports and reset ratio; the score column is the RF probability.

Run: `python dashboard/app.py --design2`

Training scripts, labels (`aggregate.py`, `train_rf.py`, `labels*.csv`) and results (`evaluation/results_rf.txt`, `evaluation/results_comparison.csv`) belong here and in `evaluation/`.
