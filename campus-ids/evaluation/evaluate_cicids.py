"""
evaluate_cicids.py
------------------------
Maps CIC-IDS2017 flow records onto the same 8 features used by
train_model.py / app.py (which come from Suricata's EVE JSON flow
records), then runs the trained Isolation Forest model against them.

This is for EVALUATION ONLY (per the project's spec report: CIC-IDS2017
is a reference benchmark, not the training baseline). It reports, per
label (BENIGN / DDoS / PortScan / etc.), how many flows the model
flags as anomalous -- i.e. false-positive rate on BENIGN, detection
rate on attacks.

Column mapping (CIC-IDS2017 -> project features):
    Total Fwd Packets             -> pkts_toserver
    Total Backward Packets        -> pkts_toclient
    Total Length of Fwd Packets   -> bytes_toserver
    Total Length of Bwd Packets   -> bytes_toclient
    Flow Duration (microseconds)  -> duration_seconds (divided by 1e6)
    (derived) total_pkts, total_bytes, bytes_per_pkt -- same formulas
    as read_suricata_flows.py / app.py

Caveat worth noting in your report: these are two different measurement
pipelines (CICFlowMeter vs Suricata's own flow accounting), so the
numbers are conceptually comparable but not identically computed --
this evaluation shows whether the trained model generalises reasonably,
not a like-for-like benchmark.

Usage:
    python evaluate_cicids.py \
        --input Friday-WorkingHours-Afternoon-DDos_pcap_ISCX.csv \
                Friday-WorkingHours-Afternoon-PortScan_pcap_ISCX.csv \
        --model model/ids_model.joblib --scaler model/ids_scaler.joblib
"""

import argparse
import pandas as pd
import joblib

FEATURE_COLUMNS = [
    "pkts_toserver",
    "pkts_toclient",
    "bytes_toserver",
    "bytes_toclient",
    "duration_seconds",
    "total_pkts",
    "total_bytes",
    "bytes_per_pkt"
]

CICIDS_TO_PROJECT = {
    "Total Fwd Packets": "pkts_toserver",
    "Total Backward Packets": "pkts_toclient",
    "Total Length of Fwd Packets": "bytes_toserver",
    "Total Length of Bwd Packets": "bytes_toclient",
}

def load_and_map(paths):
    frames = []
    for p in paths:
        df = pd.read_csv(p)
        df.columns = df.columns.str.strip()  # CIC-IDS2017 headers have stray leading spaces
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)

    missing = [c for c in list(CICIDS_TO_PROJECT.keys()) + ["Flow Duration", "Label"] if c not in df.columns]
    if missing:
        raise ValueError(f"Input file(s) missing expected column(s): {missing}")

    mapped = pd.DataFrame()
    for src, dst in CICIDS_TO_PROJECT.items():
        mapped[dst] = df[src]

    # Flow Duration is in microseconds in CIC-IDS2017; convert to seconds.
    # A small number of rows have a negative duration (a known quirk of
    # this dataset/CICFlowMeter) -- clip those to 0 rather than dropping them.
    mapped["duration_seconds"] = (df["Flow Duration"] / 1_000_000.0).clip(lower=0)

    mapped["total_pkts"] = mapped["pkts_toserver"] + mapped["pkts_toclient"]
    mapped["total_bytes"] = mapped["bytes_toserver"] + mapped["bytes_toclient"]
    mapped["bytes_per_pkt"] = mapped["total_bytes"] / mapped["total_pkts"].replace(0, 1)

    mapped["label"] = df["Label"]
    return mapped

def main():
    parser = argparse.ArgumentParser(description="Evaluate the trained IDS model against mapped CIC-IDS2017 flows")
    parser.add_argument("--input", required=True, nargs="+", help="One or more CIC-IDS2017 CSV files")
    parser.add_argument("--model", required=True, help="Path to trained model (.joblib)")
    parser.add_argument("--scaler", required=True, help="Path to fitted scaler (.joblib)")
    parser.add_argument("--out", default="cicids_evaluation.csv", help="Where to save the row-level scored output")
    args = parser.parse_args()

    mapped = load_and_map(args.input)

    model = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    X = mapped[FEATURE_COLUMNS].fillna(0)
    X_scaled = scaler.transform(X)

    mapped["anomaly_score"] = model.decision_function(X_scaled)
    mapped["flagged"] = model.predict(X_scaled) == -1

    print("=== Detection breakdown by label ===")
    summary = mapped.groupby("label")["flagged"].agg(["count", "sum", "mean"])
    summary.columns = ["total_flows", "flagged_as_anomaly", "flagged_rate"]
    summary["flagged_rate"] = (summary["flagged_rate"] * 100).round(1).astype(str) + "%"
    print(summary)
    print()
    print("Read this as: for BENIGN, 'flagged_rate' is your false-positive rate on CIC-IDS2017's")
    print("normal traffic. For DDoS/PortScan, it's your detection rate on those attacks.")

    mapped.to_csv(args.out, index=False)
    print(f"\n[Saved] Row-level scored output written to {args.out}")

if __name__ == "__main__":
    main()