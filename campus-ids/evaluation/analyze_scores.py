"""
analyze_scores.py
------------------------
Diagnostic tool for the Campus IDS Isolation Forest model.

Problem this addresses: model.predict() only gives a hard -1/1 call based on
whatever threshold was implied by --contamination at training time. If the
LIVE traffic your dashboard sees has a different distribution than the data
you trained on, almost everything can end up flagged as -1 (this is what's
happening right now: normal Google/GitHub/Teams traffic is being flagged).

This script lets you:
  1. See the actual distribution of decision_function() scores on a dataset
     (training data, or a fresh batch of captured "should be normal" traffic).
  2. Pick a threshold based on a percentile of THAT data, rather than trusting
     the training-time contamination setting blindly.

Usage:
    python analyze_scores.py --input data/suricata_flow_features.csv \
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

def main():
    parser = argparse.ArgumentParser(description="Inspect Isolation Forest anomaly score distribution")
    parser.add_argument("--input", required=True, help="CSV of flow features to score")
    parser.add_argument("--model", required=True, help="Path to trained model (.joblib)")
    parser.add_argument("--scaler", required=True, help="Path to fitted scaler (.joblib)")
    parser.add_argument("--percentile", type=float, default=1.0,
                         help="Flag the bottom X%% of scores as anomalies (default: 1.0)")
    parser.add_argument("--plot", action="store_true", help="Show a histogram (requires matplotlib)")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Input dataset is missing feature column(s): {missing}")

    model = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    X = df[FEATURE_COLUMNS].fillna(0)
    X_scaled = scaler.transform(X)

    scores = model.decision_function(X_scaled)   # higher = more normal
    preds = model.predict(X_scaled)               # -1 = anomaly under training-time threshold

    df_out = df.copy()
    df_out["anomaly_score"] = scores
    df_out["flagged_by_model"] = preds == -1

    print("=== Score distribution ===")
    print(pd.Series(scores).describe())
    print()
    print(f"Flagged by original model threshold: {(preds == -1).sum()} / {len(preds)} "
          f"({(preds == -1).mean():.1%})")

    # Suggest a threshold based on a percentile of THIS data's own scores
    suggested_threshold = pd.Series(scores).quantile(args.percentile / 100.0)
    flagged_by_percentile = (scores <= suggested_threshold).sum()
    print()
    print(f"=== Percentile-based threshold suggestion ===")
    print(f"Bottom {args.percentile}% of scores in this file -> threshold = {suggested_threshold:.4f}")
    print(f"Rows that would be flagged at this threshold: {flagged_by_percentile} / {len(scores)}")
    print()
    print("If this file is meant to represent NORMAL traffic and the model's own")
    print("threshold flags far more than expected, use a threshold like the one")
    print("above (score <= threshold) in app.py instead of relying on predict().")

    if args.plot:
        import matplotlib.pyplot as plt
        plt.hist(scores, bins=50)
        plt.axvline(suggested_threshold, color="red", linestyle="--",
                    label=f"{args.percentile}th percentile")
        plt.xlabel("Anomaly score (higher = more normal)")
        plt.ylabel("Count")
        plt.title("Isolation Forest decision_function score distribution")
        plt.legend()
        plt.show()

    out_path = "scored_flows.csv"
    df_out.to_csv(out_path, index=False)
    print(f"\n[Saved] Full scored dataset written to {out_path}")

if __name__ == "__main__":
    main()
