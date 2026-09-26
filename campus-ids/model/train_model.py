"""
train_model.py
------------------------
Reads the flow features CSV, trains an Isolation Forest anomaly detection model,
and exports the trained model and scaler.

Fix (2026-09-26): the --contamination CLI argument was previously ignored;
the IsolationForest call had contamination hardcoded to 0.01. It now uses
the value the user actually passes in (default 0.05, matching the CLI default).
"""

import argparse
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

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

def load_features(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Input dataset is missing the following feature column(s): {missing}")
    return df

def train(df: pd.DataFrame, contamination: float = 0.05):
    X = df[FEATURE_COLUMNS].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,   # <-- was hardcoded to 0.01, now uses the real argument
        random_state=42,
    )
    model.fit(X_scaled)
    return model, scaler, X_scaled

def main():
    parser = argparse.ArgumentParser(description="Train an Isolation Forest anomaly detection model")
    parser.add_argument("--input", required=True, help="Path to the input features CSV file")
    parser.add_argument("--model_out", default="ids_model.joblib", help="Output path for the trained model")
    parser.add_argument("--scaler_out", default="ids_scaler.joblib", help="Output path for the fitted scaler")
    parser.add_argument("--contamination", type=float, default=0.05, help="Estimated anomaly contamination rate")
    args = parser.parse_args()

    df = load_features(args.input)
    model, scaler, X_scaled = train(df, contamination=args.contamination)
    joblib.dump(model, args.model_out)
    joblib.dump(scaler, args.scaler_out)
    print(f"[Done] Model saved to {args.model_out}")
    print(f"[Done] Scaler saved to {args.scaler_out}")

    # Quick sanity check: how many of the TRAINING rows itself would be flagged?
    # If this is already very high (much above ~contamination), the training
    # data itself is too noisy / not representative of "normal" traffic.
    preds = model.predict(X_scaled)
    flagged = (preds == -1).sum()
    print(f"[Info] {flagged}/{len(preds)} training rows flagged as anomalies "
          f"({flagged/len(preds):.1%}). Should be close to your --contamination value "
          f"({args.contamination:.1%}). If it's far higher, your baseline data "
          f"has too much variance to be treated as one 'normal' cluster.")

if __name__ == "__main__":
    main()
