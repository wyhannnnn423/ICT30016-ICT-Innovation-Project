"""
train_model.py
------------------------
Reads the flow features CSV, trains an Isolation Forest anomaly detection model, 
and exports the trained model and scaler.
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
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X_scaled)
    return model, scaler

def main():
    parser = argparse.ArgumentParser(description="Train an Isolation Forest anomaly detection model")
    parser.add_argument("--input", required=True, help="Path to the input features CSV file")
    parser.add_argument("--model_out", default="ids_model.joblib", help="Output path for the trained model")
    parser.add_argument("--scaler_out", default="ids_scaler.joblib", help="Output path for the fitted scaler")
    parser.add_argument("--contamination", type=float, default=0.05, help="Estimated anomaly contamination rate")
    args = parser.parse_args()
    
    df = load_features(args.input)
    model, scaler = train(df, contamination=args.contamination)
    joblib.dump(model, args.model_out)
    joblib.dump(scaler, args.scaler_out)
    print(f"[Done] Model saved to {args.model_out}")
    print(f"[Done] Scaler saved to {args.scaler_out}")

if __name__ == "__main__":
    main()