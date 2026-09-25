"""
predict.py
------------------------
Loads the trained Isolation Forest model and Scaler,
performs anomaly detection on new traffic feature data, and outputs flagged results.

Usage:
    python predict.py --input ../data/suricata_flow_features.csv \
                      --model ids_model.joblib \
                      --scaler ids_scaler.joblib \
                      --output ../data/flagged_anomalies.csv
"""

import argparse
import pandas as pd
import joblib

from train_model import FEATURE_COLUMNS


def predict(df: pd.DataFrame, model, scaler) -> pd.DataFrame:
    df = df.copy()
    X = df[FEATURE_COLUMNS].fillna(0)
    X_scaled = scaler.transform(X)

    # predict(): 1 = normal, -1 = anomaly
    df["prediction"] = model.predict(X_scaled)
    # Lower decision_function values indicate greater anomaly; useful for sorting/severity ranking
    df["anomaly_score"] = model.decision_function(X_scaled)
    df["is_anomaly"] = df["prediction"] == -1

    return df


def main():
    parser = argparse.ArgumentParser(description="Perform anomaly detection on network traffic data")
    parser.add_argument("--input", required=True, help="Input features CSV to evaluate")
    parser.add_argument("--model", required=True, help="Path to the trained model file")
    parser.add_argument("--scaler", required=True, help="Path to the fitted Scaler file")
    parser.add_argument("--output", required=True, help="Output path for flagged anomaly results CSV")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    model = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    result = predict(df, model, scaler)
    anomalies = result[result["is_anomaly"]]

    result.to_csv(args.output, index=False)

    print(f"[Done] Evaluated {len(result)} flow records; detected {len(anomalies)} suspected anomalies.")
    print(f"[Done] Results saved to {args.output}")


if __name__ == "__main__":
    main()