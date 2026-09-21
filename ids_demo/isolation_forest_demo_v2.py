"""
Campus IDS — Small-Scale Parameter Trials (v2)
------------------------------------------------
This extends the first demo by:
    1. Scaling features (so no single large-value column dominates
       the model's decisions)
    2. Running SMALL trials on a sample of the data first, trying a
       few different contamination values
    3. Only applying the best-looking setting to the FULL dataset

This matches: "ran small-scale trials on sample data first, gradually
adjusting parameters such as contamination rate before applying the
model to the full dataset."

Requirements:
    pip install pandas scikit-learn
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

CSV_PATH = "NSL_KDD_Train.csv"
SAMPLE_SIZE = 5000  # small subset for quick trial runs

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label",
    "difficulty",
]


def load_and_prepare():
    df = pd.read_csv(CSV_PATH, names=COLUMN_NAMES)

    for col in ["protocol_type", "service", "flag"]:
        df[col] = LabelEncoder().fit_transform(df[col])

    df["is_attack"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
    return df


def evaluate(X, y, contamination):
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(X)
    preds = [1 if p == -1 else 0 for p in model.predict(X)]
    accuracy = sum(p == a for p, a in zip(preds, y)) / len(y)
    return accuracy


def main():
    df = load_and_prepare()
    feature_cols = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]

    # --- Step 1: small sample for quick trials ---
    sample = df.sample(SAMPLE_SIZE, random_state=1)
    X_sample = sample[feature_cols]
    y_sample = sample["is_attack"].tolist()

    # Scale so large-value columns (like src_bytes) don't dominate
    scaler = StandardScaler()
    X_sample_scaled = scaler.fit_transform(X_sample)

    print(f"Running trials on a sample of {SAMPLE_SIZE} rows...\n")

    candidate_rates = [0.1, 0.2, 0.3, 0.465]
    results = {}
    for rate in candidate_rates:
        acc = evaluate(X_sample_scaled, y_sample, rate)
        results[rate] = acc
        print(f"contamination={rate:<6} -> accuracy on sample: {acc:.3f}")

    best_rate = max(results, key=results.get)
    print(f"\nBest contamination on sample: {best_rate} (accuracy {results[best_rate]:.3f})")

    # --- Step 2: apply the best setting to the FULL dataset ---
    print(f"\nApplying contamination={best_rate} to the full dataset ({len(df)} rows)...")
    X_full = df[feature_cols]
    X_full_scaled = scaler.transform(X_full)  # reuse the same scaler
    y_full = df["is_attack"].tolist()

    full_accuracy = evaluate(X_full_scaled, y_full, best_rate)
    print(f"Accuracy on full dataset: {full_accuracy:.3f}")


if __name__ == "__main__":
    main()
