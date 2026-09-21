"""
Campus IDS — Isolation Forest Demo on NSL-KDD (static dataset)
------------------------------------------------------------------
This is a small demo to train an
Isolation Forest model, using the NSL_KDD_Train.csv file just
downloaded, BEFORE touching live packet capture. 

What it does:
    1. Loads the NSL-KDD CSV (it has no header row, so we name the
       columns ourselves)
    2. Converts text columns (protocol_type, service, flag) into
       numbers, since ML models can't read text directly
    3. Trains an Isolation Forest on the data
    4. Compares what the model guessed (normal/anomaly) against the
       real labels, just so can see roughly how well it did

Requirements:
    pip install pandas scikit-learn

Usage:
    Put NSL_KDD_Train.csv in the same folder as this script, then:
    python3 isolation_forest_demo.py
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

CSV_PATH = "NSL_KDD_Train.csv"

# NSL-KDD has 41 features + 1 label column + 1 "difficulty" column,
# but no header row in the file, so we define the column names here.
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


def load_data():
    df = pd.read_csv(CSV_PATH, names=COLUMN_NAMES)
    print(f"Loaded {len(df)} rows.")
    return df


def encode_categorical(df):
    """Turn text columns into numbers so the model can use them."""
    text_columns = ["protocol_type", "service", "flag"]
    for col in text_columns:
        df[col] = LabelEncoder().fit_transform(df[col])
    return df


def make_binary_label(df):
    """NSL-KDD has many attack types (neptune, smurf, ...) — for this
    demo we just care about normal vs anything-that-isn't-normal."""
    df["is_attack"] = df["label"].apply(lambda x: 0 if x == "normal" else 1)
    return df


def main():
    df = load_data()
    df = encode_categorical(df)
    df = make_binary_label(df)

    # Features = everything except the label columns
    feature_cols = [c for c in COLUMN_NAMES if c not in ("label", "difficulty")]
    X = df[feature_cols]

    # contamination = your rough guess at what % of the data is anomalous.
    # NSL-KDD's training set is roughly balanced, so we estimate it
    # directly from the real label just for this first trial run —
    # on live traffic later, you won't have real labels to check against.
    contamination_estimate = df["is_attack"].mean()
    print(f"Estimated contamination rate: {contamination_estimate:.3f}")

    model = IsolationForest(
        contamination=contamination_estimate,
        random_state=42,
    )
    model.fit(X)

    # IsolationForest predicts -1 = anomaly, 1 = normal.
    # Convert that to match our 0/1 "is_attack" labels for comparison.
    raw_predictions = model.predict(X)
    df["predicted_attack"] = [1 if p == -1 else 0 for p in raw_predictions]

    # Simple accuracy check — just for you to sanity-check the model,
    # not a proper evaluation (that comes later with train/test splits).
    accuracy = (df["predicted_attack"] == df["is_attack"]).mean()
    print(f"Rough agreement with real labels: {accuracy:.3f}")

    print("\nSample of predictions vs actual labels:")
    print(df[["label", "is_attack", "predicted_attack"]].sample(10, random_state=1))


if __name__ == "__main__":
    main()
