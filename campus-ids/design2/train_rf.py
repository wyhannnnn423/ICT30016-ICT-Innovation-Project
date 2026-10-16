"""
train_rf.py  (Design 2)
-----------------------
Trains a Random Forest on the labelled (source IP, 10-second window) table made by
aggregate.py and evaluates it with LEAVE-ONE-DAY-OUT cross-validation.

Why leave-one-day-out? The attack data comes from a few separate sessions on a few days.
A random train/test split would put windows of the SAME attack run on both sides and make
the result look better than it is. Here each fold holds out every window of one day that
contains attacks, trains on all the other days, and predicts the held-out day.

Features: by default conn_count, distinct_ports, rst_ratio, avg_pkts, total_bytes. To reproduce the
first version (with syn_ratio) use:
    --features conn_count distinct_ports syn_ratio total_bytes

Label handling: anything that is not "benign" counts as an attack (binary problem).
The attack type (portscan / synflood) is only used to report recall per type.

Usage:
    python design2/train_rf.py --input data/windows_labelled.csv
Outputs:
    model/rf_model.joblib           final model trained on ALL days
    evaluation/results_rf.txt       the printed report, saved
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

DEFAULT_FEATURES = ["conn_count", "distinct_ports", "rst_ratio", "avg_pkts", "total_bytes"]
REPORT = []


def say(text=""):
    print(text)
    REPORT.append(text)


def make_model(seed=42):
    return RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced_subsample",   # attacks are a tiny fraction of all windows
        min_samples_leaf=2,
        random_state=seed,
        n_jobs=-1,
    )


def load(path, tz, features):
    df = pd.read_csv(path)
    missing = [c for c in features + ["window", "label"] if c not in df.columns]
    if missing:
        raise ValueError(f"{path} is missing column(s) {missing}. Run aggregate.py with --labels first.")
    df = df[df["label"] != "ambiguous"].reset_index(drop=True)
    df["window"] = pd.to_datetime(df["window"], utc=True)
    df["day"] = df["window"].dt.tz_convert(tz).dt.date.astype(str)
    df["is_attack"] = (df["label"] != "benign").astype(int)
    return df


def summarize(df, pred, title):
    """Print precision / recall / F1 / false-positive rate for one set of predictions."""
    y = df["is_attack"].to_numpy()
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if tp else float("nan")
    fpr = fp / (fp + tn) if fp + tn else float("nan")
    say(f"{title}")
    say(f"  windows: {len(df)}  (attack {tp + fn}, benign {fp + tn})")
    say(f"  TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    say(f"  precision={precision:.3f}  recall={recall:.3f}  F1={f1:.3f}  false-positive rate={fpr:.4f}")
    for t in sorted(df["label"].unique()):
        if t == "benign":
            continue
        m = (df["label"] == t).to_numpy()
        say(f"  recall {t}: {int(pred[m].sum())}/{int(m.sum())}")


def main():
    p = argparse.ArgumentParser(description="Design 2: train and evaluate the Random Forest")
    p.add_argument("--input", required=True, help="labelled windows CSV from aggregate.py")
    p.add_argument("--model-out", default="model/rf_model.joblib")
    p.add_argument("--report-out", default="evaluation/results_rf.txt")
    p.add_argument("--tz", default="Asia/Kuala_Lumpur", help="timezone used to split windows into days")
    p.add_argument("--features", nargs="+", default=DEFAULT_FEATURES, help="feature columns to use")
    p.add_argument("--ignore-ips", nargs="*", default=[],
                   help="source IPs left out of the EVALUATION only (e.g. your own PC, which the Design 1 dashboard "
                        "also ignores); they are still used for training")
    p.add_argument("--baseline-ports", type=int, default=15, help="Design 1 Stats rule: distinct ports that count as a scan")
    p.add_argument("--baseline-flows", type=int, default=150, help="Design 1 Stats rule: flows per window that count as a flood")
    args = p.parse_args()

    features = args.features
    df = load(args.input, args.tz, features)
    say(f"Loaded {len(df)} windows: " + ", ".join(f"{k}={v}" for k, v in df["label"].value_counts().items()))
    say("Windows per day (attack/total): " + ", ".join(
        f"{d}={int(g['is_attack'].sum())}/{len(g)}" for d, g in df.groupby("day")))
    say(f"Features: {features}")
    if args.ignore_ips:
        say(f"Evaluation ignores windows from: {args.ignore_ips} (still used for training)")
    say()
    keep = ~df["src_ip"].isin(args.ignore_ips)

    # ---- leave-one-day-out cross-validation ----
    test_days = sorted(df.loc[df["is_attack"] == 1, "day"].unique())
    if len(test_days) < 2:
        raise SystemExit("Need attack windows on at least 2 different days for leave-one-day-out CV.")
    pooled_pred = pd.Series(0, index=df.index)
    pooled_mask = pd.Series(False, index=df.index)
    for day in test_days:
        test = df["day"] == day
        train = ~test
        model = make_model().fit(df.loc[train, features], df.loc[train, "is_attack"])
        pred = model.predict(df.loc[test, features])
        pooled_pred[test] = pred
        pooled_mask |= test
        summarize(df[test & keep], pooled_pred[test & keep].to_numpy(), f"Fold: test day {day} (trained on the other days)")
        say()

    eval_mask = pooled_mask & keep
    summarize(df[eval_mask], pooled_pred[eval_mask].to_numpy(), "ALL FOLDS POOLED")
    cols = ["src_ip", "window", "label"] + features
    fp_rows = df[eval_mask & (pooled_pred == 1) & (df["is_attack"] == 0)]
    if len(fp_rows):
        say()
        say("False positives (benign windows predicted as attack), up to 10:")
        say(fp_rows[cols].head(10).to_string())
    fn_rows = df[eval_mask & (pooled_pred == 0) & (df["is_attack"] == 1)]
    if len(fn_rows):
        say()
        say("Missed attacks (attack windows predicted as benign):")
        say(fn_rows[cols].to_string())
    say()

    # ---- reference: the fixed-threshold rule of Design 1 (Stats layer) on the same windows ----
    # Approximation: the real Stats layer counts ports per destination host in a sliding window;
    # here the same two thresholds are applied to the fixed 10-second windows.
    rule_pred = ((df["distinct_ports"] >= args.baseline_ports) | (df["conn_count"] >= args.baseline_flows)).astype(int)
    summarize(df[eval_mask], rule_pred[eval_mask].to_numpy(),
              f"REFERENCE: fixed rule (distinct_ports >= {args.baseline_ports} or conn_count >= {args.baseline_flows}) "
              f"on the same windows")
    say()

    # ---- final model on all days ----
    final = make_model().fit(df[features], df["is_attack"])
    say("Feature importance of the final model (trained on all days):")
    for name, imp in sorted(zip(features, final.feature_importances_), key=lambda x: -x[1]):
        say(f"  {name:15s} {imp:.3f}")

    Path(args.model_out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": final, "features": features}, args.model_out)
    say(f"\n[Done] Final model saved to {args.model_out}")

    Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report_out).write_text("\n".join(REPORT) + "\n", encoding="utf-8")
    print(f"[Done] Report saved to {args.report_out}")


if __name__ == "__main__":
    main()
