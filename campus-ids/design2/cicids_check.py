"""
cicids_check.py  (Design 2)
---------------------------
Tests the lab-trained Random Forest on CIC-IDS2017 (Friday PortScan / DDoS files) and compares it
with Design 1's fixed rule on the same windows. It does three things:
  1. reads the CIC-IDS2017 flow CSVs,
  2. builds the same per-source-IP window features as aggregate.py,
  3. predicts with the saved model and prints precision / recall / F1 / false-positive rate.

IMPORTANT - which CIC-IDS2017 files:
  The files in evaluation/ (79 columns) have NO Source IP and NO Timestamp, so per-IP windows
  cannot be built from them. You need the "TrafficLabelling" (GeneratedLabelledFlows) version of
  the Friday files, which has the columns Flow ID, Source IP, ..., Timestamp, ..., Label.

Known differences between CIC-IDS2017 flows (CICFlowMeter) and the lab flows (Suricata):
  * total_bytes: CIC counts payload bytes only, Suricata counts whole packets (headers included).
    So train a model WITHOUT total_bytes for this check (command below).
  * CIC timestamps have no AM/PM and may have only minute resolution. If they have no seconds,
    10-second windows are impossible: the script stops and tells you to use --window 60s (and to
    build the lab windows with aggregate.py --window 60s and train on those).
  * CICFlowMeter sometimes records a flow in the reverse direction, so a few "source" IPs are
    really the victim. This adds a little noise.

Steps:
  python design2/train_rf.py --input data/windows_labelled.csv --features conn_count distinct_ports rst_ratio avg_pkts --model-out model/rf_model_nobytes.joblib --report-out evaluation/results_rf_nobytes.txt
  python design2/cicids_check.py --csv <Friday-PortScan>.csv <Friday-DDoS>.csv --model model/rf_model_nobytes.joblib

A CIC window is called an attack window when more than half of its flows carry an attack label.
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd

from train_rf import REPORT, say, summarize

NEEDED = ["Source IP", "Destination Port", "Timestamp", "Total Fwd Packets", "Total Backward Packets",
          "Total Length of Fwd Packets", "Total Length of Bwd Packets", "RST Flag Count", "Label"]


def read_cic(path):
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    missing = [c for c in NEEDED if c not in df.columns]
    if missing:
        raise SystemExit(
            f"{path}\n  is missing the column(s) {missing}.\n"
            "  This must be the TrafficLabelling (GeneratedLabelledFlows) version of CIC-IDS2017, "
            "which has Source IP and Timestamp. The MachineLearningCSV version does not.")
    return df


def build_windows(flows, window):
    df = flows.copy()
    df["Timestamp"] = pd.to_datetime(df["Timestamp"].astype(str).str.strip(), dayfirst=True, errors="coerce")
    bad = int(df["Timestamp"].isna().sum())
    if bad:
        say(f"[!] {bad} rows with an unreadable Timestamp were dropped")
    df = df.dropna(subset=["Timestamp", "Source IP"])

    if pd.Timedelta(window) < pd.Timedelta("60s") and (df["Timestamp"].dt.second == 0).all():
        raise SystemExit(
            "The Timestamp column has only minute resolution (no seconds), so --window "
            f"{window} is impossible.\nUse --window 60s, build the lab windows with "
            "'aggregate.py --window 60s ...' and train the model on those.")

    for c in ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
              "Total Length of Bwd Packets", "RST Flag Count"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["pkts"] = df["Total Fwd Packets"] + df["Total Backward Packets"]
    df["bytes"] = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
    df["rst"] = (df["RST Flag Count"] > 0).astype(float)
    if "Protocol" in df.columns:
        df.loc[pd.to_numeric(df["Protocol"], errors="coerce") != 6, "rst"] = float("nan")   # TCP only
    df["is_attack_flow"] = df["Label"].astype(str).str.strip().str.upper() != "BENIGN"
    df["window"] = df["Timestamp"].dt.floor(window)

    keys = ["Source IP", "window"]
    win = df.groupby(keys).agg(
        conn_count=("Source IP", "size"),
        distinct_ports=("Destination Port", "nunique"),
        rst_ratio=("rst", "mean"),
        avg_pkts=("pkts", "mean"),
        total_bytes=("bytes", "sum"),
        attack_share=("is_attack_flow", "mean"),
    ).reset_index().rename(columns={"Source IP": "src_ip"})
    win["rst_ratio"] = win["rst_ratio"].fillna(0.0)

    kind = (df[df["is_attack_flow"]].groupby(keys)["Label"]
            .agg(lambda s: s.astype(str).str.strip().mode().iat[0]).rename("attack_type").reset_index()
            .rename(columns={"Source IP": "src_ip"}))
    win = win.merge(kind, on=["src_ip", "window"], how="left")
    is_attack = win["attack_share"] > 0.5
    win["label"] = "benign"
    win.loc[is_attack, "label"] = win.loc[is_attack, "attack_type"].fillna("attack").str.lower().str.replace(" ", "")
    win["is_attack"] = is_attack.astype(int)
    return win


def main():
    p = argparse.ArgumentParser(description="Design 2: test the lab-trained Random Forest on CIC-IDS2017")
    p.add_argument("--csv", nargs="+", required=True, help="CIC-IDS2017 TrafficLabelling CSV file(s)")
    p.add_argument("--model", required=True, help="joblib file saved by train_rf.py")
    p.add_argument("--window", default="10s")
    p.add_argument("--baseline-ports", type=int, default=15)
    p.add_argument("--baseline-flows", type=int, default=150)
    p.add_argument("--windows-out", help="optional: save the CIC windows to this CSV")
    p.add_argument("--report-out", default="evaluation/results_rf_cicids.txt")
    args = p.parse_args()

    flows = pd.concat([read_cic(f) for f in args.csv], ignore_index=True)
    say(f"Read {len(flows)} CIC-IDS2017 flows from {len(args.csv)} file(s)")
    win = build_windows(flows, args.window)
    say(f"Built {len(win)} (source IP, {args.window} window) rows: "
        + ", ".join(f"{k}={v}" for k, v in win["label"].value_counts().items()))

    bundle = joblib.load(args.model)
    model, features = bundle["model"], bundle["features"]
    say(f"Model features: {features}")
    if "total_bytes" in features:
        say("[!] The model uses total_bytes, but CIC counts payload bytes only, so this check is unreliable. "
            "Train a model without total_bytes (see the top of this script).")
    if win["is_attack"].sum() == 0:
        raise SystemExit("No attack windows were found - check the Label column and the file choice.")
    say()

    pred = model.predict(win[features])
    summarize(win, pred, "Random Forest (trained on lab data only) on CIC-IDS2017 windows")
    say()
    rule = ((win["distinct_ports"] >= args.baseline_ports) | (win["conn_count"] >= args.baseline_flows)).astype(int)
    summarize(win, rule.to_numpy(),
              f"REFERENCE: fixed rule (distinct_ports >= {args.baseline_ports} or conn_count >= {args.baseline_flows})")

    if args.windows_out:
        win.to_csv(args.windows_out, index=False)
        say(f"\nWindows saved to {args.windows_out}")
    Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report_out).write_text("\n".join(REPORT) + "\n", encoding="utf-8")
    print(f"[Done] Report saved to {args.report_out}")


if __name__ == "__main__":
    main()
