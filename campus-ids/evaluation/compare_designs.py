"""
compare_designs.py
------------------
Design 1 (hybrid: Rule + Stats + Isolation Forest) and Design 2 (Random Forest) on the SAME windows.

The unit of comparison is one (source IP, 10-second window) from data/windows_labelled.csv, i.e. the
exact table that design2/train_rf.py uses. For every window we ask: did the method raise an alert for
that source IP in that window?  The labels (benign / portscan / synflood) come from your own attack logs.

Design 2 (Random Forest) is evaluated with leave-one-day-out cross-validation, exactly like
train_rf.py, so it never predicts a day it was trained on.
Design 1 needs no training on attacks, so every window is simply scored.

WITHOUT --eve the script can only reproduce the Stats layer of Design 1 (two fixed limits applied to
the windows). WITH --eve (the same eve.json files you gave aggregate.py) it replays them through the
real dashboard detector (dashboard/detection.py), so the Rule and ML layers and the full hybrid are
measured too, plus "Design 1 + Design 2" together.

Usage (from the project root):
    python evaluation/compare_designs.py
    python evaluation/compare_designs.py --eve eve_oct03.json eve_oct08.json eve_oct13.json
    python evaluation/compare_designs.py --eve ... --ignore-ips 192.168.50.190
Outputs:
    evaluation/results_comparison.md   the tables, ready for the report
    evaluation/results_comparison.csv  the same numbers as a CSV
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "design2"))
sys.path.insert(0, str(ROOT / "dashboard"))

from train_rf import DEFAULT_FEATURES, load, make_model   # noqa: E402


# ---------------------------------------------------------------- metrics
def metrics(df, pred, name, needs_labels):
    y = df["is_attack"].to_numpy()
    pred = pd.Series(pred, index=df.index).astype(int).to_numpy()
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    f1 = 2 * prec * rec / (prec + rec) if tp else 0.0
    row = {"method": name, "needs_attack_labels": needs_labels, "TP": tp, "FN": fn, "FP": fp, "TN": tn,
           "precision": prec, "recall": rec, "F1": f1, "false_positive_rate": fp / (fp + tn) if fp + tn else float("nan")}
    for t in sorted(df["label"].unique()):
        if t != "benign":
            m = (df["label"] == t).to_numpy()
            row[f"recall_{t}"] = f"{int(pred[m].sum())}/{int(m.sum())}"
    return row


# ---------------------------------------------------------------- Design 2: leave-one-day-out
def random_forest_predictions(df, features):
    test_days = sorted(df.loc[df["is_attack"] == 1, "day"].unique())
    if len(test_days) < 2:
        raise SystemExit("Need attack windows on at least 2 different days for leave-one-day-out CV.")
    pred = pd.Series(0, index=df.index)
    tested = pd.Series(False, index=df.index)
    for day in test_days:
        test = df["day"] == day
        model = make_model().fit(df.loc[~test, features], df.loc[~test, "is_attack"])
        pred[test] = model.predict(df.loc[test, features])
        tested |= test
    return pred, tested


# ---------------------------------------------------------------- Design 1: replay of eve.json
def window_start(value, width):
    t = pd.to_datetime(value, errors="coerce", utc=True)
    return None if pd.isnull(t) else t.floor(width)


def replay_design1(eve_files, args):
    """Run the real dashboard detector over eve.json files. Returns {layer: set((src_ip, window))}."""
    from detection import Detector
    det = Detector(model_path=args.ml_model, scaler_path=args.scaler, own_ips=(), trusted_ips=(),
                   scan_ports=args.scan_ports, flood_flows=args.flood_flows, window=args.stats_window,
                   cooldown=0, dedup_seconds=0)
    if not det.ml_enabled:
        print(f"[!] ML layer is off in the replay ({det.ml_error}); the ML row will be empty.")
    width = f"{args.window}s"
    hits = {"Rule": set(), "Stats": set(), "ML": set()}
    n = 0
    for path in eve_files:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("event_type") not in ("flow", "alert"):
                    continue
                stamp = pd.to_datetime(ev.get("timestamp"), errors="coerce", utc=True)
                if pd.isnull(stamp):
                    continue
                alerts = det.process(ev, now=stamp.timestamp())
                if not alerts:
                    continue
                # flow events are grouped by when the flow STARTED (as in aggregate.py); signature alerts by their time
                when = (ev.get("flow") or {}).get("start") if ev["event_type"] == "flow" else ev.get("timestamp")
                w = window_start(when or ev.get("timestamp"), width)
                if w is None:
                    continue
                for a in alerts:
                    hits[a["source"]].add((a["src_ip"], w))
                n += 1
        print(f"[*] Replayed {path}")
    print(f"[*] {n} events raised at least one Design 1 alert")
    return hits


# ---------------------------------------------------------------- report
def pct(x):
    return "-" if pd.isnull(x) else f"{x:.2f}"


def markdown(rows, df, args, has_eve):
    types = [c for c in rows[0] if c.startswith("recall_")]
    head = ["Method", "Labels needed", "TP", "FN", "FP", "Precision", "Recall", "F1"] + \
           [c.replace("recall_", "Recall ") for c in types]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        lines.append("| " + " | ".join(
            [r["method"], "yes" if r["needs_attack_labels"] else "no", str(r["TP"]), str(r["FN"]), str(r["FP"]),
             pct(r["precision"]), pct(r["recall"]), pct(r["F1"])] + [str(r.get(t, "-")) for t in types]) + " |")
    n_att = int(df["is_attack"].sum())
    out = [f"## Design 1 vs Design 2 on the same windows",
           "",
           f"{len(df)} windows (one per source IP and {args.window} s): {n_att} attack windows "
           f"({', '.join(f'{k} {v}' for k, v in df.loc[df['is_attack'] == 1, 'label'].value_counts().items())}) and "
           f"{len(df) - n_att} benign windows, from the {df['day'].nunique()} days that contain attacks. "
           + (f"Windows from {', '.join(args.ignore_ips)} are left out of every row. " if args.ignore_ips else "")
           + "",
           "", *lines, "",
           "How to read it:",
           f"- Design 2 (Random Forest, features {', '.join(DEFAULT_FEATURES)}) is tested with leave-one-day-out "
           "cross-validation: every window is predicted by a model that never saw that day.",
           f"- Stats rows apply Design 1's two fixed limits (distinct ports, connections) to the fixed {args.window}-second windows. "
           "The live Stats layer counts ports per destination host in a sliding window, while these rows count ports over all "
           "destinations, so they over-count ports of busy normal hosts (many false positives at a low port limit)."
           + (" The Stats (live replay) row is the real layer." if has_eve else ""),
           ("- Rule, Stats (live replay) and ML rows come from replaying the same eve.json files through "
            "dashboard/detection.py. A window counts as detected when the layer raised at least one alert for that "
            "source IP in it. The Isolation Forest was trained on baseline traffic that may include some of these days."
            if has_eve else
            "- Rule and ML (Isolation Forest) rows are missing: they need the eve.json files. Run again with --eve."),
           f"- Only {n_att} attack windows from a few separate runs were available, so one window is worth about "
           f"{100 / max(n_att, 1):.1f} recall points; treat differences of a few points as noise.",
           "- The Stats limits and the Design 2 features were both chosen while looking at part of these data, "
           "so none of the numbers is a final, independent test.", ""]
    return "\n".join(out)


def main():
    p = argparse.ArgumentParser(description="Compare Design 1 and Design 2 on the same labelled windows")
    p.add_argument("--input", default=str(ROOT / "data" / "windows_labelled.csv"))
    p.add_argument("--eve", nargs="*", default=[], help="eve.json files behind the windows (adds Rule, ML and hybrid rows)")
    p.add_argument("--features", nargs="+", default=DEFAULT_FEATURES)
    p.add_argument("--ignore-ips", nargs="*", default=[], help="source IPs left out of the comparison (e.g. your own PC)")
    p.add_argument("--tz", default="Asia/Kuala_Lumpur")
    p.add_argument("--window", type=int, default=10, help="window length in seconds (must match aggregate.py)")
    p.add_argument("--scan-ports", type=int, default=15, help="Design 1 Stats limit: different ports (report default 15)")
    p.add_argument("--flood-flows", type=int, default=150, help="Design 1 Stats limit: connections")
    p.add_argument("--stats-window", type=int, default=10, help="Design 1 live Stats look-back window in seconds")
    p.add_argument("--extra-scan-ports", type=int, default=5,
                   help="also show Stats with this port limit (data/settings.json used 5); 0 = skip")
    p.add_argument("--ml-model", default=str(ROOT / "model" / "ids_model.joblib"))
    p.add_argument("--scaler", default=str(ROOT / "model" / "ids_scaler.joblib"))
    p.add_argument("--out", default=str(ROOT / "evaluation" / "results_comparison.md"))
    args = p.parse_args()

    df = load(args.input, args.tz, args.features)
    rf_pred, tested = random_forest_predictions(df, args.features)
    keep = tested & ~df["src_ip"].isin(args.ignore_ips)
    d = df[keep].copy()
    rf = rf_pred[keep]
    print(f"[*] {len(d)} windows compared ({int(d['is_attack'].sum())} attack)")

    rows = []

    def add(name, pred, labels):
        rows.append(metrics(d, pred, name, labels))

    stats = lambda ports, flows: ((d["distinct_ports"] >= ports) | (d["conn_count"] >= flows)).astype(int)
    add(f"Design 1 Stats, fixed limits ({args.scan_ports} ports / {args.flood_flows} flows)",
        stats(args.scan_ports, args.flood_flows), False)
    if args.extra_scan_ports and args.extra_scan_ports != args.scan_ports:
        add(f"Design 1 Stats, fixed limits ({args.extra_scan_ports} ports / {args.flood_flows} flows)",
            stats(args.extra_scan_ports, args.flood_flows), False)

    if args.eve:
        hits = replay_design1(args.eve, args)
        key = list(zip(d["src_ip"], pd.to_datetime(d["window"], utc=True)))
        flag = {k: pd.Series([kk in hits[k] for kk in key], index=d.index).astype(int) for k in hits}
        add("Design 1 Rule layer (Suricata signatures)", flag["Rule"], False)
        add(f"Design 1 Stats layer, live replay ({args.scan_ports} ports / {args.flood_flows} flows)", flag["Stats"], False)
        add("Design 1 ML layer (Isolation Forest)", flag["ML"], False)
        hybrid = ((flag["Rule"] + flag["Stats"] + flag["ML"]) > 0).astype(int)
        add("Design 1 hybrid (Rule or Stats or ML)", hybrid, False)
        add("Design 2 Random Forest", rf, True)
        add("Design 1 + Design 2 together", ((hybrid + rf) > 0).astype(int), True)
    else:
        add("Design 2 Random Forest", rf, True)

    text = markdown(rows, d, args, bool(args.eve))
    print("\n" + text)
    Path(args.out).write_text(text, encoding="utf-8")
    pd.DataFrame(rows).to_csv(Path(args.out).with_suffix(".csv"), index=False)
    print(f"[Done] Saved {args.out} and {Path(args.out).with_suffix('.csv')}")


if __name__ == "__main__":
    main()
