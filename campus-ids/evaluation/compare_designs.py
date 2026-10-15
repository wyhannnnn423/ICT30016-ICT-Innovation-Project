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
from datetime import datetime
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


def fast_epoch(text):
    """ISO timestamp -> UTC epoch seconds. Much faster than pd.to_datetime for millions of lines."""
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        t = pd.to_datetime(text, errors="coerce", utc=True)
        return None if pd.isnull(t) else t.timestamp()


ML_COLUMNS = ["pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
              "duration_seconds", "total_pkts", "total_bytes", "bytes_per_pkt"]   # same as Detector._features


def ml_row(flow):
    pts, ptc = flow.get("pkts_toserver", 0), flow.get("pkts_toclient", 0)
    bts, btc = flow.get("bytes_toserver", 0), flow.get("bytes_toclient", 0)
    start, end = fast_epoch(flow.get("start")), fast_epoch(flow.get("end"))
    duration = end - start if start is not None and end is not None else 0.0
    total_pkts, total_bytes = pts + ptc, bts + btc
    return [pts, ptc, bts, btc, duration, total_pkts, total_bytes, total_bytes / (total_pkts if total_pkts > 0 else 1)]


def score_ml_batch(ml, rows, keys, hits, width):
    """Isolation Forest on many flows at once (one flow at a time is ~100 times slower)."""
    if not rows:
        return
    x = ml.scaler.transform(pd.DataFrame(rows, columns=ML_COLUMNS))
    flagged = ml.model.predict(x) == -1
    for key, bad in zip(keys, flagged):
        if bad:
            hits["ML"].add((key[0], pd.Timestamp(key[1], unit="s", tz="UTC")))


def replay_design1(eve_files, args, first, last):
    """Run Design 1 over eve.json files. Returns {layer: set((src_ip, window))}.

    Rule and Stats go through the real dashboard detector (dashboard/detection.py), one event at a time.
    The Isolation Forest uses the same model, scaler, packet filter and features, but scores flows in
    batches, because scoring one flow at a time takes hours on a file this big.

    Only the time range of the labelled windows (first .. last) is replayed. eve.json is huge and keeps
    growing, and lines before or after that range cannot change the table. The files are read in order,
    so reading stops as soon as the first line after the range appears."""
    import time
    from detection import Detector
    det = Detector(model_path=None, own_ips=(), trusted_ips=(),
                   scan_ports=args.scan_ports, flood_flows=args.flood_flows, window=args.stats_window,
                   cooldown=0, dedup_seconds=0)
    ml = Detector(model_path=args.ml_model, scaler_path=args.scaler)
    if not ml.ml_enabled:
        print(f"[!] ML layer is off in the replay ({ml.ml_error}); the ML row will be empty.")
    width = f"{args.window}s"
    # local-time strings, the same format as the start of every eve.json line (2026-10-13T14:21:15)
    lo = first.tz_convert(args.tz).strftime("%Y-%m-%dT%H:%M:%S")
    hi = (last + pd.Timedelta(seconds=args.window + 60)).tz_convert(args.tz).strftime("%Y-%m-%dT%H:%M:%S")
    print(f"[*] Replaying only {lo} to {hi} ({args.tz})")

    hits = {"Rule": set(), "Stats": set(), "ML": set()}
    ml_rows, ml_keys = [], []
    n_alert_events = 0
    t0 = time.time()
    for path in eve_files:
        lines = used = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                lines += 1
                if lines % 1_000_000 == 0:
                    print(f"    {lines:,} lines read, {used:,} replayed, at {line[14:33]}, {time.time() - t0:.0f} s", flush=True)
                if line.startswith('{"timestamp":"'):
                    if '"event_type":"flow"' not in line and '"event_type":"alert"' not in line:
                        continue
                    ts = line[14:33]
                    if ts < lo:
                        continue
                    if ts > hi:
                        break                      # the file is in time order: nothing useful comes later
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                etype = ev.get("event_type")
                if etype not in ("flow", "alert"):
                    continue
                stamp = fast_epoch(ev.get("timestamp"))
                if stamp is None:
                    continue
                used += 1
                # flow events are grouped by when the flow STARTED (as in aggregate.py); signature alerts by their time
                flow = ev.get("flow") or {}
                when = fast_epoch(flow.get("start")) if etype == "flow" else stamp
                if when is None:
                    when = stamp
                bucket = (when // args.window) * args.window

                if etype == "flow" and ml.ml_enabled and \
                        flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0) >= ml.min_pkts:
                    ml_rows.append(ml_row(flow))
                    ml_keys.append((ev.get("src_ip"), bucket))
                    if len(ml_rows) >= 50_000:
                        score_ml_batch(ml, ml_rows, ml_keys, hits, width)
                        ml_rows, ml_keys = [], []

                alerts = det.process(ev, now=stamp)
                if alerts:
                    n_alert_events += 1
                    for a in alerts:
                        hits[a["source"]].add((a["src_ip"], pd.Timestamp(bucket, unit="s", tz="UTC")))
        print(f"[*] Replayed {path}: {lines:,} lines read, {used:,} used, {time.time() - t0:.0f} s")
    score_ml_batch(ml, ml_rows, ml_keys, hits, width)
    print(f"[*] Alerts: Rule in {len(hits['Rule'])} windows, Stats in {len(hits['Stats'])}, ML in {len(hits['ML'])}")
    if len(hits["Rule"]) + len(hits["Stats"]) + len(hits["ML"]) < 50:
        print("[!] Very few alerts. Does this eve.json really contain the attack days? "
              "(Use the file(s) you gave to aggregate.py.)")
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
        win = pd.to_datetime(d["window"], utc=True)
        hits = replay_design1(args.eve, args, win.min(), win.max())
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
