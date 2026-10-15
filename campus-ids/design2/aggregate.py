"""
aggregate.py  (Design 2)
------------------------
Turns Suricata eve.json flow records into ONE row per (source IP, 10-second window).

Why not reuse data/suricata_flow_features.csv or suricata/read_suricata_flows.py?
Design 1 drops flows with < 15 packets (to avoid web-browsing false alarms), but a port
scan or SYN flood is made of exactly those tiny flows. Design 2 therefore reads the raw
eve.json and keeps every flow.

Features per (src_ip, window):
    conn_count      number of flows started by this source in the window
    distinct_ports  number of different destination ports it touched
    syn_ratio       share of TCP flows that are SYN attempts that never became a real
                    connection (SYN seen, <= 3 packets in total).  NOTE: on the real lab data
                    this is ~0 for hping3 floods, because each flood flow has 6 packets.
    rst_ratio       share of TCP flows that ended with a TCP reset (RST flag seen)
    avg_pkts        average number of packets per flow in the window
    total_bytes     bytes sent + received over all those flows

Optional labelling (for training): give --labels labels.csv (one or more files) with the columns
    start,end,attacker_ip,label
    2026-10-14 15:02:00,2026-10-14 15:04:30,192.168.50.204,portscan
    2026-10-14 15:10:00,2026-10-14 15:11:00,192.168.50.204,synflood
A window is labelled when it overlaps [start, end] AND comes from attacker_ip, and only if the
attacker started at least --min-attack-flows flows in it (default 5; fragments with fewer flows
become "ambiguous").
Every other window is labelled "benign", EXCEPT windows from a machine listed in
--attacker-ips that fall outside every labelled period: those are "ambiguous" (the attacker
machine was just idling or doing something else) and are dropped unless --keep-ambiguous.
Times without a timezone are read as --tz.

Usage:
    python design2/aggregate.py --eve eve.json --out data/windows.csv
    python design2/aggregate.py --eve eve.json --labels design2/labels.csv --attacker-ips 192.168.50.204 192.168.50.72 --out data/windows_labelled.csv
"""

import argparse
import json

import pandas as pd

FEATURES = ["conn_count", "distinct_ports", "syn_ratio", "rst_ratio", "avg_pkts", "total_bytes"]


def parse_flow_event(ev):
    """One parsed eve.json line -> one flow row (dict), or None if it is not a flow event.
    Shared by the offline reader below and by the live detector (design2/rf_detector.py), so
    training and live detection compute the features from exactly the same numbers."""
    if ev.get("event_type") != "flow":
        return None

    flow = ev.get("flow", {})
    tcp = ev.get("tcp") or {}
    proto = ev.get("proto")
    total_pkts = flow.get("pkts_toserver", 0) + flow.get("pkts_toclient", 0)
    total_bytes = flow.get("bytes_toserver", 0) + flow.get("bytes_toclient", 0)

    # SYN attempt that never turned into a real connection.
    # (If Suricata did not log the tcp flags, any tiny TCP flow counts.)
    syn_seen = bool(tcp.get("syn")) if "syn" in tcp else True
    syn_attempt = proto == "TCP" and syn_seen and total_pkts <= 3

    return {
        "timestamp": ev.get("timestamp"),
        "start": flow.get("start"),
        "src_ip": ev.get("src_ip"),
        "dest_ip": ev.get("dest_ip"),
        "dest_port": ev.get("dest_port"),
        "proto": proto,
        "is_tcp": proto == "TCP",
        "syn_attempt": syn_attempt,
        "rst": proto == "TCP" and bool(tcp.get("rst")),
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
    }


def read_eve_flows(path):
    """Read every flow event (no packet-count filter) from one eve.json file."""
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = parse_flow_event(ev)
            if row is not None:
                rows.append(row)
    return pd.DataFrame(rows)


def aggregate(flows, window="10s"):
    """flows (one row per flow) -> one row per (src_ip, window)."""
    if flows.empty:
        return pd.DataFrame(columns=["src_ip", "window"] + FEATURES)

    df = flows.copy()
    # Use the flow's START time (the event timestamp is when Suricata wrote it, i.e. later).
    t = pd.to_datetime(df["start"], errors="coerce", utc=True)
    t = t.fillna(pd.to_datetime(df["timestamp"], errors="coerce", utc=True))
    df["window"] = t.dt.floor(window)
    df = df.dropna(subset=["window", "src_ip"])

    # syn_ratio is measured against TCP flows only
    df["syn_attempt"] = df["syn_attempt"].astype(float)
    df.loc[~df["is_tcp"], "syn_attempt"] = float("nan")
    df["rst"] = df["rst"].astype(float)
    df.loc[~df["is_tcp"], "rst"] = float("nan")

    out = (
        df.groupby(["src_ip", "window"])
        .agg(
            conn_count=("src_ip", "size"),
            distinct_ports=("dest_port", "nunique"),
            syn_ratio=("syn_attempt", "mean"),
            rst_ratio=("rst", "mean"),
            avg_pkts=("total_pkts", "mean"),
            total_bytes=("total_bytes", "sum"),
        )
        .reset_index()
    )
    out["syn_ratio"] = out["syn_ratio"].fillna(0.0)   # no TCP flows in the window
    out["rst_ratio"] = out["rst_ratio"].fillna(0.0)
    out = out[["src_ip", "window"] + FEATURES]
    return out


def add_labels(windows, labels_path, window="10s", tz="Asia/Kuala_Lumpur", attacker_ips=(), min_attack_flows=0):
    """Add a 'label' column: attack name if the window overlaps a labelled period, else 'benign'.
    Windows from an attacker machine outside every labelled period become 'ambiguous'.
    Attack windows in which the attacker started fewer than min_attack_flows flows (for example the
    first or last fragment of a run) also become 'ambiguous': one flow is not an attack by itself."""
    paths = [labels_path] if isinstance(labels_path, str) else list(labels_path)
    lab = pd.concat([pd.read_csv(p) for p in paths], ignore_index=True)
    need = {"start", "end", "attacker_ip", "label"}
    if not need.issubset(lab.columns):
        raise ValueError(f"labels file needs the columns {sorted(need)}")

    def parse(col):
        t = pd.to_datetime(lab[col])
        return t.dt.tz_localize(tz) if t.dt.tz is None else t.dt.tz_convert("UTC")

    lab["start"], lab["end"] = parse("start"), parse("end")
    width = pd.Timedelta(window)

    out = windows.copy()
    out["label"] = "benign"
    for _, r in lab.iterrows():
        hit = (
            (out["src_ip"] == r["attacker_ip"])
            & (out["window"] + width > r["start"])
            & (out["window"] <= r["end"])
        )
        out.loc[hit, "label"] = r["label"]

    idle_attacker = (out["label"] == "benign") & out["src_ip"].isin(list(attacker_ips))
    out.loc[idle_attacker, "label"] = "ambiguous"

    weak_attack = ~out["label"].isin(["benign", "ambiguous"]) & (out["conn_count"] < min_attack_flows)
    out.loc[weak_attack, "label"] = "ambiguous"
    return out


def main():
    p = argparse.ArgumentParser(description="Design 2: aggregate Suricata flows per source IP and time window")
    p.add_argument("--eve", nargs="+", required=True, help="one or more eve.json files")
    p.add_argument("--out", required=True, help="output CSV")
    p.add_argument("--window", default="10s", help="window size (default 10s)")
    p.add_argument("--labels", nargs="+", help="one or more labels CSV files (start,end,attacker_ip,label); omit for unlabelled data")
    p.add_argument("--tz", default="Asia/Kuala_Lumpur", help="timezone for label times without one")
    p.add_argument("--attacker-ips", nargs="*", default=[], help="machines used for attacks (their unlabelled windows become 'ambiguous')")
    p.add_argument("--min-attack-flows", type=int, default=5,
                   help="attack windows with fewer flows than this are set to 'ambiguous' (default 5)")
    p.add_argument("--keep-ambiguous", action="store_true", help="do not drop 'ambiguous' windows")
    args = p.parse_args()

    flows = pd.concat([read_eve_flows(f) for f in args.eve], ignore_index=True)
    print(f"[*] Read {len(flows)} flow records (no packet filter)")
    windows = aggregate(flows, args.window)
    if args.labels:
        windows = add_labels(windows, args.labels, args.window, args.tz, args.attacker_ips, args.min_attack_flows)
        print(windows["label"].value_counts().to_string())
        if not args.keep_ambiguous:
            windows = windows[windows["label"] != "ambiguous"]
            print("[*] Dropped 'ambiguous' windows")
    windows.to_csv(args.out, index=False)
    print(f"[Done] {len(windows)} (source IP, window) rows saved to {args.out}")


if __name__ == "__main__":
    main()
