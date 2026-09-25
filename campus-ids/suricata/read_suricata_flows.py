"""
read_suricata_flows.py
------------------------
Reads flow events from the Suricata eve.json log,
extracts key features for anomaly detection models, and saves them to a CSV file.

Suricata Configuration Requirements (in suricata.yaml):
    outputs:
      - eve-log:
          enabled: yes
          filetype: regular
          filename: eve.json
          types:
            - flow

Usage:
    python read_suricata_flows.py --input /var/log/suricata/eve.json --output ../data/suricata_flow_features.csv
"""

import json
import argparse
import pandas as pd


def parse_eve_json(input_path: str) -> pd.DataFrame:
    """
    Read eve.json line by line, filter for records where event_type == 'flow',
    and extract relevant feature fields.
    """
    records = []

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines (e.g., incomplete lines read while Suricata is actively writing)
                continue

            if event.get("event_type") != "flow":
                continue

            flow = event.get("flow", {})

            record = {
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "src_port": event.get("src_port"),
                "dest_port": event.get("dest_port"),
                "proto": event.get("proto"),
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "duration_start": flow.get("start"),
                "duration_end": flow.get("end"),
                "state": flow.get("state"),
            }
            records.append(record)

    if not records:
        raise ValueError("No flow records were parsed from eve.json. Please verify your Suricata configuration and the input file path.")

    return pd.DataFrame(records)


def enrich_features(df: pd.DataFrame) -> pd.DataFrame:
    """Derive numerical features required for model training from raw fields."""
    df = df.copy()

    # Calculate flow duration in seconds
    df["duration_start"] = pd.to_datetime(df["duration_start"], errors="coerce")
    df["duration_end"] = pd.to_datetime(df["duration_end"], errors="coerce")
    df["duration_seconds"] = (
        (df["duration_end"] - df["duration_start"]).dt.total_seconds().fillna(0)
    )

    # Calculate total packets and total bytes
    df["total_pkts"] = df["pkts_toserver"] + df["pkts_toclient"]
    df["total_bytes"] = df["bytes_toserver"] + df["bytes_toclient"]

    # Prevent division by zero
    df["bytes_per_pkt"] = df["total_bytes"] / df["total_pkts"].replace(0, 1)

    return df


def main():
    parser = argparse.ArgumentParser(description="Parse Suricata eve.json and export flow features to CSV")
    parser.add_argument("--input", required=True, help="Path to the input eve.json file")
    parser.add_argument("--output", required=True, help="Path to the output CSV file")
    args = parser.parse_args()

    df = parse_eve_json(args.input)
    df = enrich_features(df)
    df.to_csv(args.output, index=False)

    print(f"[Done] Parsed {len(df)} flow records; successfully saved to {args.output}")


if __name__ == "__main__":
    main()