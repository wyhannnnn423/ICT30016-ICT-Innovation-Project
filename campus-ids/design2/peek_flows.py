"""
peek_flows.py  (Design 2, helper)
---------------------------------
Prints a few raw flow records from eve.json for one source IP and one time prefix, so you can
see what an attack really looks like (packets per flow, TCP flags, state).

Usage:
    python design2/peek_flows.py --eve "C:\\Program Files\\Suricata\\log\\eve.json" --src-ip 192.168.50.204 --start 2026-10-08T14:35:4
The --start value is matched against the start of the flow's own "start" field (local time,
as Suricata writes it), so "2026-10-08T14:35:4" means 14:35:40 to 14:35:49.
"""

import argparse
import json


def main():
    p = argparse.ArgumentParser(description="Show raw Suricata flow records for one source IP and time prefix")
    p.add_argument("--eve", required=True)
    p.add_argument("--src-ip", required=True)
    p.add_argument("--start", required=True, help='prefix of flow start time, e.g. "2026-10-08T14:35:4"')
    p.add_argument("--limit", type=int, default=15)
    args = p.parse_args()

    shown = 0
    total = 0
    with open(args.eve, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "flow" or ev.get("src_ip") != args.src_ip:
                continue
            flow = ev.get("flow", {})
            if not str(flow.get("start", "")).startswith(args.start):
                continue
            total += 1
            if shown < args.limit:
                shown += 1
                print(f"start={flow.get('start')}  dest_ip={ev.get('dest_ip')}  dest_port={ev.get('dest_port')}  proto={ev.get('proto')}  "
                      f"pkts_toserver={flow.get('pkts_toserver')}  pkts_toclient={flow.get('pkts_toclient')}  "
                      f"bytes_toserver={flow.get('bytes_toserver')}  bytes_toclient={flow.get('bytes_toclient')}  "
                      f"state={flow.get('state')}  tcp={ev.get('tcp')}")
    print(f"[Done] {total} matching flows, showed {shown}")


if __name__ == "__main__":
    main()
