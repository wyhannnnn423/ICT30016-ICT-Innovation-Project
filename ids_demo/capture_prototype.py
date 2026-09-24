"""
Campus IDS — Flow-Based Capture Engine Prototype
--------------------------------------------------
Captures live packets and groups them into IPv4 flows (5-tuple:
src_ip, dst_ip, src_port, dst_port, protocol), then prints basic
flow statistics when a flow goes idle. This matches Goal 1 of the
report: "group live IPv4 traffic into complete network flows" and
"extract statistical metrics such as packet speed and average size."

Requirements:
    pip install scapy

Run with admin/root privileges (needed for raw packet capture):
    Windows: run terminal as Administrator
    Mac/Linux: sudo python3 capture_prototype.py

This is a STARTING POINT, not the final capture engine — it prints
flow stats to the console instead of feeding them into the model.
Once this works, the next step is to replace the print() with a
call to feature_extraction.py / model pipeline.
"""

import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

# How long (seconds) a flow can be idle before we consider it "finished"
FLOW_TIMEOUT = 5

# flow_key -> {start_time, last_time, packet_count, total_bytes}
flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "packet_count": 0,
    "total_bytes": 0,
})


def get_flow_key(pkt):
    """Build a 5-tuple key to identify which flow this packet belongs to."""
    if IP not in pkt:
        return None

    proto = pkt[IP].proto  # 6 = TCP, 17 = UDP
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if TCP in pkt:
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
    else:
        src_port, dst_port = 0, 0

    return (src_ip, dst_ip, src_port, dst_port, proto)


def handle_packet(pkt):
    key = get_flow_key(pkt)
    if key is None:
        return

    now = time.time()
    pkt_size = len(pkt)
    flow = flows[key]

    if flow["start_time"] is None:
        flow["start_time"] = now

    flow["last_time"] = now
    flow["packet_count"] += 1
    flow["total_bytes"] += pkt_size

    check_expired_flows(now)


def check_expired_flows(now):
    """Print and remove flows that have gone idle for FLOW_TIMEOUT seconds."""
    expired_keys = [
        key for key, f in flows.items()
        if now - f["last_time"] > FLOW_TIMEOUT
    ]

    for key in expired_keys:
        f = flows.pop(key)
        duration = max(f["last_time"] - f["start_time"], 0.001)  # avoid /0
        avg_size = f["total_bytes"] / f["packet_count"]
        pkt_rate = f["packet_count"] / duration

        src_ip, dst_ip, src_port, dst_port, proto = key
        print(
            f"[FLOW] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
            f"(proto={proto}) | packets={f['packet_count']} "
            f"| avg_size={avg_size:.1f}B | rate={pkt_rate:.2f} pkt/s "
            f"| duration={duration:.2f}s"
        )
        # TODO: instead of printing, pass this feature dict to
        # feature_extraction.py / the Isolation Forest model here.


if __name__ == "__main__":
    print("Starting capture... press Ctrl+C to stop.")
    try:
        sniff(prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopped. Flushing remaining flows...")
        check_expired_flows(time.time() + FLOW_TIMEOUT + 1)
