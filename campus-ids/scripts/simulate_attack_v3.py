"""
simulate_attack_v3.py
Sends a few BIG TCP flows (about 8 MB each) so the model sees them as anomalies.
Run this from ANOTHER device (laptop/phone with Python) on the same Wi-Fi,
NOT from the same PC that runs Suricata.
"""
import socket
import time

TARGET_IP = "192.168.50.190"   # <-- the LAN IP of the PC running the dashboard (check with ipconfig)
TARGET_PORT = 5000             # dashboard port (must be reachable)
FLOWS = 5
MB_PER_FLOW = 8

chunk = b"X" * 65536
chunks_needed = (MB_PER_FLOW * 1024 * 1024) // len(chunk)

for i in range(FLOWS):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((TARGET_IP, TARGET_PORT))
        for _ in range(chunks_needed):
            sock.sendall(chunk)
        print(f"[+] Flow {i+1}: sent {MB_PER_FLOW} MB")
    except Exception as e:
        print(f"[!] Flow {i+1} FAILED: {e}")   # if you see this, the traffic never reached the PC
    finally:
        sock.close()
    time.sleep(1)
