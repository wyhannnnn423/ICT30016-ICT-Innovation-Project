"""
simulate_attack.py
-------------------
Local security testing script: Simulates burst traffic and port probing 
to trigger IDS anomaly alerts.
"""
import socket
import time

TARGET_HOST = "127.0.0.1"          # Local loopback address: safe and isolated
TARGET_PORTS = range(7000, 7050)   # Rapidly probe 50 non-standard ports

print("[*] Initiating simulated anomalous traffic: Rapid Port Scanning...")

for port in TARGET_PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)         # High-frequency packet transmission
        s.connect((TARGET_HOST, port))
        # Inject abnormal burst payloads that deviate from regular traffic profiles
        s.sendall(b"X" * 1400)
        s.close()
    except Exception:
        pass
    time.sleep(0.01)

print("[✓] Attack simulation completed. Traffic events logged by Suricata.")