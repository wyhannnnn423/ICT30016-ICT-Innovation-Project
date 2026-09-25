"""
simulate_attack.py
-------------------
Local security testing script: Simulates burst traffic and port probing 
to trigger IDS anomaly alerts.
"""

import socket
import time

# IMPORTANT: Change this to your real LAN IP address (do not use 127.0.0.1)
TARGET_HOST = "192.168.50.190"          
TARGET_PORTS = range(7000, 7050)   

print("[*] Initiating simulated anomalous traffic: Rapid Port Scanning...")
for port in TARGET_PORTS:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect((TARGET_HOST, port))
        s.sendall(b"X" * 1400)
        s.close()
    except Exception:
        pass
    time.sleep(0.01)
print("[v] Attack simulation completed. Traffic events logged by Suricata.")