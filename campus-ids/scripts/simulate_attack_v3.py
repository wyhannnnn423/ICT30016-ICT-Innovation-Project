"""
simulate_attack_v3.py
Sends large TCP flows to the target so the ML layer can flag them.
Run it from the Kali VM (or another device), NOT from the target PC itself.

Usage:
    python3 simulate_attack_v3.py <target_ip> [port]
Example:
    python3 simulate_attack_v3.py 10.95.197.181 5000
"""
import socket
import sys
import time

TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.50.190"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
FLOWS = 15
CHUNK = b"MASSIVE_TCP_ANOMALY_DATA" * 2500   # about 60 KB per send
CHUNKS_PER_FLOW = 20                         # about 1.2 MB per flow


def send_flow():
    """Send one big TCP flow. Returns the number of bytes sent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    sent = 0
    try:
        sock.connect((TARGET_IP, TARGET_PORT))
        for _ in range(CHUNKS_PER_FLOW):
            sock.sendall(CHUNK)
            sent += len(CHUNK)
    finally:
        sock.close()  # FIN lets Suricata close the flow
    return sent


def main():
    print(f"[*] Target: {TARGET_IP}:{TARGET_PORT}")
    ok = 0
    for i in range(FLOWS):
        try:
            sent = send_flow()
            ok += 1
            print(f"[+] Flow #{i + 1}: sent {sent} bytes")
        except Exception as e:
            print(f"[-] Flow #{i + 1} FAILED: {e}")
        time.sleep(1.5)

    print(f"\n[*] {ok}/{FLOWS} flows sent.")
    if ok == 0:
        print("[!] Nothing reached the target. Check:")
        print("    1. Is the target IP the PC's CURRENT IP? (see the dashboard)")
        print("    2. Are the attacker and the target on the same network?")
        print("    3. Is the dashboard listening on 0.0.0.0 and is port 5000 allowed in Windows Firewall?")


if __name__ == "__main__":
    main()
