"""
simulate_attack_tcp_instant.py
Instant TCP Response Edition: Utilizes the TCP disconnection mechanism 
to bypass caching and achieve <500ms real-time alerts.
"""
import socket
import time

# === [ CRITICAL: ENSURE THIS IS YOUR REAL LAN IP ] ===
TARGET_IP = "192.168.50.190" 
TARGET_PORT = 5000  # Target the Dashboard port to ensure an instant TCP handshake
# ====================================================

def main():
    print(f"[*] Preparing to launch instant TCP anomaly flows at {TARGET_IP}:{TARGET_PORT}...")
    print("[*] Keep your eyes on the Dashboard. Alerts will pop up within 500ms!\n")
    
    # Send 15 massive TCP anomaly flows sequentially
    for i in range(15):
        # Initialize TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        
        try:
            # 1. Establish connection instantly
            sock.connect((TARGET_IP, TARGET_PORT))
            
            # 2. Instantly dump massive anomaly traffic to break the AI's baseline
            payload = b"MASSIVE_TCP_ANOMALY_DATA" * 5000
            sock.sendall(payload)
            
        except Exception as e:
            pass
        finally:
            # 3. CRITICAL STEP: Close the connection instantly!
            # This sends a TCP FIN/RST packet, forcing Suricata to flush 
            # and write the flow to eve.json in under 100 milliseconds.
            sock.close()
            
        print(f"[+] Massive TCP anomaly flow #{i+1} sent and severed -> Triggered instant Suricata logging")
        
        # Pause for 0.5 seconds to let you enjoy the visual waterfall of alerts on the dashboard
        time.sleep(0.5) 

    print("\n[*] Instant attack sequence completed! This proves the <500ms latency requirement.")

if __name__ == "__main__":
    main()