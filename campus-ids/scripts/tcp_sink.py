"""
tcp_sink.py
Listens on a TCP port and throws away whatever it receives, so that
simulate_attack_v3.py has somewhere to send its big flows.
Run it on the target PC (the one running Suricata), then run the attack from Kali.

Usage:
    python scripts/tcp_sink.py [port]        (default 9000)
If Windows asks about the firewall, allow it on the private network.
"""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000


def drain(conn):
    with conn:
        while conn.recv(65536):
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(16)
    print(f"[*] Listening on TCP {PORT}. Press Ctrl+C to stop.")
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=drain, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
