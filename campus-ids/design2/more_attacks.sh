#!/usr/bin/env bash
# more_attacks.sh  (Design 2, run on the Kali VM, next to attack_logger.sh)
# Runs a list of different lab attacks one after another, 40 s apart, and writes one label line
# per attack to attack_log.csv (through attack_logger.sh).
# ONLY use it against your own lab PC (the one running Suricata), as the project scope says.
#
# Usage:   ./more_attacks.sh [target_ip] [kali_ip]
# Default: ./more_attacks.sh 192.168.50.190 192.168.50.204
# Takes about 20 minutes. Keep Suricata running on the Windows PC the whole time.

cd "$(dirname "$0")" || exit 1
TARGET="${1:-192.168.50.190}"
KALI_IP="${2:-192.168.50.204}"
PAUSE=40

echo "Target: $TARGET   Kali: $KALI_IP"
echo "Kali clock (must be right):  $(TZ=Asia/Kuala_Lumpur date)"
sudo -v || exit 1            # ask for the sudo password once, now

run() {                      # run <label> <command...>
  local label="$1"; shift
  echo; echo "=== $label ==="
  ./attack_logger.sh "$label" "$KALI_IP" "$@"
  echo "--- pause ${PAUSE}s so the windows do not mix"
  sleep "$PAUSE"
}

# --- port scans: other speeds, scan types and port ranges ---
run portscan_top100   sudo nmap -sS --top-ports 100 "$TARGET"
run portscan_t5       sudo nmap -sS -T5 -p 1-3000 "$TARGET"
run portscan_connect  sudo nmap -sT -p 1-1000 "$TARGET"
run portscan_fin      sudo nmap -sF -p 1-1000 "$TARGET"
run portscan_service  sudo nmap -sV -p 1-200 "$TARGET"
run portscan_slow_T2  sudo nmap -sS -T2 -p 1-100 "$TARGET"

# --- SYN floods: other speeds and ports (timeout stops hping3 after N seconds) ---
run synflood_fast_80    sudo timeout 15 hping3 -S -p 80 --flood "$TARGET"
run synflood_fast_443   sudo timeout 15 hping3 -S -p 443 --flood "$TARGET"
run synflood_1000pps    sudo timeout 15 hping3 -S -p 80 -i u1000 "$TARGET"
run synflood_100pps     sudo timeout 20 hping3 -S -p 80 -i u10000 "$TARGET"
run synflood_20pps      sudo timeout 20 hping3 -S -p 80 -i u50000 "$TARGET"
run synflood_10pps      sudo timeout 20 hping3 -S -p 80 -i u100000 "$TARGET"

# --- attack types the model has never seen (tests "fails on unseen attacks") ---
run udpscan    sudo nmap -sU --top-ports 50 --max-retries 1 "$TARGET"
run udpflood   sudo timeout 15 hping3 --udp -p 53 --flood "$TARGET"
run icmpflood  sudo timeout 15 hping3 --icmp --flood "$TARGET"

echo; echo "Done. The label lines are in attack_log.csv:"
cat attack_log.csv
