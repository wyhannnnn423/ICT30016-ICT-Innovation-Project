#!/usr/bin/env bash
# attack_logger.sh  (Design 2, run on the Kali VM)
# Runs one attack command and writes the labels.csv line for it (start, end, attacker IP, label)
# in Malaysia time, so you do not have to note the times by hand.
#
# Usage:   ./attack_logger.sh <label> <kali_ip> <command...>
# Example: ./attack_logger.sh portscan 192.168.50.204 sudo nmap -sS -p 1-100 192.168.50.190
#          ./attack_logger.sh synflood 192.168.50.204 sudo hping3 -S -p 80 -i u5000 -c 500 192.168.50.190
# The line is printed and appended to attack_log.csv (same folder). Copy the lines to the end of
# design2/labels.csv on the Windows PC.
# Check first that Kali's clock is right:  TZ=Asia/Kuala_Lumpur date

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <label> <kali_ip> <command...>"
  exit 1
fi

label="$1"
ip="$2"
shift 2

fmt='+%Y-%m-%d %H:%M:%S'
start=$(TZ=Asia/Kuala_Lumpur date "$fmt")
"$@"
status=$?
end=$(TZ=Asia/Kuala_Lumpur date "$fmt")

echo "$start,$end,$ip,$label" | tee -a attack_log.csv
echo "[attack_logger] command exit status: $status"
