# Lab setup for attack testing

All attack testing is done in a small controlled lab, as required by the client (the live campus network is out of scope).

## Machines

| Machine | Role | Address in our test |
|---|---|---|
| Windows PC | Target. Runs Suricata, the Flask dashboard and the browser | 192.168.50.190 |
| Kali Linux VM (VMware Workstation Player) | Attacker | 192.168.50.204 |

The Kali VM network adapter must be set to **Bridged**. In NAT or Host-only mode the traffic never goes through the Wi-Fi adapter that Suricata is listening on, so Suricata cannot see it.
Check with `ip a` in Kali: the address should be in the same subnet as the Windows PC (here `192.168.50.x`).

## One-time setup on the Windows PC

1. Copy `suricata/rules/campus-ids.rules` into `C:\Program Files\Suricata\rules\`.
2. In `suricata.yaml`, add `- campus-ids.rules` under `rule-files:` and make sure `alert` is listed under the `eve-log` types.
3. Test the config in an Administrator terminal: `suricata.exe -T -c suricata.yaml`. It should say the rules loaded with 0 failed.
4. Set `OWN_IPS` at the top of `dashboard/app.py` to the PC's own LAN IP, so the PC's normal outgoing traffic is not reported.

Tip: edit the rules file with an editor that saves plain text. Saving it with the wrong encoding made Suricata load 0 rules once ("no rules were loaded").

## Attack commands (run in Kali)

```bash
# 1. Ping
ping -c 4 192.168.50.190

# 2. Port scan (SYN scan, ports 1-1000)
sudo nmap -sS -p 1-1000 192.168.50.190

# 3. SYN flood (500 SYN packets, one every 0.01 s)
sudo hping3 -S -p 80 -i u10000 -c 500 192.168.50.190
```

Only run these against our own test PC.

## First test run (3 Oct 2026, one run of each attack)

| Attack | What the dashboard showed |
|---|---|
| Ping | 1 Rule alert |
| nmap SYN scan | Rule alerts + 1 Stats alert "Port scan" |
| hping3 SYN flood | Rule alert + 1 Stats alert "Connection flood" (High) |

The Stats alerts appeared about 5-8 seconds after the first Rule alert, because Suricata only writes a flow event when the flow ends.
The Isolation Forest (ML) layer did not flag any of the three attacks.

These are preliminary numbers from a single run per attack. Repeat each attack at least 3 times and record the results in the D5 testing report.
