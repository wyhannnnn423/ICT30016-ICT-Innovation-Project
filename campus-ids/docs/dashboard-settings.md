# Dashboard Settings panel and automatic network handling

The dashboard has a **Settings** button (next to *Export to CSV*). Nothing has to be typed in a terminal, and changes apply without restarting. The IP address of the monitored PC is handled automatically, because it changes whenever the PC joins another network.

## What the dashboard does by itself

| Situation | What happens |
|---|---|
| Dashboard starts | The LAN IP of this PC is detected and its own alerts are hidden (the PC's own browsing is not an attack). |
| The PC joins another network while the dashboard runs | The new IP is picked up within about 5 seconds. The summary line and the panel update on their own. |
| Suricata listens on the wrong network | A banner under the summary line says so (see *Capture check*). |
| A demo is shown | The Settings panel lists the Kali commands with the target IP already filled in. |

## Capture check (banner)

The banner under the summary line compares what Suricata delivers with this PC's IP:

| Colour | Meaning |
|---|---|
| green | Traffic of this PC is arriving. Everything is fine. |
| grey | Dashboard just started, or no IP is set. |
| amber, "none involve this PC" | Suricata is running but listens on another network, for example it was started before the PC changed network. Stop it with Ctrl+C and start it again with `scripts\start_suricata.ps1`. |
| amber, "No new events" | Nothing arrived for a minute. Suricata may not be running (or the network is simply quiet). |

It is a hint, not an alarm: if Suricata monitors a mirror port that never carries this PC's traffic, "none involve this PC" is expected.

## Starting Suricata without typing the IP

`scripts\start_suricata.ps1` finds the network adapter that carries the default route and starts Suricata on it. Run it in an Administrator PowerShell:
```powershell
.\scripts\start_suricata.ps1               # detect, then start Suricata
.\scripts\start_suricata.ps1 -ShowOnly     # only show which address would be used
.\scripts\start_suricata.ps1 -Ip 192.168.1.20   # force an address
```
Suricata cannot follow a network change by itself, so after the PC joins another network, stop Suricata (Ctrl+C) and run the script again. The dashboard banner tells you when this is needed.

## Settings in the panel

| Setting | Meaning | Allowed values |
|---|---|---|
| This PC's IP address | Rule and Stats alerts from this address are hidden. **Detect automatically** is on by default; untick it to type an address yourself. | one IP address (IPv4 or IPv6) |
| Trusted IPs or ranges | Other sources to hide: router, a phone, a lab server. | IPs or ranges such as `192.168.50.0/28`, separated by commas. IPv4 ranges must be /8 or smaller, IPv6 /32 or smaller |
| Port scan: different ports | Different ports on one host within the time window that count as a port scan | 2 - 1000 (default 15) |
| Flood: connections | Connections from one source within the time window that count as a flood | 10 - 100000 (default 150) |
| Time window | How far back the detector looks, in seconds | 1 - 300 (default 10) |
| Cooldown | Seconds before the same source raises the same alert again | 0 - 3600 (default 30) |

The ML layer is not affected by the ignore lists. Invalid entries are rejected with a message and nothing is changed. Only one address is followed in automatic mode. A PC that uses Wi-Fi and Ethernet at the same time can add the second address under *Trusted IPs*.

## Where the values come from

At start-up the dashboard combines three sources. A later one overrides an earlier one:

1. built-in defaults,
2. the settings file `data/settings.json`, written by the Save button (not committed to Git),
3. command-line options such as `--own-ip` and `--scan-ports` (still supported, useful for scripts).

Giving `--own-ip` switches automatic mode off. A settings file from before automatic mode existed that already holds an address also keeps it.

## Who may change settings

Everyone who can open the dashboard can **see** the settings and the banner. Only a browser on **the PC that runs the dashboard** can **change** them. This matters when the dashboard is started with `--host 0.0.0.0`: other devices get a read-only panel. Requests must also be JSON and carry a `localhost` or IP-address Host header, which blocks simple cross-site and DNS-rebinding attempts from a web page.

## Technical notes
- `dashboard/ids_settings.py` - validation, IP matching, settings file, auto-detection (no Flask).
- `dashboard/settings_api.py` - `GET /api/status`, `GET` and `POST /api/settings`.
- `Detector.apply_settings()`, `refresh_own_ip()` and `capture_status()` in `dashboard/detection.py`.
- `watch_network()` in `dashboard/app.py` checks the PC's IP every 5 seconds.
- Tests: `python tests/test_settings.py` (the API tests need Flask only).
