# Campus IDS - ICT30016 (ICT Innovation Project)

A lightweight Intrusion Detection System (IDS) for campus networks. It reads network traffic from Suricata and shows alerts on a real-time web dashboard. Alerts come from three detection layers that work side by side.

The dashboard is the main contribution of the project. It brings the three layers together on one screen, draws live charts, and looks after its own set-up: it finds the PC's IP address by itself, follows the PC when it joins another network, and warns when Suricata is listening on the wrong one.

## 👥 Team Members
- **Jane Yan Zhen YU** (Team Leader)
- **Yan Han WONG**
- **Neville Zi Yang**
- **Bruce Gee Yick WONG**

## 🧩 How it works

```
Network traffic -> Suricata -> eve.json -> Flask app (dashboard/app.py) -> live dashboard
                                              |- Rule layer   (Suricata signature alerts)
                                              |- Stats layer  (port scan / connection flood per source IP)
                                              '- ML layer     (Isolation Forest on flow features)
```

| Layer | Dashboard label | What it detects | How |
|---|---|---|---|
| Rule | red **Rule** | Known patterns, e.g. ping, bursts of SYN packets | Suricata rules in `suricata/rules/campus-ids.rules` |
| Stats | blue **Stats** | Port scan (15+ different ports on one host within 10 s), connection flood (150+ connections within 10 s). Both limits can be changed | `dashboard/stats_detector.py`, no training needed |
| ML | orange **ML** | Flows with unusual size or volume | Isolation Forest trained on our own baseline traffic |

## 🖥️ The dashboard

Open **http://127.0.0.1:5000** after starting it (see the workflow below).

- **Timeline.** Alerts of the last 10 minutes in bars of 30 seconds, stacked by detection layer. It keeps sliding even when nothing arrives.
- **Legend as filter.** The three buttons above the timeline show how many alerts each layer raised. Click one to show only that layer in the table, click again to show all.
- **Share by detection layer** (ring chart) and **Busiest sources** (the five addresses that raised the most alerts, coloured by their main alert type).
- **Alert table** with time, layer, source and destination IP, protocol, detail, severity and anomaly score. *Export to CSV* saves the rows that are currently shown.
- **Settings panel.** Change this PC's IP address, trusted IPs or ranges, and the scan and flood limits without restarting. Values are kept in `data/settings.json`.
- **Automatic IP.** The IP address of the monitored PC is detected at start-up and followed when the PC joins another network (checked every 5 seconds). Alerts coming from the PC itself are hidden, because its own browsing is not an attack.
- **Capture check.** A banner under the title tells whether Suricata is delivering traffic of this PC: green means yes; amber means Suricata is running but listens on another network, or sends nothing; grey means the dashboard has just started.
- **Attack commands.** The Settings panel lists the Kali commands with the target IP already filled in, with a copy button.

Other devices can open the dashboard too when it is started with `--host 0.0.0.0`, but only a browser on the PC that runs it can change settings.

## 🔄 Approach evolution

**Version 1 - Isolation Forest only.** We started with an unsupervised Isolation Forest, because we had no labelled attack data and the client wanted a lightweight tool. We trained it on about 29,500 flows (about 16.5 hours) of our own baseline traffic.

**What we found.** Tested against CIC-IDS2017 (Friday DDoS and PortScan files), the false-positive rate on normal traffic was low (0.02%), but the detection rate was **0% for DDoS and 0% for PortScan**. The model looks at one flow at a time (packets, bytes, duration). A port scan or flood is made of many small, normal-looking flows, so a single flow does not look unusual.

**Version 2 - hybrid detection (current).** Instead of replacing the model, we kept the Isolation Forest and added two layers that are good at what it misses:
- the **Rule layer**: Suricata already matches known patterns, so we only added two small rules;
- the **Stats layer**: counts connections per source IP in a short time window.

The dashboard is where the three layers come together. This also kept the work small: no new training data was needed.

**Alternatives we looked at and did not use.**
- *Supervised model (Random Forest) trained in our lab.* Still possible as future work. It needs labelled lab traffic first.
- *Pre-trained third-party IDS models.* Many are trained on the CICFlowMeter feature set (dozens of columns). Suricata gives us fewer features, so they would not fit our pipeline without a new feature extractor.
- *Complete open-source systems* (for example Suri-Oculus, which also uses an Isolation Forest on Suricata data and has its own dashboard). They would replace our work instead of supporting it.

## 📊 Results so far

CIC-IDS2017 cross-dataset test (ML layer only, trained on our baseline):

| Test data | Result |
|---|---|
| BENIGN flows flagged (false positives) | 0.02% |
| DDoS detected | 0% |
| PortScan detected | 0% |

Lab test with a Kali VM attacking the target PC (see `docs/lab-setup.md`), **one run per attack, preliminary**:

| Attack | Rule layer | Stats layer | ML layer |
|---|---|---|---|
| Ping | detected | - | not detected |
| nmap SYN scan | detected | detected (Port scan) | not detected |
| hping3 SYN flood | detected | detected (Connection flood) | not detected |

Stats alerts appeared about 5-8 seconds after the first Rule alert.

**Known limitations**
- The ML layer alone does not detect scans or floods (see above). It also flagged some of our own video-streaming and IPv6 traffic.
- The SYN-burst rule can fire on normal traffic from the monitored PC itself (for example when a video site opens many connections at once). The PC's own address is therefore hidden automatically (see *Automatic IP* above).
- The thresholds (15 ports, 150 connections, 20 SYNs in 5 s) are starting values. They are not tuned on a large dataset.
- The charts and the table start empty every time the page is opened or refreshed. Alerts are not stored.
- The dashboard page loads the Socket.IO script from a public CDN, so the live updates need an internet connection.
- Automatic IP follows one address (the one used to reach the network). A PC that uses Wi-Fi and Ethernet at the same time has to add the second address under *Trusted IPs*.
- Suricata cannot follow a network change by itself: after the PC joins another network it has to be restarted (see below).
- Testing is done only in our own lab, as required by the client.

## ⚙️ Prerequisites
1. **Python 3**, a recent version. `requirements.txt` pins `scikit-learn==1.9.0`, which does not support old Python versions. Check yours with `python --version`.
2. **Suricata (Windows)**, installed with **Npcap** (WinPcap API-compatible mode), to capture local network traffic on Windows.
3. **Suricata configuration**: in `suricata.yaml`, `eve-log` must log both `flow` and `alert` event types, and `campus-ids.rules` must be listed under `rule-files:`.
4. *(For attack testing)* A Kali Linux VM in VMware with the network adapter set to **Bridged**. See `docs/lab-setup.md`.

## 📦 Installation
```bash
pip install -r requirements.txt
```

## 🚀 Execution Workflow

### Step 1: Set up the rules (first time only)
Copy `suricata/rules/campus-ids.rules` to `C:\Program Files\Suricata\rules\`, add it to `rule-files:` in `suricata.yaml`, then test the config in an Administrator terminal:
```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -T -c suricata.yaml
```
It should report the rules loaded with 0 failed.

### Step 2: Start the Suricata capture engine
Open an **Administrator PowerShell** in the project folder. The script finds the network the PC is using right now and starts Suricata on it, so no IP address has to be typed:
```powershell
.\scripts\start_suricata.ps1 -ShowOnly    # optional: only show which address it would use
.\scripts\start_suricata.ps1
```
Leave this terminal open. Suricata writes events to `C:\Program Files\Suricata\log\eve.json`. Use `-Ip <address>` to force an address, or `-SuricataDir` if Suricata is installed elsewhere.

Manual alternative: `cd "C:\Program Files\Suricata"` and `.\suricata.exe -c suricata.yaml -i <YOUR_REAL_LAN_IP>`.

### Step 3: Train the ML model (first time only)
```powershell
# 1. Extract flow features from eve.json into a CSV
python suricata/read_suricata_flows.py --input "C:\Program Files\Suricata\log\eve.json" --output data/suricata_flow_features.csv

# 2. Train the Isolation Forest and save the scaler
python model/train_model.py --input data/suricata_flow_features.csv --model_out model/ids_model.joblib --scaler_out model/ids_scaler.joblib
```

### Step 4: Launch the dashboard
From the project folder:
```powershell
python dashboard/app.py
```
Open **http://127.0.0.1:5000** in your browser. The terminal prints the LAN IP it detected for this PC. Check the banner under the title: it should turn green once Suricata delivers traffic. Click **Settings** to review the values.

### Step 5: Run the attack tests (from the Kali VM)
The Settings panel shows these commands with the target address filled in. Run them from the Kali VM, never from the PC that runs Suricata:
```bash
ping -c 4 <TARGET_IP>
sudo nmap -sS -p 1-1000 <TARGET_IP>
sudo hping3 -S -p 80 -i u10000 -c 500 <TARGET_IP>
```
Alerts appear on the dashboard without a page refresh. Details are in `docs/lab-setup.md`.

> Run attack tests only on a network you control, for example your own home network or a phone hotspot. Shared Wi-Fi often blocks traffic between devices, and scans may be noticed by the network administrators.

> The older `scripts/simulate_attack*.py` scripts send large volumes of data to trigger the ML layer. Run them from another device, not from the PC that runs Suricata.

### Step 6: Cross-dataset evaluation (ML layer)
```powershell
python evaluation/evaluate_cicids.py --input evaluation/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv evaluation/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --model model/ids_model.joblib --scaler model/ids_scaler.joblib --out evaluation/cicids_evaluation.csv
```
The CIC-IDS2017 CSV files are large and are not stored in this repo. Download them from the official CIC-IDS2017 page and place them in `evaluation/`.

## 🔁 When the PC joins another network

1. The dashboard follows the new address within about 5 seconds. The line under the title and the Settings panel update by themselves.
2. Suricata is still listening on the old network, so the banner turns amber ("none involve this PC"). Stop Suricata with `Ctrl + C` and run `.\scripts\start_suricata.ps1` again.
3. On the Kali VM, get a new address in the new network and check it:
   ```bash
   sudo nmcli device disconnect eth0 && sudo nmcli device connect eth0
   ip a
   ```
   The attack commands in the Settings panel already use the new target address.

## 🔧 Settings

Everything below can be changed in the dashboard's **Settings** panel. Changes apply to new traffic immediately and are saved to `data/settings.json` (not committed to Git).

| Setting | Meaning | Default |
|---|---|---|
| This PC's IP address | Rule and Stats alerts from it are hidden. *Detect automatically* is on by default | detected |
| Trusted IPs or ranges | Other sources to hide, for example the router or a phone. Ranges like `192.168.50.0/28` are allowed | none |
| Port scan: different ports | Different ports on one host within the window that count as a port scan (2 to 1000) | 15 |
| Flood: connections | Connections from one source within the window that count as a flood (10 to 100000) | 150 |
| Time window | Look-back window in seconds (1 to 300) | 10 |
| Cooldown | Seconds before the same source raises the same Stats alert again (0 to 3600) | 30 |

The same limits can be given on the command line (`python dashboard/app.py --help` lists all options): `--own-ip`, `--scan-ports`, `--flood-flows`, `--window`, `--cooldown`, `--eve`, `--host`, `--port`. Order of precedence: built-in defaults, then the settings file, then the command line. Giving `--own-ip` switches automatic IP off. More details are in `docs/dashboard-settings.md`.

## 🧪 Tests
```bash
python tests/test_settings.py
```
Unit tests for settings validation, IP matching, live setting changes, the automatic IP, the capture check and the settings web API. They need Flask but no Suricata.

## 📁 Project layout
```
dashboard/        Flask app, detection layers, settings, web page (templates/dashboard.html)
suricata/         Suricata rules (rules/) and the script that turns eve.json into flow features
model/            Isolation Forest training script and the saved model and scaler
evaluation/       CIC-IDS2017 evaluation script and results
scripts/          start_suricata.ps1, replay_demo.py, attack simulation scripts
docs/             lab-setup.md, suricata-config.md, dashboard-settings.md
tests/            unit tests
data/             baseline flow features (raw captures and settings.json are not committed)
```

## 🛑 Safe Shutdown Procedure
1. **Dashboard:** press `Ctrl + C` in the terminal running `app.py`.
2. **Suricata:** press `Ctrl + C` in the Administrator terminal and wait 3-5 seconds until it prints `Engine shut down`.

## ⚠️ Troubleshooting
* **Permission denied errors:** run PowerShell as Administrator.
* **"no rules were loaded":** the rules file was probably saved with the wrong encoding or a rule was split over two lines. Keep every rule on one line and save as plain text (write it with PowerShell `Set-Content -Encoding ascii` rather than Notepad).
* **Banner says "No new events":** Suricata is not running or writes somewhere else. Check the Suricata terminal for errors and the `--eve` path.
* **Banner says "none involve this PC":** Suricata listens on another network. Restart it with `.\scripts\start_suricata.ps1`.
* **No alerts from attacks:** make sure the attacker is on the same LAN (Kali must be in **Bridged** mode), that the target is your real LAN IP, and that the network does not isolate devices from each other. Npcap cannot capture `127.0.0.1` (loopback) traffic.
* **No alerts at all after starting:** start `app.py` *before* the attack. The dashboard only reads *new* lines of `eve.json`.
* **Alerts from your own PC:** open Settings and check that the address of this PC is listed. Add other devices under Trusted IPs.
* **Settings cannot be saved:** settings can only be changed in a browser on the PC that runs the dashboard.
