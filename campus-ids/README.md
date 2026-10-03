# Campus IDS - ICT30016 (ICT Innovation Project)

A lightweight Intrusion Detection System (IDS) for campus networks. It reads network traffic from Suricata and shows alerts on a real-time web dashboard. Alerts come from three detection layers that work side by side.

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
| Stats | blue **Stats** | Port scan (15+ different ports on one host within 10 s), connection flood (150+ connections within 10 s) | `dashboard/stats_detector.py`, no training needed |
| ML | orange **ML** | Flows with unusual size or volume | Isolation Forest trained on our own baseline traffic |

The dashboard can filter by layer, shows a counter per layer, and exports the shown alerts to CSV.

## 🔄 Approach evolution

**Version 1 - Isolation Forest only.** We started with an unsupervised Isolation Forest, because we had no labelled attack data and the client wanted a lightweight tool. We trained it on about 29,500 flows (about 16.5 hours) of our own baseline traffic.

**What we found.** Tested against CIC-IDS2017 (Friday DDoS and PortScan files), the false-positive rate on normal traffic was low (0.8%), but the detection rate was **0% for DDoS and 0% for PortScan**. The model looks at one flow at a time (packets, bytes, duration). A port scan or flood is made of many small, normal-looking flows, so a single flow does not look unusual.

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
| BENIGN flows flagged (false positives) | 0.8% |
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
- The SYN-burst rule can fire on normal traffic from the monitored PC itself (for example when a video site opens many connections at once). `OWN_IPS` in `dashboard/app.py` hides alerts coming from that PC.
- The thresholds (15 ports, 150 connections, 20 SYNs in 5 s) are starting values. They are not tuned on a large dataset.
- Testing is done only in our own lab, as required by the client.

## ⚙️ Prerequisites
1. **Python 3.8+**
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
Open an **Administrator PowerShell**, find your LAN IPv4 address (for example `192.168.50.190`) and start Suricata:
```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -c suricata.yaml -i <YOUR_REAL_LAN_IP>
```
Leave this terminal open. Suricata writes events to `C:\Program Files\Suricata\log\eve.json`.

### Step 3: Train the ML model (first time only)
```powershell
# 1. Extract flow features from eve.json into a CSV
python suricata/read_suricata_flows.py --input "C:\Program Files\Suricata\log\eve.json" --output data/suricata_flow_features.csv

# 2. Train the Isolation Forest and save the scaler
python model/train_model.py --input data/suricata_flow_features.csv --model_out model/ids_model.joblib --scaler_out model/ids_scaler.joblib
```

### Step 4: Launch the dashboard
Before starting, open `dashboard/app.py` and set `OWN_IPS` to the LAN IP of this PC. Then:
```powershell
cd dashboard
python app.py
```
Open **http://127.0.0.1:5000** in your browser.

### Step 5: Run the attack tests (from the Kali VM)
```bash
ping -c 4 <TARGET_IP>
sudo nmap -sS -p 1-1000 <TARGET_IP>
sudo hping3 -S -p 80 -i u10000 -c 500 <TARGET_IP>
```
Alerts appear on the dashboard without a page refresh. Details are in `docs/lab-setup.md`.

> The older `scripts/simulate_attack*.py` scripts send large volumes of data to trigger the ML layer. Run them from another device, not from the PC that runs Suricata.

### Step 6: Cross-dataset evaluation (ML layer)
```powershell
python evaluation/evaluate_cicids.py --input evaluation/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv evaluation/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --model model/ids_model.joblib --scaler model/ids_scaler.joblib --out evaluation/cicids_evaluation.csv
```
The CIC-IDS2017 CSV files are large and are not stored in this repo. Download them from the official CIC-IDS2017 page and place them in `evaluation/`.

## 🔧 Settings you may want to change
In `dashboard/app.py`:

| Setting | Meaning | Default |
|---|---|---|
| `OWN_IPS` | LAN IP(s) of the monitored PC. Rule and Stats alerts from these sources are skipped | `192.168.50.190` |
| `SCAN_PORTS` | Different ports on one host within the window that count as a port scan | 15 |
| `FLOOD_FLOWS` | Connections from one source within the window that count as a flood | 150 |
| `STATS_WINDOW_SEC` | Length of the look-back window | 10 s |
| `STATS_COOLDOWN_SEC` | Minimum time before the same source raises the same Stats alert again | 30 s |

## 🛑 Safe Shutdown Procedure
1. **Dashboard:** press `Ctrl + C` in the terminal running `app.py`.
2. **Suricata:** press `Ctrl + C` in the Administrator terminal and wait 3-5 seconds until it prints `Engine shut down`.

## ⚠️ Troubleshooting
* **Permission denied errors:** run PowerShell as Administrator.
* **"no rules were loaded":** the rules file was probably saved with the wrong encoding or a rule was split over two lines. Keep every rule on one line and save as plain text.
* **No alerts from attacks:** make sure the attacker is on the same LAN (Kali must be in **Bridged** mode) and that the target is your real LAN IP. Npcap cannot capture `127.0.0.1` (loopback) traffic.
* **No alerts at all after starting:** start `app.py` *before* the attack. The dashboard only reads *new* lines of `eve.json`.
* **Alerts from your own PC:** add its LAN IP to `OWN_IPS`.
