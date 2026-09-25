# Campus IDS - Complete Setup & Execution Manual

A lightweight, AI-driven Intrusion Detection System designed for campus networks.

This system captures real-time network traffic via **Suricata**, extracts IPv4 flow features in memory, and performs unsupervised anomaly detection using an **Isolation Forest** model. Detected threats are pushed instantly to a real-time web dashboard using **WebSocket / SocketIO** integration.

---

## Team Members

- **Jane Yan Zhen YU** — Team Leader
- **Yan Han WONG**
- **Neville**
- **Bruce Gee Yick WONG**

---

# Phase 1: Prerequisites & Installation

## 1. Python Environment

Ensure that **Python 3.8+** is installed on your computer.

Install the required Python dependencies:

```bash
pip install pandas scikit-learn joblib flask flask-socketio eventlet
```

These packages are used for:

- **Pandas** — Data processing and feature extraction
- **Scikit-learn** — Machine learning and Isolation Forest
- **Joblib** — Saving and loading trained models
- **Flask** — Web dashboard backend
- **Flask-SocketIO** — Real-time communication
- **Eventlet** — Asynchronous networking support

---

## 2. Download and Install Suricata on Windows

Download and install Suricata for Windows.

During installation, make sure the required packet capture driver is installed.

### Npcap Requirement

Suricata requires **Npcap** to capture network traffic on Windows.

During the Npcap installation:

- Install Npcap when prompted.
- If available, enable **"WinPcap API-compatible Mode"**.

Npcap provides the packet capture functionality required for Suricata to monitor physical network interfaces.

---

## 3. Configure Suricata

Navigate to:

```text
C:\Program Files\Suricata\
```

Open:

```text
suricata.yaml
```

You may need **Administrator privileges** to save changes to this file.

### EVE JSON Logging

Make sure the `eve-log` output is enabled and configured to record `flow` events.

The system uses:

```text
eve.json
```

as the main source of network flow information.

### Missing Rules Warning

If Suricata displays errors about missing:

```text
emerging-*.rules
```

files during startup, these errors can generally be ignored for this project.

This AI-driven IDS relies on **statistical network flow features** from `eve.json` rather than traditional signature-based rule matching.

---

# Phase 2: AI Model Generation

This phase is required **only during the first-time setup** or when retraining the AI model using a new baseline traffic dataset.

The training process generates:

```text
model/ids_model.joblib
model/ids_scaler.joblib
```

## Step A: Extract Network Flow Features

Use an existing Suricata `eve.json` log to generate a CSV feature dataset:

```powershell
python suricata/read_suricata_flows.py --input "C:\Program Files\Suricata\log\eve.json" --output data/suricata_flow_features.csv
```

This extracts the relevant network flow features and saves them as:

```text
data/suricata_flow_features.csv
```

---

## Step B: Train the Isolation Forest Model

Train the AI model using the extracted features:

```powershell
python model/train_model.py --input data/suricata_flow_features.csv --model_out model/ids_model.joblib --scaler_out model/ids_scaler.joblib
```

After successful training, the following files should be available:

```text
model/
├── ids_model.joblib
└── ids_scaler.joblib
```

---

# Phase 3: System Execution Workflow

The system requires multiple terminal windows during execution.

The recommended workflow is:

```text
Terminal 1
    ↓
Suricata Traffic Capture
    ↓
eve.json
    ↓
Terminal 2
    ↓
Flask + AI Dashboard
    ↓
Real-Time Detection
    ↓
Terminal 3
    ↓
Attack Simulation
```

---

## Step 1: Identify Your Target Network Interface

Open **PowerShell** and run:

```powershell
ipconfig
```

Locate your active network adapter, such as:

- Wi-Fi
- Ethernet

Find the adapter's **IPv4 Address**.

Example:

```text
IPv4 Address. . . . . . . . . . . : 192.168.50.190
```

Your actual IP address may be different.

### Important: Do Not Use `127.0.0.1`

Do **not** use:

```text
127.0.0.1
```

for Suricata traffic capture or attack simulation.

`127.0.0.1` is the localhost / loopback interface. Windows Npcap does not capture loopback traffic in the same way as a physical network interface by default.

Using it may result in:

```text
No traffic
```

or:

```text
No events in eve.json
```

Use your actual LAN IPv4 address instead.

---

## Step 2: Start the Suricata Capture Engine

Open an **Administrator PowerShell** window.

Navigate to the Suricata installation directory:

```powershell
cd "C:\Program Files\Suricata"
```

Start Suricata:

```powershell
.\suricata.exe -c suricata.yaml -i <YOUR_REAL_LAN_IP>
```

Replace:

```text
<YOUR_REAL_LAN_IP>
```

with your actual IPv4 address.

For example:

```powershell
.\suricata.exe -c suricata.yaml -i 192.168.50.190
```

### Keep This Terminal Open

Do not close this terminal.

Suricata must continue running so that it can capture network traffic and write flow events to:

```text
C:\Program Files\Suricata\log\eve.json
```

---

## Step 3: Launch the Real-Time AI Dashboard

Open a **second PowerShell / terminal window**.

Navigate to the dashboard directory:

```powershell
cd dashboard
```

Start the Flask application:

```powershell
python app.py
```

The application will:

1. Start the Flask web server.
2. Monitor new entries in `eve.json`.
3. Extract network flow features.
4. Run the Isolation Forest model.
5. Detect anomalous traffic.
6. Send alerts through SocketIO.
7. Display alerts on the real-time dashboard.

Open your browser and visit:

```text
http://127.0.0.1:5000
```

---

## Step 4: Simulate a Cyber Attack

To test the IDS, open a **third PowerShell / terminal window**.

### Configure the Target Host

Open:

```text
simulate_attack.py
```

Find:

```python
TARGET_HOST = "192.168.50.190"
```

Replace the IP address with your actual LAN IPv4 address.

For example:

```python
TARGET_HOST = "192.168.50.190"
```

> **Important:** Use the same real LAN IP identified in Step 1.

### Run the Attack Simulation

Execute:

```powershell
python simulate_attack.py
```

The simulation generates rapid network connection attempts / port-scan traffic.

The resulting network flow features are captured by Suricata and processed by the AI model.

Detected anomalies should then be sent to the dashboard in real time without requiring a page refresh.

---

# Phase 4: Safe Shutdown Procedure

To safely stop the system and allow Suricata to finish writing its logs:

## 1. Stop the Dashboard

Go to the terminal running:

```text
python app.py
```

Press:

```text
Ctrl + C
```

---

## 2. Stop Suricata

Go to the **Administrator PowerShell** running Suricata.

Press:

```text
Ctrl + C
```

Wait approximately **3–5 seconds** for Suricata to finish flushing the remaining flow logs.

The console should eventually display a shutdown message such as:

```text
Engine shut down
```

Avoid immediately closing the terminal after pressing `Ctrl + C`.

---

# Troubleshooting

## Permission Denied Errors

### Problem

Suricata immediately crashes or displays errors involving:

```text
fast.log
eve.json
```

### Solution

Make sure Suricata is being started from an **Administrator PowerShell** window.

Try:

```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -c suricata.yaml -i <YOUR_REAL_LAN_IP>
```

---

## No Alerts Appearing on the Dashboard

### Problem

The dashboard starts successfully, but no alerts appear when running the attack simulation.

### Checklist

Make sure:

1. Suricata is running.
2. `eve.json` is being updated.
3. `app.py` was started before the attack simulation.
4. `TARGET_HOST` in `simulate_attack.py` is set to the correct LAN IP.
5. You are not using `127.0.0.1`.
6. The trained model files exist.

The file-monitoring process uses:

```python
os.SEEK_END
```

to start reading from the end of the existing log file.

Therefore, traffic generated **before the dashboard starts** may not be processed as new events.

### Recommended Startup Order

Always start the system in this order:

```text
1. Suricata
      ↓
2. Flask Dashboard
      ↓
3. Attack Simulation
```

---

## Python Path Syntax Warnings

### Problem

Python displays warnings such as:

```text
SyntaxWarning: invalid escape sequence '\P'
```

This can happen when Windows paths are written using normal Python strings.

### Incorrect

```python
"C:\Program Files\Suricata\log\eve.json"
```

### Recommended

Use a raw string:

```python
r"C:\Program Files\Suricata\log\eve.json"
```

Alternatively, use escaped backslashes:

```python
"C:\\Program Files\\Suricata\\log\\eve.json"
```

---

# Project Structure

A typical project structure should look similar to:

```text
Campus-IDS/
│
├── data/
│   └── suricata_flow_features.csv
│
├── dashboard/
│   └── app.py
│
├── model/
│   ├── train_model.py
│   ├── ids_model.joblib
│   └── ids_scaler.joblib
│
├── suricata/
│   └── read_suricata_flows.py
│
├── simulate_attack.py
│
└── README.md
```

---

# Quick Start

For an already-configured system, the normal execution process is:

### Terminal 1 — Suricata

Run **PowerShell as Administrator**:

```powershell
cd "C:\Program Files\Suricata"
.\suricata.exe -c suricata.yaml -i <YOUR_REAL_LAN_IP>
```

### Terminal 2 — Dashboard

```powershell
cd dashboard
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

### Terminal 3 — Attack Simulation

Make sure `TARGET_HOST` contains your real LAN IP, then run:

```powershell
python simulate_attack.py
```

---

# System Overview

The overall detection pipeline is:

```text
Network Traffic
      │
      ▼
   Suricata
      │
      ▼
   eve.json
      │
      ▼
Flow Feature Extraction
      │
      ▼
Feature Scaling
      │
      ▼
Isolation Forest
      │
      ▼
Anomaly Detection
      │
      ▼
Flask + SocketIO
      │
      ▼
Real-Time Web Dashboard
```

The system uses an **unsupervised machine learning approach**, meaning the Isolation Forest model identifies traffic that differs significantly from the baseline traffic used during training.
