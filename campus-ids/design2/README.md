# Design 2: Random Forest on 10-second IP windows

Design 1 looks at one network flow at a time. A port scan or a SYN flood is made of many tiny flows, so
it is hard to see that way. Design 2 looks at **one source IP over 10 seconds** and a Random Forest
decides "attack or normal". It is an optional extra layer on top of Design 1: without `--rf` the dashboard
works exactly as before.

> Status: early prototype. It was trained and tested only on our own lab attacks (Kali VM and one other
> device, port scans and SYN floods), so the numbers below are a first indication, not a final test.

## How it works

1. Suricata writes flow records to `eve.json`.
2. Flows are grouped by source IP and by 10-second window (by when the flow started).
3. For each (IP, window) we compute 5 features:

| Feature | Meaning |
|---|---|
| `conn_count` | number of flows the IP started in the window |
| `distinct_ports` | number of different destination ports it touched |
| `rst_ratio` | share of TCP flows that ended with a reset |
| `avg_pkts` | average packets per flow |
| `total_bytes` | bytes sent and received in all those flows |

4. A Random Forest (scikit-learn, 200 trees, class-weighted) says attack or normal.
   It is a two-class model: port scans and floods are both just "attack".

`syn_ratio` was in our first plan but is no longer used: every flow of our hping3 flood has 6 packets
(SYN, RST, ACK), so the SYN ratio stayed close to zero and the model ignored it.

## Files

| File | What it does |
|---|---|
| `aggregate.py` | Turns `eve.json` into one row per (source IP, 10 s window). With `--labels` it also labels the windows. Also holds `parse_flow_event`, which the live detector reuses, so training and live detection use the same numbers. |
| `train_rf.py` | Trains the Random Forest and tests it with leave-one-day-out cross-validation. Saves `model/rf_model.joblib` and a report in `evaluation/results_rf.txt`. |
| `labels.csv`, `labels_oct13.csv` | Our attack logs (start time, end time, attacker IP, label). |
| `attack_logger.sh` | Runs on the Kali VM. Runs one attack and writes its label line for you. |
| `peek_flows.py` | Prints a few raw flow records, to see what an attack really looks like. |
| `cicids_check.py` | Tries the model on CIC-IDS2017 (needs the TrafficLabelling version of the files, see Limits). |
| `../dashboard/rf_detector.py` | The live version, used by the dashboard. |
| `../evaluation/compare_designs.py` | Design 1 vs Design 2 table on the same windows. |
| `../tests/test_rf_detector.py` | Tests for the live detector. |

## Run it live (quick start)

You need `model/rf_model.joblib`. It is not in Git (`.gitignore` skips `*.joblib`), so make it first:

```
python design2/train_rf.py --input data/windows_labelled.csv
```

Then start the dashboard with the extra layer:

```
python dashboard/app.py --rf
```

- The terminal should say `RF = on`. If it says `RF = OFF (...)`, the text in the brackets is the reason.
- RF alerts show in the dashboard as the purple **Random Forest** source, with the attack probability in the score column.
- Add `--rf-debug` to see the probability of every 10-second window that has 2 or more flows. This is the easiest way to see why RF is quiet.
- `--rf-model <path>` uses another model file.

Things to know:

- An RF alert comes **about 15 seconds after the attack**: the 10-second window has to end, and the detector
  waits 5 seconds for late flow records. Rule and Stats alerts are still instant.
- An IP needs at least 5 flows in a window before RF can alert on it (`min_flows`), and the same IP raises
  one RF alert at most every 30 seconds (`cooldown`). Other settings: attack probability must reach 0.5.
  These are arguments of `RFDetector` in `dashboard/rf_detector.py`.
- Hidden IPs (own PC, trusted IPs in the Settings panel) are skipped by RF too.

## Make new training data

Do the attacks from the Kali VM, one by one, with `attack_logger.sh`, so every attack gets an exact label.

On the Kali VM (target = the IP of the PC running Suricata, here 192.168.50.190; Kali itself is 192.168.50.204):

```
chmod +x attack_logger.sh                 # once
TZ=Asia/Kuala_Lumpur date                 # check Kali's clock is right
./attack_logger.sh portscan 192.168.50.204 sudo nmap -sS -p 1-1000 192.168.50.190
./attack_logger.sh synflood 192.168.50.204 sudo hping3 -S -p 80 -i u5000 -c 500 192.168.50.190
```

Each run prints one line (start, end, attacker IP, label) and adds it to `attack_log.csv`.
Copy these lines to the end of `design2/labels.csv` on the Windows PC. If the Kali clock is wrong, the labels are wrong.

Then build the labelled windows and train again. `<eve.json files>` are all the files that contain your attacks
(for us `C:\Program Files\Suricata\log\eve.json`; copy it to a safe place after every test session, because the
file can be cleared):

```
python design2/aggregate.py --eve <eve.json files> --labels design2/labels.csv design2/labels_oct13.csv --attacker-ips 192.168.50.204 192.168.50.72 --out data/windows_labelled.csv
python design2/train_rf.py --input data/windows_labelled.csv
```

- A window is labelled as an attack if it comes from the attacker IP, overlaps an attack time, and has at least 5 flows.
- Windows from an attacker machine outside every attack time are "ambiguous" and left out.
- Everything else is "benign".
- If train_rf.py says the attack runs come from fewer than 2 days, the cross-validation cannot run.

Add `--ignore-ips 192.168.50.190` to `train_rf.py` to leave out your own PC when you check the results.

## Results so far

Same windows for both designs (20,575 windows, 60 attack windows: 40 port scan, 20 SYN flood).
Random Forest is tested with leave-one-day-out cross-validation: every window is predicted by a model that never saw that day.

| Method | Precision | Recall | False alarms |
|---|---|---|---|
| Random Forest | 0.92 | 0.75 | 4 (all from our own PC) |
| Design 1 Stats, fixed limits (15 ports or 150 flows) | 0.49 | 0.80 | 51 (mostly our own PC) |

When our own PC is hidden, as the dashboard does: both have no false alarms and recall 0.75 (RF) vs 0.80 (Stats).
So the prototype does **not** show that Design 2 detects more than the Stats layer. What it does show is that scans and
floods can be learned from data, without hand-set limits. The Isolation Forest layer flagged none of our Kali attacks.

Live tests from Kali against the Windows PC:

- `nmap -sS -p 1-1000`: RF alert with 1591 flows, 934 ports, attack probability 1.0.
- `hping3 -S -p 80 --flood`: RF alert with 20310 flows, but only probability 0.70, so the model is less sure about floods.

Reproduce the Design 1 vs Design 2 table:

```
python evaluation/compare_designs.py --eve <eve.json files> --ignore-ips 192.168.50.190
```

The Rule and ML rows only work when `--eve` points to the files that contain the attacks. With the wrong or a
new `eve.json` they show 0 detections, which is not a real result.

## Limits

- Slow scans are missed (`nmap -T2` touches only about 13 ports per window); Design 1 missed them too.
- Little attack data: one Kali VM, one other device, two attack types. The model may not work on other tools or speeds.
- Flood probability was low in one live test (0.70). Test more flood speeds.
- About 15 seconds of delay for RF alerts.
- CIC-IDS2017: the Friday files in `evaluation/` have no Source IP and no Timestamp, so no per-IP windows can be built.
  `cicids_check.py` needs the TrafficLabelling version. CIC also counts bytes differently from Suricata, so train without
  `total_bytes` for that check (command in the file's header).
- The Stats limits and the model features were chosen while looking at part of this data, so none of the numbers is a final, independent test.

## Troubleshooting

| Problem | What to do |
|---|---|
| `RF = OFF (...)` at start | Read the text in the brackets. Usually the model file is missing: run `train_rf.py`. |
| Model was trained with another scikit-learn version | Run `train_rf.py` again on your own computer. |
| RF shows no alert during an attack | Wait 20 seconds, then run with `--rf-debug` and look at `p(attack)`. |
| `[RF debug] ... (fewer than min_flows: never alerts)` | That IP had fewer than 5 flows in the window. Normal for quiet traffic. |
| Labels do not match the attacks | Check Kali's clock and that `--attacker-ips` lists every machine used for attacks. |

## Tests

```
python tests/test_rf_detector.py
```
