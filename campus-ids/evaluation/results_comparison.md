## Design 1 vs Design 2 on the same windows

20685 windows (one per source IP and 10 s): 96 attack windows (portscan 40, synflood 20, portscan_slow_T2 9, portscan_fin 3, synflood_fast_80 3, synflood_1000pps 3, synflood_100pps 3, synflood_20pps 3, synflood_10pps 3, portscan_t5 2, synflood_fast_443 2, portscan_top100 1, portscan_connect 1, portscan_service 1, udpscan 1, udpflood 1) and 20589 benign windows, from the 5 days that contain attacks. Windows from 192.168.50.190 are left out of every row. 

| Method | Labels needed | TP | FN | FP | Precision | Recall | F1 | Recall portscan | Recall portscan_connect | Recall portscan_fin | Recall portscan_service | Recall portscan_slow_T2 | Recall portscan_t5 | Recall portscan_top100 | Recall synflood | Recall synflood_1000pps | Recall synflood_100pps | Recall synflood_10pps | Recall synflood_20pps | Recall synflood_fast_443 | Recall synflood_fast_80 | Recall udpflood | Recall udpscan |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Design 1 Stats, fixed limits (15 ports / 150 flows) | no | 71 | 25 | 3 | 0.96 | 0.74 | 0.84 | 31/40 | 1/1 | 3/3 | 1/1 | 0/9 | 2/2 | 1/1 | 17/20 | 3/3 | 3/3 | 0/3 | 2/3 | 2/2 | 3/3 | 1/1 | 1/1 |
| Design 1 Stats, fixed limits (5 ports / 150 flows) | no | 89 | 7 | 45 | 0.66 | 0.93 | 0.77 | 40/40 | 1/1 | 3/3 | 1/1 | 9/9 | 2/2 | 1/1 | 17/20 | 3/3 | 3/3 | 0/3 | 2/3 | 2/2 | 3/3 | 1/1 | 1/1 |
| Design 1 Rule layer (Suricata signatures) | no | 82 | 14 | 310 | 0.21 | 0.85 | 0.34 | 40/40 | 1/1 | 0/3 | 1/1 | 0/9 | 2/2 | 1/1 | 20/20 | 3/3 | 3/3 | 3/3 | 3/3 | 2/2 | 3/3 | 0/1 | 0/1 |
| Design 1 Stats layer, live replay (15 ports / 150 flows) | no | 90 | 6 | 6 | 0.94 | 0.94 | 0.94 | 39/40 | 1/1 | 3/3 | 1/1 | 8/9 | 2/2 | 1/1 | 19/20 | 3/3 | 3/3 | 0/3 | 3/3 | 2/2 | 3/3 | 1/1 | 1/1 |
| Design 1 ML layer (Isolation Forest) | no | 0 | 96 | 298 | 0.00 | 0.00 | 0.00 | 0/40 | 0/1 | 0/3 | 0/1 | 0/9 | 0/2 | 0/1 | 0/20 | 0/3 | 0/3 | 0/3 | 0/3 | 0/2 | 0/3 | 0/1 | 0/1 |
| Design 1 hybrid (Rule or Stats or ML) | no | 95 | 1 | 601 | 0.14 | 0.99 | 0.24 | 40/40 | 1/1 | 3/3 | 1/1 | 8/9 | 2/2 | 1/1 | 20/20 | 3/3 | 3/3 | 3/3 | 3/3 | 2/2 | 3/3 | 1/1 | 1/1 |
| Design 1 Stats layer + Design 2 together (either alerts) | yes | 95 | 1 | 6 | 0.94 | 0.99 | 0.96 | 40/40 | 1/1 | 3/3 | 1/1 | 9/9 | 2/2 | 1/1 | 20/20 | 3/3 | 3/3 | 2/3 | 3/3 | 2/2 | 3/3 | 1/1 | 1/1 |
| Design 2 Random Forest | yes | 86 | 10 | 1 | 0.99 | 0.90 | 0.94 | 39/40 | 1/1 | 3/3 | 1/1 | 8/9 | 2/2 | 1/1 | 20/20 | 3/3 | 3/3 | 2/3 | 3/3 | 0/2 | 0/3 | 0/1 | 0/1 |
| Design 1 + Design 2 together | yes | 96 | 0 | 601 | 0.14 | 1.00 | 0.24 | 40/40 | 1/1 | 3/3 | 1/1 | 9/9 | 2/2 | 1/1 | 20/20 | 3/3 | 3/3 | 3/3 | 3/3 | 2/2 | 3/3 | 1/1 | 1/1 |

How to read it:
- Design 2 (Random Forest, features conn_count, distinct_ports, rst_ratio, avg_pkts, total_bytes) is tested with leave-one-day-out cross-validation: every window is predicted by a model that never saw that day.
- Stats rows apply Design 1's two fixed limits (distinct ports, connections) to the fixed 10-second windows. The live Stats layer counts ports per destination host in a sliding window, while these rows count ports over all destinations, so they over-count ports of busy normal hosts (many false positives at a low port limit). The Stats (live replay) row is the real layer.
- Rule, Stats (live replay) and ML rows come from replaying the same eve.json files through dashboard/detection.py. A window counts as detected when the layer raised at least one alert for that source IP in it. The Isolation Forest was trained on baseline traffic that may include some of these days.
- Only 96 attack windows from a few separate runs were available, so one window is worth about 1.0 recall points; treat differences of a few points as noise.
- The Stats limits and the Design 2 features were both chosen while looking at part of these data, so none of the numbers is a final, independent test.
