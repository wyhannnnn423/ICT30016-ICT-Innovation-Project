## Design 1 vs Design 2 on the same windows

16820 windows (one per source IP and 10 s): 60 attack windows (portscan 40, synflood 20) and 16760 benign windows, from the 4 days that contain attacks. Windows from 192.168.50.190 are left out of every row. 

| Method | Labels needed | TP | FN | FP | Precision | Recall | F1 | Recall portscan | Recall synflood |
|---|---|---|---|---|---|---|---|---|---|
| Design 1 Stats, fixed limits (5 ports / 150 flows) | no | 57 | 3 | 25 | 0.70 | 0.95 | 0.80 | 40/40 | 17/20 |
| Design 1 Rule layer (Suricata signatures) | no | 0 | 60 | 0 | - | 0.00 | 0.00 | 0/40 | 0/20 |
| Design 1 Stats layer, live replay (5 ports / 150 flows) | no | 0 | 60 | 0 | - | 0.00 | 0.00 | 0/40 | 0/20 |
| Design 1 ML layer (Isolation Forest) | no | 0 | 60 | 0 | - | 0.00 | 0.00 | 0/40 | 0/20 |
| Design 1 hybrid (Rule or Stats or ML) | no | 0 | 60 | 0 | - | 0.00 | 0.00 | 0/40 | 0/20 |
| Design 2 Random Forest | yes | 45 | 15 | 0 | 1.00 | 0.75 | 0.86 | 27/40 | 18/20 |
| Design 1 + Design 2 together | yes | 45 | 15 | 0 | 1.00 | 0.75 | 0.86 | 27/40 | 18/20 |

How to read it:
- Design 2 (Random Forest, features conn_count, distinct_ports, rst_ratio, avg_pkts, total_bytes) is tested with leave-one-day-out cross-validation: every window is predicted by a model that never saw that day.
- Stats rows apply Design 1's two fixed limits (distinct ports, connections) to the fixed 10-second windows. The live Stats layer counts ports per destination host in a sliding window, while these rows count ports over all destinations, so they over-count ports of busy normal hosts (many false positives at a low port limit). The Stats (live replay) row is the real layer.
- Rule, Stats (live replay) and ML rows come from replaying the same eve.json files through dashboard/detection.py. A window counts as detected when the layer raised at least one alert for that source IP in it. The Isolation Forest was trained on baseline traffic that may include some of these days.
- Only 60 attack windows from a few separate runs were available, so one window is worth about 1.7 recall points; treat differences of a few points as noise.
- The Stats limits and the Design 2 features were both chosen while looking at part of these data, so none of the numbers is a final, independent test.
