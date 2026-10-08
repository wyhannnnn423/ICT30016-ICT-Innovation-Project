"""
app.py
------------------------
Flask real-time dashboard for the Campus IDS.

Tails Suricata's eve.json, runs every event through the detector (Rule + Stats + ML,
see detection.py) and pushes the alerts to the browser with Socket.IO.

Examples:
    python dashboard/app.py                                  # live Suricata log (default path)
    python dashboard/app.py --eve demo/eve_demo.json         # demo mode (see scripts/replay_demo.py)
    python dashboard/app.py --own-ip 192.168.50.190          # hide alerts caused by this PC itself

The PC's own LAN IP is detected automatically when --own-ip is not given. Everything
(own IP, trusted IPs, thresholds) can also be changed live in the dashboard's Settings panel.
"""

import eventlet
eventlet.monkey_patch()

import argparse
import json
import os
from pathlib import Path

from flask import Flask, render_template
from flask_socketio import SocketIO

import ids_settings as S
import settings_api
from detection import Detector

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVE = r"C:\Program Files\Suricata\log\eve.json" if os.name == "nt" else "/var/log/suricata/eve.json"

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
detector = None   # created in main()


def tail_and_detect(eve_path):
    announced = False
    while not os.path.exists(eve_path):
        if not announced:
            print(f"[*] Waiting for {eve_path} to appear ...")
            announced = True
        socketio.sleep(1)

    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)          # only look at NEW events
        print(f"[*] Detection engine running. Watching {eve_path}")

        while True:
            pos = f.tell()
            line = f.readline()

            if not line:
                try:                     # file was emptied or rotated -> start from the top
                    if os.path.getsize(eve_path) < pos:
                        f.seek(0)
                except OSError:
                    pass
                socketio.sleep(0.1)
                continue

            if not line.endswith("\n"):  # half-written line: wait and read it again
                f.seek(pos)
                socketio.sleep(0.05)
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            try:
                for alert in detector.process(event):
                    print(f"[{alert['source']:5}] {alert['src_ip']} -> {alert['dest_ip']} | {alert['detail']}")
                    socketio.emit("new_alert", alert)
            except Exception as e:
                print(f"[!] Detection engine error: {e}")

            if detector.ml_error and not detector.ml_enabled and not getattr(detector, "_ml_warned", False):
                detector._ml_warned = True
                print(f"[!] ML layer switched off: {detector.ml_error}")


def watch_network(settings_path):
    """Automatic mode: when the PC joins another network, follow its new IP."""
    while True:
        socketio.sleep(5)
        try:
            ip = S.detect_lan_ip()
            if detector.refresh_own_ip(ip):
                print(f"[*] Network changed. This PC is now {ip}")
                try:
                    S.save(settings_path, detector.get_settings())
                except OSError:
                    pass
        except Exception as e:
            print(f"[!] Network check error: {e}")


@app.route("/")
def index():
    return render_template("dashboard.html")


def main():
    global detector
    D = S.DEFAULTS
    p = argparse.ArgumentParser(description="Campus IDS real-time dashboard")
    p.add_argument("--eve", default=DEFAULT_EVE, help=f"Path to Suricata eve.json (default: {DEFAULT_EVE})")
    p.add_argument("--model", default=str(ROOT / "model" / "ids_model.joblib"), help="Isolation Forest model file")
    p.add_argument("--scaler", default=str(ROOT / "model" / "ids_scaler.joblib"), help="Scaler file")
    p.add_argument("--settings-file", default=str(ROOT / "data" / "settings.json"),
                   help="Where the Settings panel saves its values (default: data/settings.json)")
    p.add_argument("--own-ip", action="append", default=None, metavar="IP",
                   help="LAN IP of the monitored PC; Rule and Stats alerts from it are skipped "
                        "(can be repeated; default: detected automatically)")
    p.add_argument("--scan-ports", type=int, default=None, help=f"Different ports on one host that count as a port scan (default {D['scan_ports']})")
    p.add_argument("--flood-flows", type=int, default=None, help=f"Connections from one source that count as a flood (default {D['flood_flows']})")
    p.add_argument("--window", type=int, default=None, help=f"Look-back window in seconds for the Stats layer (default {D['window']})")
    p.add_argument("--cooldown", type=int, default=None, help=f"Seconds before the same Stats alert repeats (default {D['cooldown']})")
    p.add_argument("--host", default="127.0.0.1", help="Use 0.0.0.0 to open the dashboard from other devices (they can view, not change settings)")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()

    # defaults < settings file < command line
    cli = {}
    if args.own_ip is not None:
        cli["own_ips"] = args.own_ip
    for key in ("scan_ports", "flood_flows", "window", "cooldown"):
        if getattr(args, key) is not None:
            cli[key] = getattr(args, key)
    settings, errors, auto_ip = S.startup_settings(S.load(args.settings_file), cli, S.detect_lan_ip())
    if errors:
        p.error("; ".join(errors))

    detector = Detector(model_path=args.model, scaler_path=args.scaler, **settings)
    settings_api.register(app, lambda: detector, args.settings_file)

    ignored = detector.own.to_list() + detector.trusted.to_list()
    if auto_ip:
        print(f"[*] This PC's LAN IP was detected automatically: {auto_ip} (it follows network changes)")
    if ignored:
        print("[*] Ignoring Rule/Stats alerts from: " + ", ".join(ignored))
    else:
        print("[*] Not ignoring any source. Alerts from this PC will be shown (see the Settings panel).")

    print("[*] Layers: Rule = on, Stats = on, ML = " +
          ("on" if detector.ml_enabled else f"OFF ({detector.ml_error})"))
    if not detector.ml_enabled:
        print("    To fix: pip install -r requirements.txt  (the model needs the pinned scikit-learn),")
        print("    or retrain: python model/train_model.py --input data/baseline_features.csv "
              "--model_out model/ids_model.joblib --scaler_out model/ids_scaler.joblib")

    socketio.start_background_task(tail_and_detect, args.eve)
    socketio.start_background_task(watch_network, args.settings_file)
    print(f"[*] Dashboard: http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}")
    socketio.run(app, host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
