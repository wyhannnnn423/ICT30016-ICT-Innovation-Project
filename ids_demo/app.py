"""
Campus IDS — Alert Dashboard Prototype (Flask-SocketIO)
------------------------------------------------------------
A minimal working example of pushing an alert to a web page in
real time, WITHOUT the page needing to refresh or poll.

This is the "basic prototype that pushes test alerts" step from
the report — it's not connected to the real detection pipeline
yet, it just proves the push mechanism works.

Requirements:
    pip install flask flask-socketio

Usage:
    python3 app.py
    Then open http://127.0.0.1:5000 in your browser.
    Click the "Send Test Alert" button and watch it appear
    instantly, with no page refresh.
"""

import random
import time

from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
app.config["SECRET_KEY"] = "demo-secret-key"
socketio = SocketIO(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/trigger-test-alert")
def trigger_test_alert():
    """Simulates the model detecting an anomaly and pushes it live."""
    alert = {
        "time": time.strftime("%H:%M:%S"),
        "src_ip": f"192.168.1.{random.randint(2, 254)}",
        "message": "Anomalous traffic detected (test alert)",
    }
    socketio.emit("new_alert", alert)
    return "Alert sent! Check the dashboard."


if __name__ == "__main__":
    socketio.run(app, debug=True)
