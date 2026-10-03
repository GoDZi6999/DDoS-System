"""
Flask web dashboard for the DDoS detection system.
Provides live stats via Socket.IO and a REST API for manual prediction.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from data_preprocessing import SELECTED_FEATURES
from real_time_detection import ALERT_QUEUE, RealTimeDetector

logging.basicConfig(
    filename="logs/ddos_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ddos-detection-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Shared state
_stats = {"packets": 0, "attacks": 0, "normal": 0, "alerts": []}
_model = None
_scaler = None


def _load_artifacts():
    global _model, _scaler
    try:
        _model = joblib.load("models/best_ddos_detector.pkl")
        _scaler = joblib.load("models/scaler.pkl")
        app.logger.info("Model and scaler loaded.")
    except FileNotFoundError:
        app.logger.warning("Model not found — run training first.")


def _alert_watcher():
    """Background thread: drains ALERT_QUEUE and broadcasts via Socket.IO."""
    while True:
        try:
            alert = ALERT_QUEUE.get(timeout=1)
            _stats["alerts"].insert(0, alert)
            _stats["alerts"] = _stats["alerts"][:100]  # keep last 100
            _stats["attacks"] += 1
            _stats["packets"] += 1
            socketio.emit("alert", alert)
            socketio.emit("stats", _stats)
        except Exception:
            pass


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(_stats)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(_stats["alerts"])


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    Accepts a JSON body with the 15 feature values and returns a prediction.
    Example body: {"src_bytes": 500, "count": 10, ...}
    """
    if _model is None or _scaler is None:
        return jsonify({"error": "Model not loaded. Run training first."}), 503

    data = request.get_json(force=True)
    row = {feat: data.get(feat, 0) for feat in SELECTED_FEATURES}
    df = pd.DataFrame([row], columns=SELECTED_FEATURES)

    try:
        X = _scaler.transform(df)
        proba = float(_model.predict_proba(X)[0][1])
        label = "ATTACK" if proba >= 0.5 else "NORMAL"
        return jsonify({"label": label, "confidence": proba})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": _model is not None,
        "timestamp": datetime.now().isoformat(),
    })


@socketio.on("connect")
def on_connect():
    socketio.emit("stats", _stats)


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    _load_artifacts()
    t = threading.Thread(target=_alert_watcher, daemon=True)
    t.start()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Dashboard running at http://localhost:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
