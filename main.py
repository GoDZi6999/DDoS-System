"""
Main orchestrator for the DDoS Detection System.

Usage:
    python main.py --mode train [--data data/KDDTrain+.txt]
    python main.py --mode detect [--interface eth0]
    python main.py --mode evaluate
    python main.py --mode dashboard
"""

import argparse
import logging
import os
import sys

logging.basicConfig(
    filename="logs/ddos_detection.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def mode_train(data_path: str):
    print("[*] Starting training pipeline...")
    from data_preprocessing import run as preprocess
    from model_training import run as train

    os.makedirs("logs", exist_ok=True)
    os.makedirs("models", exist_ok=True)

    print("[1/3] Preprocessing data...")
    X_train, X_test, y_train, y_test, le = preprocess(data_path)
    print(f"     Train: {X_train.shape} | Test: {X_test.shape}")

    print("[2/3] Training models...")
    xgb, lr, scaler, xgb_m, lr_m = train(X_train, X_test, y_train, y_test)

    print("[3/3] Training complete.")
    print(f"     XGBoost  — Accuracy: {xgb_m['accuracy']:.4f}  AUC: {xgb_m['auc_roc']:.6f}")
    print(f"     Logistic — Accuracy: {lr_m['accuracy']:.4f}  AUC: {lr_m['auc_roc']:.6f}")
    print("\n[*] Models saved to ./models/")
    print("[*] Run 'python main.py --mode evaluate' to generate full report.")


def mode_evaluate():
    print("[*] Running evaluation...")
    from testing import full_report, load_artifacts
    from data_preprocessing import run as preprocess

    _, X_test, _, y_test, _ = preprocess()
    model, scaler = load_artifacts()
    full_report(model, scaler, X_test, y_test)
    print("\n[*] Plots saved to ./logs/")


def mode_detect(interface: str = None):
    print("[*] Starting real-time detection...")
    _check_models()
    from real_time_detection import RealTimeDetector
    detector = RealTimeDetector()
    detector.start(interface=interface)


def mode_dashboard():
    print("[*] Starting web dashboard...")
    _check_models()
    from app import app, socketio, _load_artifacts
    import threading
    from real_time_detection import ALERT_QUEUE
    from app import _alert_watcher
    _load_artifacts()
    t = threading.Thread(target=_alert_watcher, daemon=True)
    t.start()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Dashboard at http://localhost:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)


def _check_models():
    if not os.path.exists("models/best_ddos_detector.pkl"):
        print("[!] No trained model found. Run: python main.py --mode train")
        sys.exit(1)


def main():
    os.makedirs("logs", exist_ok=True)

    parser = argparse.ArgumentParser(description="DDoS Detection System (NSL-KDD / XGBoost)")
    parser.add_argument(
        "--mode",
        choices=["train", "detect", "evaluate", "dashboard"],
        required=True,
        help="Operating mode",
    )
    parser.add_argument(
        "--data",
        default="data/KDDTrain+.txt",
        help="Path to KDDTrain+.txt (training mode only)",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Network interface for real-time capture (detect mode only)",
    )
    args = parser.parse_args()

    if args.mode == "train":
        mode_train(args.data)
    elif args.mode == "detect":
        mode_detect(args.interface)
    elif args.mode == "evaluate":
        mode_evaluate()
    elif args.mode == "dashboard":
        mode_dashboard()


if __name__ == "__main__":
    main()
