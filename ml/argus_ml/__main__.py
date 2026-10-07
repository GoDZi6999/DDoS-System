"""Command line:

python -m argus_ml train   --data data/raw/cic-ids2017/MachineLearningCVE
python -m argus_ml predict --bundle models/argus-flow/<version> --csv flows.csv
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import pandas as pd


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m argus_ml")
    commands = parser.add_subparsers(dest="command", required=True)

    train = commands.add_parser("train", help="train, evaluate and bundle the models")
    train.add_argument("--data", type=Path, default=Path("data/raw/cic-ids2017/MachineLearningCVE"))
    train.add_argument("--models", type=Path, default=Path("models"))
    train.add_argument("--reports", type=Path, default=Path("ml/reports"))
    train.add_argument(
        "--cap", type=int, default=150_000, help="max training rows per attack class"
    )
    train.add_argument("--no-ablation", action="store_true", help="skip the feature ablation")
    train.add_argument(
        "--tune-decisions", action="store_true", help="bundle tuned per-class decision weights"
    )
    train.add_argument("--seed", type=int, default=42)

    predict = commands.add_parser("predict", help="classify flows from a CIC-format CSV")
    predict.add_argument("--bundle", type=Path, required=True)
    predict.add_argument("--csv", type=Path, required=True)
    predict.add_argument("--limit", type=int, default=20)

    export = commands.add_parser("export-profiles", help="sample held-out flows for the demo")
    export.add_argument(
        "--data", type=Path, default=Path("data/raw/cic-ids2017/MachineLearningCVE")
    )
    export.add_argument("--out", type=Path, default=Path("data/samples/flow_profiles.csv"))

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "train":
        from argus_ml.train import run

        run(
            args.data, args.models, args.reports, args.cap, args.seed, ablation=not args.no_ablation
        )
        return 0

    if args.command == "export-profiles":
        from argus_ml.profiles import export_profiles

        profiles = export_profiles(args.data, args.out)
        print(f"Wrote {len(profiles)} flows to {args.out}")
        return 0

    from argus_ml import features
    from argus_ml.inference import Predictor

    frame = pd.read_csv(args.csv, encoding="latin-1", nrows=args.limit)
    frame.columns = [c.strip() for c in frame.columns]
    predictor = Predictor.from_bundle(args.bundle)
    for prediction in predictor.predict(features.from_cic(frame)):
        print(json.dumps({"summary": prediction.summary(), **prediction.__dict__}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
