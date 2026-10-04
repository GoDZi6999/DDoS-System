"""Command line:

    python -m sentinel_engine run --source simulate --scenario demo --loop
    python -m sentinel_engine run --source pcap --pcap capture.pcap --speed 2
    python -m sentinel_engine run --source live --interface eth0     (needs CAP_NET_RAW)
    python -m sentinel_engine run --source sensor                    (flows from sensors)
    python -m sentinel_engine inject --scenario ddos --duration 20   (attack burst only)

Capture sensors on other hosts: python -m sentinel_engine.sensor --help

Environment: REDIS_URL, MODEL_BUNDLE, FLOW_PROFILES.
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from sentinel_engine.simulator import SCENARIOS

DEFAULT_BUNDLE = "models/sentinel-flow/2026.10.03"
DEFAULT_PROFILES = "data/samples/flow_profiles.csv"
HEARTBEAT_FILE = Path("/tmp/sentinel-engine.heartbeat")  # noqa: S108 (container-local)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinel_engine")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="run the real-time engine")
    run.add_argument("--source", choices=["simulate", "pcap", "live", "sensor"], default="simulate")
    run.add_argument("--scenario", choices=sorted(SCENARIOS), default="normal")
    run.add_argument("--loop", action="store_true", help="repeat the scenario forever")
    run.add_argument("--duration", type=float, help="stop after N seconds (simulate)")
    run.add_argument("--pcap", type=Path)
    run.add_argument("--speed", type=float, default=1.0, help="PCAP replay speed factor")
    run.add_argument("--no-retime", action="store_true", help="keep original PCAP timestamps")
    run.add_argument("--interface")
    run.add_argument("--filter", help="BPF filter for live capture")

    inject = commands.add_parser("inject", help="simulate one attack burst (no background)")
    inject.add_argument("--scenario", choices=sorted(set(SCENARIOS) - {"normal", "demo"}))
    inject.add_argument("--duration", type=float, default=20)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    from sentinel_ml.inference import Predictor

    from sentinel_engine.pipeline import Engine
    from sentinel_engine.publisher import RedisPublisher
    from sentinel_engine.simulator import Simulator

    predictor = Predictor.from_bundle(os.environ.get("MODEL_BUNDLE", DEFAULT_BUNDLE))
    publisher = RedisPublisher(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    profiles = Path(os.environ.get("FLOW_PROFILES", DEFAULT_PROFILES))

    if args.command == "inject":
        simulator = Simulator.from_csv(profiles, benign_rate=0)
        engine = Engine(predictor, publisher, "sim")
        count = engine.run(simulator.run(args.scenario, duration=args.duration))
        print(f"Injected {args.scenario}: {count} detections published")
        return 0

    if args.source == "simulate":
        source = Simulator.from_csv(profiles).run(
            args.scenario, loop=args.loop, duration=args.duration
        )
        kind = "sim"
    elif args.source == "pcap":
        from sentinel_engine.sources import pcap_source

        if args.pcap is None:
            parser.error("--pcap is required with --source pcap")
        source = pcap_source(args.pcap, speed=args.speed, retime=not args.no_retime)
        kind = "pcap"
    elif args.source == "sensor":
        from sentinel_engine.sources import sensor_source

        source = sensor_source(publisher.redis)
        kind = "live"
    else:
        from sentinel_engine.sources import live_source

        source = live_source(args.interface, args.filter)
        kind = "live"

    engine = Engine(predictor, publisher, kind, heartbeat_file=HEARTBEAT_FILE)
    count = engine.run(source)
    logging.getLogger(__name__).info("Source ended; %d detections published", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
