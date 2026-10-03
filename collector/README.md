# Traffic collector (Phase 5)

Turns packets into flows for the ML engine.

- `capture.py`: live, read-only capture with Scapy (needs `NET_RAW`; this is the
  only container that gets that capability, and it has no database credentials)
- `replay.py`: replays a PCAP file at a configurable speed, so demos need no live attack
- `flow_builder.py`: bidirectional flows keyed by 5-tuple, with idle/active
  timeouts, plus periodic partial flows so a flood is detected *while* it runs

Flows are published to the Redis stream `flows`. Only headers and derived
statistics are kept, never payloads.
