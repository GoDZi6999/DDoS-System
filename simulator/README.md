# Lab traffic simulator (Phase 5)

Generates benign and attack-like traffic **only inside the isolated Docker lab
network** (`labnet`, `internal: true`, no route to the internet), so the full
pipeline can be demonstrated without attacking anything real.

- `benign.py`: web/DNS-like background traffic
- `attacks.py`: SYN flood, UDP flood, HTTP flood and port-scan patterns
- `scenarios/*.yaml`: scripted demos (normal -> ramp-up -> attack -> recovery)

Safety rules: targets are restricted to lab-network addresses and checked
before sending; rates are capped; the simulator is off unless the `demo`
Compose profile is enabled.
