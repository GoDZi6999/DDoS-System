"""Human-readable alert text. Recommended actions are advisory only: ArgusAI
never blocks traffic on its own."""

from ipaddress import IPv4Address, IPv6Address

from app.models.enums import Severity

IP = IPv4Address | IPv6Address

_TITLES = {
    "ddos": "DDoS",
    "dos": "DoS",
    "other_dos": "DoS",
    "portscan": "Port scan",
    "botnet": "Botnet",
}

_ACTIONS = {
    "ddos": (
        "Confirm service health on {dst}; apply rate limiting or upstream filtering for the "
        "targeted service; engage the ISP or scrubbing provider if volume keeps rising; "
        "preserve flow records as evidence."
    ),
    "dos": (
        "Identify the exhausted resource on {dst} (connections, CPU, bandwidth); rate-limit "
        "{src}; monitor for escalation."
    ),
    "portscan": (
        "Review which services on {dst} are exposed; check firewall logs for {src}; block {src} "
        "at the perimeter once the scan is confirmed as unauthorised."
    ),
    "botnet": (
        "Isolate {src} for forensic review; look for command-and-control indicators and other "
        "hosts contacting the same destinations."
    ),
}
_ACTIONS["other_dos"] = _ACTIONS["dos"]

_DEFAULT_ACTION = (
    "Investigate traffic between {src} and {dst} and confirm whether it is expected before "
    "taking containment action."
)


def attack_title(label: str) -> str:
    return _TITLES.get(label, label.replace("_", " ").capitalize())


def describe(label: str, confidence: float, dst: IP, dst_port: int | None) -> str:
    target = f"{dst}:{dst_port}" if dst_port else str(dst)
    return f"{attack_title(label)} detected — confidence {confidence:.1%} — target {target}"


def recommended_action(label: str, severity: Severity, src: IP, dst: IP) -> str:
    action = _ACTIONS.get(label, _DEFAULT_ACTION).format(src=src, dst=dst)
    if severity == Severity.CRITICAL:
        return f"Escalate to the on-call responder now. {action}"
    return action
