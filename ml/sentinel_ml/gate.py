"""Release gate: may a new bundle replace the default one?

Fixed before the candidate is evaluated on the test set (first stated for
2026.10.04, written down as code for 2026.10.08). A candidate passes when,
on the test set, compared with the reference (default) bundle:

1. its false-positive rate (benign flows flagged as an attack) is strictly
   lower, and
2. no class loses more than MAX_RECALL_DROP of recall (absolute).

Anything else (macro-F1, precision) is reported but does not decide.
"""

import json
from pathlib import Path

REFERENCE_VERSION = "2026.10.03"
MAX_RECALL_DROP = 0.10


def check(candidate: dict, reference: dict, max_recall_drop: float = MAX_RECALL_DROP) -> dict:
    """Compare two `evaluate.evaluate` results; returns every check and the verdict."""
    checks = [
        {
            "name": "false_positive_rate",
            "candidate": candidate["false_positive_rate"],
            "reference": reference["false_positive_rate"],
            "passed": candidate["false_positive_rate"] < reference["false_positive_rate"],
        }
    ]
    for cls, ref in reference["per_class"].items():
        if not ref["support"]:
            continue
        recall = candidate["per_class"][cls]["recall"]
        checks.append(
            {
                "name": f"recall_{cls}",
                "candidate": recall,
                "reference": ref["recall"],
                "passed": recall >= ref["recall"] - max_recall_drop,
            }
        )
    return {
        "reference": reference.get("version", REFERENCE_VERSION),
        "max_recall_drop": max_recall_drop,
        "checks": checks,
        "passed": all(c["passed"] for c in checks),
    }


def reference_metrics(models_dir: Path, version: str = REFERENCE_VERSION) -> dict | None:
    """Test metrics recorded in the reference bundle's metadata, if it is present."""
    path = Path(models_dir) / "sentinel-flow" / version / "model_metadata.json"
    if not path.exists():
        return None
    return {**json.loads(path.read_text())["metrics"], "version": version}
