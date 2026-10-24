#!/usr/bin/env python3
"""Evaluate the deterministic audit agent against public sample answers."""
import csv
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
ROOT = CODE.parent
sys.path.insert(0, str(CODE))
import main as agent


def load(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def canonical_step(step):
    return tuple(step.get(k) for k in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"))


def evaluate():
    with tempfile.TemporaryDirectory() as tmp:
        pred_path = Path(tmp) / "predictions.csv"
        subprocess.run([sys.executable, str(CODE / "main.py"), "--requests", str(ROOT / "dataset" / "sample_deletion_requests.csv"), "--output", str(pred_path)], check=True)
        pred = {r["case_id"]: r for r in load(pred_path)}
    gold = {r["case_id"]: r for r in load(ROOT / "dataset" / "sample_output.csv")}
    status_ok = sum(pred[k]["deletion_status"] == gold[k]["deletion_status"] for k in gold)
    exact_steps = 0
    predicted_steps = expected_steps = common_steps = 0
    field_matches = field_total = sequence_ok = 0
    for case_id, expected in gold.items():
        got = json.loads(pred[case_id]["steps_json"])
        want = json.loads(expected["steps_json"])
        predicted_steps += len(got); expected_steps += len(want)
        have, need = Counter(canonical_step(x) for x in got), Counter(canonical_step(x) for x in want)
        common_steps += sum((have & need).values())
        if got == want and pred[case_id]["deletion_status"] == expected["deletion_status"]:
            exact_steps += 1; sequence_ok += 1
        # Position-based field score; missing or extra steps count as field errors.
        for i in range(max(len(got), len(want))):
            for key in ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += 1
                if i < len(got) and i < len(want) and got[i].get(key) == want[i].get(key): field_matches += 1
    # Three created, non-corpus checks exercise intent and core treatment decisions.
    custom = [
        ("non-deletion access request", not agent.authorizes_deletion("Please send me a copy of the data you hold.")),
        ("Japanese erasure request", agent.authorizes_deletion("このアカウントの完全な削除を依頼します。")),
        ("active connector requires flow stop", agent.classify({"resource_id": "data_flow_77", "_system": "integration_service", "enabled": 1})[2:5] == ("flow", "ACTIVE", True)),
    ]
    return {
        "sample_cases": len(gold), "status_correct": status_ok,
        "status_accuracy": status_ok / max(1, len(gold)), "exact_case_and_sequence": exact_steps,
        "sequence_accuracy": sequence_ok / max(1, len(gold)), "predicted_steps": predicted_steps,
        "expected_steps": expected_steps, "matched_steps": common_steps,
        "step_precision": common_steps / max(1, predicted_steps), "step_recall": common_steps / max(1, expected_steps),
        "field_matches": field_matches, "field_total": field_total,
        "field_accuracy": field_matches / max(1, field_total), "custom_cases": custom,
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2, ensure_ascii=False))
