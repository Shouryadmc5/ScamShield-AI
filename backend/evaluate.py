"""
ScamShield AI Evaluation Benchmark Runner

Evaluates the rule-based detection engine against a synthetic benchmark dataset.

Binary Classification Decision Policy:
- 'scam' (Positive): risk_score >= 30 (Medium or High risk level).
  Rationale: Any sample that produces actionable suspicious indicators (scoring 30+)
  triggers security warnings and is classified as potentially unsafe/scam.
- 'benign' (Negative): risk_score < 30 (Low risk level).
  Rationale: Low-risk messages have either zero indicators or isolated minor signals
  not warranting warning banners or intervention.
"""

import json
import os
import sys
from typing import Any, Dict, List, Tuple

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import evaluate_rules

DEFAULT_DATASET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evaluation_dataset.json")
POSITIVE_THRESHOLD = 30  # Scores >= 30 are treated as Positive (Scam/Suspicious)


def load_dataset(filepath: str) -> List[Dict[str, Any]]:
    """Loads and validates dataset entries."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Evaluation dataset file not found at: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Dataset root must be a list of benchmark items.")

    validated: List[Dict[str, Any]] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Dataset entry at index {idx} is not an object.")

        item_id = item.get("id")
        if not item_id:
            raise ValueError(f"Dataset entry at index {idx} missing 'id'.")

        expected = item.get("expected_label")
        if expected not in ["benign", "scam"]:
            raise ValueError(
                f"Entry '{item_id}' has invalid expected_label '{expected}'. Must be 'benign' or 'scam'."
            )

        inp = item.get("input")
        if not isinstance(inp, dict):
            raise ValueError(f"Entry '{item_id}' has invalid 'input' field (must be dict).")

        msg = inp.get("message")
        url = inp.get("url")
        if not msg and not url:
            raise ValueError(f"Entry '{item_id}' input must provide at least 'message' or 'url'.")

        validated.append(item)

    return validated


def run_benchmark(dataset: List[Dict[str, Any]], threshold: int = POSITIVE_THRESHOLD):
    """
    Executes rules against each benchmark item and computes metrics.
    """
    tp, fp, tn, fn = 0, 0, 0, 0
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []

    # Category breakdown: {category: {"total": int, "correct": int}}
    category_stats: Dict[str, Dict[str, int]] = {}

    for item in dataset:
        item_id = item["id"]
        category = item.get("category", "unclassified")
        expected = item["expected_label"]
        inp = item["input"]

        res = evaluate_rules(inp.get("message"), inp.get("url"))
        score = res["risk_score"]
        predicted = "scam" if score >= threshold else "benign"

        if category not in category_stats:
            category_stats[category] = {"total": 0, "correct": 0}
        category_stats[category]["total"] += 1

        is_correct = predicted == expected
        if is_correct:
            category_stats[category]["correct"] += 1

        if expected == "scam" and predicted == "scam":
            tp += 1
        elif expected == "benign" and predicted == "scam":
            fp += 1
            false_positives.append({
                "id": item_id,
                "category": category,
                "input": inp,
                "score": score,
                "indicators": res["indicators"],
                "explanation": item.get("explanation", "")
            })
        elif expected == "benign" and predicted == "benign":
            tn += 1
        elif expected == "scam" and predicted == "benign":
            fn += 1
            false_negatives.append({
                "id": item_id,
                "category": category,
                "input": inp,
                "score": score,
                "indicators": res["indicators"],
                "explanation": item.get("explanation", "")
            })

    total = len(dataset)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "total": total,
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        },
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "category_stats": category_stats,
    }


def format_report(results: Dict[str, Any]) -> str:
    cm = results["confusion_matrix"]
    m = results["metrics"]
    lines = [
        "============================================================",
        "             SCAMSHIELD AI BENCHMARK REPORT                 ",
        "============================================================",
        f"Total Samples Evaluated: {results['total']}",
        f"Decision Policy: 'scam' if risk_score >= {POSITIVE_THRESHOLD} (Medium/High), else 'benign' (Low)",
        "",
        "--- Confusion Matrix ---",
        f"  True Positives  (TP) : {cm['TP']:2d}   |   False Positives (FP) : {cm['FP']:2d}",
        f"  False Negatives (FN) : {cm['FN']:2d}   |   True Negatives  (TN) : {cm['TN']:2d}",
        "",
        "--- Classification Metrics ---",
        f"  Accuracy  : {m['accuracy'] * 100:.1f}%",
        f"  Precision : {m['precision'] * 100:.1f}%",
        f"  Recall    : {m['recall'] * 100:.1f}%",
        f"  F1 Score  : {m['f1_score']:.4f}",
        "",
        "--- Breakdown by Category ---",
    ]

    for cat, stats in sorted(results["category_stats"].items()):
        acc = (stats["correct"] / stats["total"]) * 100 if stats["total"] > 0 else 0
        lines.append(f"  * {cat:<24} : {stats['correct']}/{stats['total']} ({acc:.1f}%)")

    lines.append("")
    lines.append("--- Misclassifications ---")
    if not results["false_positives"] and not results["false_negatives"]:
        lines.append("  None. All samples in this synthetic benchmark matched expected labels.")
    else:
        for fp in results["false_positives"]:
            lines.append(f"  [FALSE POSITIVE] ID: {fp['id']} (Category: {fp['category']})")
            lines.append(f"    Input: {fp['input']}")
            lines.append(f"    Score: {fp['score']} | Indicators: {fp['indicators']}")
        for fn in results["false_negatives"]:
            lines.append(f"  [FALSE NEGATIVE] ID: {fn['id']} (Category: {fn['category']})")
            lines.append(f"    Input: {fn['input']}")
            lines.append(f"    Score: {fn['score']} | Indicators: {fn['indicators']}")

    lines.append("============================================================")
    lines.append("Notice: Initial synthetic benchmark for local regression tracking.")
    lines.append("Does not constitute proof of real-world production accuracy.")
    lines.append("============================================================")
    return "\n".join(lines)


if __name__ == "__main__":
    dataset_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATASET_PATH
    try:
        items = load_dataset(dataset_file)
        res = run_benchmark(items)
        print(format_report(res))
    except Exception as e:
        print(f"Error running benchmark: {e}", file=sys.stderr)
        sys.exit(1)
