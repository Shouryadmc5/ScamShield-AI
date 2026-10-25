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
import argparse
from typing import Any, Dict, List

# Ensure backend directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import evaluate_rules

DEFAULT_DATASET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evaluation_dataset.json")
HELD_OUT_DATASET_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "heldout_evaluation_dataset.json"
)
POSITIVE_THRESHOLD = 30  # Scores >= 30 are treated as Positive (Scam/Suspicious)
DATASET_LIMITATION = (
    "Synthetic, manually authored examples; not independently sourced or representative "
    "of real-world prevalence. Metrics do not establish production accuracy."
)


def load_dataset(filepath: str) -> List[Dict[str, Any]]:
    """Loads and validates dataset entries."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Evaluation dataset file not found at: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Dataset root must be a list of benchmark items.")

    validated: List[Dict[str, Any]] = []
    seen_ids = set()
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Dataset entry at index {idx} is not an object.")

        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id.strip():
            raise ValueError(f"Dataset entry at index {idx} missing 'id'.")
        if item_id in seen_ids:
            raise ValueError(f"Duplicate dataset id '{item_id}'.")
        seen_ids.add(item_id)

        expected = item.get("expected_label")
        if expected not in ["benign", "scam"]:
            raise ValueError(
                f"Entry '{item_id}' has invalid expected_label '{expected}'. Must be 'benign' or 'scam'."
            )

        inp = item.get("input")
        if not isinstance(inp, dict):
            raise ValueError(f"Entry '{item_id}' has invalid 'input' field (must be dict).")
        category = item.get("category", "unclassified")
        explanation = item.get("explanation", "")
        if not isinstance(category, str) or not category.strip():
            raise ValueError(f"Entry '{item_id}' category must be a non-empty string.")
        if not isinstance(explanation, str):
            raise ValueError(f"Entry '{item_id}' explanation must be a string.")

        msg = inp.get("message")
        url = inp.get("url")
        if msg is not None and not isinstance(msg, str):
            raise ValueError(f"Entry '{item_id}' message must be a string.")
        if url is not None and not isinstance(url, str):
            raise ValueError(f"Entry '{item_id}' URL must be a string.")
        if not (msg and msg.strip()) and not (url and url.strip()):
            raise ValueError(f"Entry '{item_id}' input must provide at least 'message' or 'url'.")

        validated.append(item)

    return validated


def run_benchmark(dataset: List[Dict[str, Any]], threshold: int = POSITIVE_THRESHOLD):
    """
    Executes rules against each benchmark item and computes metrics.
    """
    if not isinstance(threshold, int) or not 0 <= threshold <= 100:
        raise ValueError("threshold must be an integer between 0 and 100.")

    tp, fp, tn, fn = 0, 0, 0, 0
    label_distribution = {"benign": 0, "scam": 0}
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []

    # Category breakdown: {category: {"total": int, "correct": int}}
    category_stats: Dict[str, Dict[str, int]] = {}

    for item in dataset:
        item_id = item["id"]
        category = item.get("category", "unclassified")
        expected = item["expected_label"]
        label_distribution[expected] += 1
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
        "threshold": threshold,
        "label_distribution": label_distribution,
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
        f"Dataset: {results.get('dataset_name', 'synthetic benchmark')}",
        f"Total Samples Evaluated: {results['total']}",
        f"Label Distribution: benign={results['label_distribution']['benign']}, scam={results['label_distribution']['scam']}",
        f"Decision Policy: 'scam' if risk_score >= {results['threshold']} (Medium/High), else 'benign' (Low)",
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
    lines.append(f"Limitations: {DATASET_LIMITATION}")
    lines.append("============================================================")
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate ScamShield's deterministic rules on a JSON dataset.")
    parser.add_argument("dataset", nargs="?", help="Optional benchmark JSON path.")
    parser.add_argument(
        "--held-out",
        action="store_true",
        help="Evaluate the separate held-out synthetic dataset.",
    )
    args = parser.parse_args()
    if args.held_out and args.dataset:
        parser.error("provide either --held-out or a dataset path, not both.")
    dataset_file = (
        HELD_OUT_DATASET_PATH if args.held_out else args.dataset or DEFAULT_DATASET_PATH
    )
    try:
        items = load_dataset(dataset_file)
        res = run_benchmark(items)
        if args.held_out:
            res["dataset_name"] = "separate held-out synthetic evaluation set"
        elif os.path.abspath(dataset_file) == os.path.abspath(DEFAULT_DATASET_PATH):
            res["dataset_name"] = "original synthetic regression set"
        else:
            res["dataset_name"] = "custom dataset"
        print(format_report(res))
    except Exception as e:
        print(f"Error running benchmark: {e}", file=sys.stderr)
        sys.exit(1)
