#!/usr/bin/env python
"""Evaluate Scam Shield's existing text and URL predictors on a labeled dataset."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPOSITORY_ROOT / "scripts" / "eval_dataset.json"
DEFAULT_REPORT = REPOSITORY_ROOT / "reports" / "section7_results.md"
ALLOWED_TYPES = {"text", "sms", "email", "url", "script", "chat"}
ALLOWED_LABELS = {"scam", "legitimate"}

if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from app import predictors


def load_dataset(path: Path) -> List[Dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    samples = payload.get("samples")
    if not isinstance(samples, list):
        raise ValueError("Dataset must contain a 'samples' list.")
    if len(samples) != 30:
        raise ValueError(f"Expected 30 evaluation samples, received {len(samples)}.")

    ids = set()
    labels = Counter()
    types = set()
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("Every sample must be a JSON object.")
        if not {"id", "type", "label", "content"} <= sample.keys():
            raise ValueError("Every sample must include id, type, label, and content.")
        if sample["id"] in ids:
            raise ValueError(f"Duplicate sample id: {sample['id']}")
        if sample["type"] not in ALLOWED_TYPES:
            raise ValueError(f"Unsupported sample type: {sample['type']}")
        if sample["label"] not in ALLOWED_LABELS:
            raise ValueError(f"Unsupported expected label: {sample['label']}")
        if not isinstance(sample["content"], str) or not sample["content"].strip():
            raise ValueError(f"Sample {sample['id']} has no content.")
        ids.add(sample["id"])
        labels[sample["label"]] += 1
        types.add(sample["type"])

    if labels != Counter({"scam": 15, "legitimate": 15}):
        raise ValueError(f"Expected 15 samples per class, received {dict(labels)}.")
    if types != ALLOWED_TYPES:
        raise ValueError(f"Dataset must cover all six types; found {sorted(types)}.")
    return samples


def classify_sample(sample: Dict[str, str]) -> Tuple[str, float, Dict[str, float]]:
    if sample["type"] == "url":
        probabilities = predictors.predict_url_probs(sample["content"])
        if not probabilities:
            raise RuntimeError(f"URL predictor returned no probabilities for {sample['id']}.")
        class_label = max(probabilities, key=probabilities.get)
        predicted = "legitimate" if class_label == "benign" else "scam"
        confidence = float(probabilities[class_label])
    else:
        probabilities = predictors.predict_text_probs(sample["content"])
        if not probabilities:
            raise RuntimeError(f"Text predictor returned no probabilities for {sample['id']}.")
        phishing_probability = float(probabilities.get("phishing", 0.0))
        benign_probability = float(probabilities.get("benign", 0.0))
        predicted = "scam" if phishing_probability >= benign_probability else "legitimate"
        confidence = max(phishing_probability, benign_probability)
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise RuntimeError(f"Predictor returned an invalid confidence for {sample['id']}.")
    return predicted, confidence, probabilities


def percentile_95(values: List[float]) -> float:
    ordered = sorted(values)
    nearest_rank = max(1, math.ceil(0.95 * len(ordered)))
    return ordered[nearest_rank - 1]


def evaluate(samples: List[Dict[str, str]]) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    results: List[Dict[str, Any]] = []
    latencies_ms: List[float] = []
    for sample in samples:
        started = time.perf_counter()
        predicted, confidence, probabilities = classify_sample(sample)
        latency_ms = (time.perf_counter() - started) * 1000
        latencies_ms.append(latency_ms)
        results.append(
            {
                **sample,
                "predicted": predicted,
                "confidence": confidence,
                "probabilities": probabilities,
                "latency_ms": latency_ms,
            }
        )

    expected_positive = [result for result in results if result["label"] == "scam"]
    expected_negative = [result for result in results if result["label"] == "legitimate"]
    tp = sum(result["predicted"] == "scam" for result in expected_positive)
    fn = len(expected_positive) - tp
    tn = sum(result["predicted"] == "legitimate" for result in expected_negative)
    fp = len(expected_negative) - tn
    accuracy = (tp + tn) / len(results) if results else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    metrics = {
        "tp": float(tp),
        "tn": float(tn),
        "fp": float(fp),
        "fn": float(fn),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "average_latency_ms": sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0,
        "p95_latency_ms": percentile_95(latencies_ms) if latencies_ms else 0.0,
        "max_latency_ms": max(latencies_ms, default=0.0),
    }
    return results, metrics


def model_status() -> str:
    registry = predictors.get_registry()
    text_status = "available" if registry.text_model and registry.text_tokenizer else "heuristic fallback"
    url_status = "available" if registry.url_model and registry.url_tokenizer else "heuristic fallback"
    return f"text: {text_status}; URL: {url_status}"


def _format_misclassifications(results: List[Dict[str, Any]], expected: str) -> str:
    incorrect = [
        result
        for result in results
        if result["label"] == expected and result["predicted"] != expected
    ]
    if not incorrect:
        return "_None._"
    lines = []
    for result in incorrect:
        content = " ".join(result["content"].split()).replace("|", "\\|")
        lines.append(
            f"- `{result['id']}` ({result['type']}): expected **{expected}**, "
            f"predicted **{result['predicted']}** ({result['confidence']:.1%} confidence) — {content}"
        )
    return "\n".join(lines)


def render_report(
    results: List[Dict[str, Any]],
    metrics: Dict[str, float],
    execution_mode: str,
    local_model_status: str,
) -> str:
    count_by_type = Counter(result["type"] for result in results)
    accuracy_by_type = {}
    for sample_type in sorted(ALLOWED_TYPES):
        subset = [result for result in results if result["type"] == sample_type]
        correct = sum(result["label"] == result["predicted"] for result in subset)
        accuracy_by_type[sample_type] = f"{correct}/{len(subset)} ({correct / len(subset):.1%})"

    type_rows = "\n".join(
        f"| {sample_type} | {count_by_type[sample_type]} | {accuracy_by_type[sample_type]} |"
        for sample_type in sorted(ALLOWED_TYPES)
    )
    return f"""# Section 7 — Scam Shield Evaluation Results

**Run time (UTC):** {datetime.now(timezone.utc).isoformat(timespec="seconds")}  
**Dataset:** `scripts/eval_dataset.json` — {len(results)} balanced, labeled synthetic samples  
**Execution:** Direct calls to `app.predictors.predict_text_probs` and `predict_url_probs`; text, SMS, email, script, and chat use the text predictor, while URLs use the URL predictor.
**Mode:** {execution_mode}
**Local model assets:** {local_model_status}

## Aggregate metrics

| Metric | Result |
|---|---:|
| TP | {int(metrics["tp"])} |
| TN | {int(metrics["tn"])} |
| FP | {int(metrics["fp"])} |
| FN | {int(metrics["fn"])} |
| Accuracy | {metrics["accuracy"]:.1%} |
| Precision | {metrics["precision"]:.1%} |
| Recall | {metrics["recall"]:.1%} |
| F1-score | {metrics["f1"]:.1%} |
| Average latency | {metrics["average_latency_ms"]:.2f} ms |
| P95 latency (nearest-rank) | {metrics["p95_latency_ms"]:.2f} ms |
| Maximum latency | {metrics["max_latency_ms"]:.2f} ms |

## Results by input type

| Type | Samples | Accuracy |
|---|---:|---:|
{type_rows}

## False positives

{_format_misclassifications(results, "legitimate")}

## False negatives

{_format_misclassifications(results, "scam")}

## Evaluation notes

- “Scam” combines phishing and malware URL predictions; all non-`benign` URL classes count as positive.
- Latency is measured around the direct predictor call and includes its configured model/provider and local dataset-intelligence behavior, but excludes HTTP transport and report generation.
- The average and maximum include first-call initialization; a single cold-start outlier can exceed the nearest-rank p95 on this 30-sample set.
- This small synthetic dataset is a smoke-test benchmark, not a substitute for a representative, independently labeled production evaluation.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--use-configured-provider",
        action="store_true",
        help="Send the 30 synthetic samples to the configured NVIDIA classifier instead of using local model/fallback inference.",
    )
    args = parser.parse_args()

    if args.use_configured_provider:
        execution_mode = "Configured NVIDIA classifier enabled; synthetic sample text and URLs are sent to its API."
    else:
        predictors.classify_with_nvidia = lambda _content, _modality: None
        execution_mode = "Offline; NVIDIA calls disabled; local models are used when available, with dataset-intelligence and heuristic fallbacks."

    samples = load_dataset(args.dataset)
    results, metrics = evaluate(samples)
    report = render_report(results, metrics, execution_mode, model_status())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(f"Report written to {args.output}")
    print(
        f"Accuracy: {metrics['accuracy']:.1%} | "
        f"F1: {metrics['f1']:.1%} | "
        f"Average latency: {metrics['average_latency_ms']:.2f} ms | "
        f"P95 latency: {metrics['p95_latency_ms']:.2f} ms"
    )


if __name__ == "__main__":
    main()
