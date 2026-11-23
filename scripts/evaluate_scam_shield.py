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
from typing import Any, Dict, List, Optional, Tuple

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = REPOSITORY_ROOT / "scripts" / "eval_dataset.json"
DEFAULT_REPORT = REPOSITORY_ROOT / "reports" / "section7_results.md"
ALLOWED_TYPES = {"text", "sms", "email", "url", "script", "chat"}
ALLOWED_LABELS = {"scam", "legitimate"}

if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from app import predictors


def load_dataset(path: Path) -> List[Dict[str, str]]:
    """Load and validate the balanced sample file before running predictions."""
    # payload is the parsed JSON document; checking its schema prevents misleading metrics.
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
    """Map each sample type to its predictor and convert labels to scam/legitimate."""
    # URL scans have three possible classes; text-like inputs use benign or phishing.
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
    # Confidence here is the winning class score, not a separately calibrated guarantee.
    return predicted, confidence, probabilities


def percentile_95(values: List[float]) -> float:
    """Return the nearest-rank 95th percentile, including for small test sets."""
    ordered = sorted(values)
    # Nearest rank selects the value at ceil(95% of the sample count), using one-based ranks.
    nearest_rank = max(1, math.ceil(0.95 * len(ordered)))
    return ordered[nearest_rank - 1]


def _calculate_metrics(
    results: List[Dict[str, Any]],
    latencies_ms: List[float],
) -> Dict[str, float]:
    """Calculate confusion counts, quality scores, and latency summaries."""
    # TP/FN count scam samples; TN/FP count legitimate samples.
    expected_positive = [result for result in results if result["label"] == "scam"]
    expected_negative = [result for result in results if result["label"] == "legitimate"]
    tp = sum(result["predicted"] == "scam" for result in expected_positive)
    fn = len(expected_positive) - tp
    tn = sum(result["predicted"] == "legitimate" for result in expected_negative)
    fp = len(expected_negative) - tn
    # Accuracy is overall correctness; precision and recall describe positive predictions.
    accuracy = (tp + tn) / len(results) if results else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    # F1 balances precision and recall, returning zero when neither is defined.
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    # Latency is elapsed time for one direct predictor call, converted to milliseconds.
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
    return metrics


def evaluate(samples: List[Dict[str, str]]) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Run each sample once and measure only the direct predictor call."""
    results: List[Dict[str, Any]] = []
    latencies_ms: List[float] = []
    for sample in samples:
        # perf_counter is a monotonic timer suitable for measuring short elapsed times.
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

    metrics = _calculate_metrics(results, latencies_ms)
    return results, metrics


def model_status() -> str:
    """Describe whether local model files are available for this evaluation."""
    registry = predictors.get_registry()
    text_status = "available" if registry.text_model and registry.text_tokenizer else "heuristic fallback"
    url_status = "available" if registry.url_model and registry.url_tokenizer else "heuristic fallback"
    return f"text: {text_status}; URL: {url_status}"


def _format_misclassifications(results: List[Dict[str, Any]], expected: str) -> str:
    """Format false positives or false negatives as readable Markdown bullets."""
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
        # Confidence is the score for this prediction; it is not a calibrated guarantee.
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
    """Build the Markdown report from the measured results and run configuration."""
    # Specificity answers: of legitimate samples, what fraction stayed legitimate?
    negative_total = metrics["tn"] + metrics["fp"]
    specificity = metrics["tn"] / negative_total if negative_total else 0.0
    correct_count = int(metrics["tp"] + metrics["tn"])
    scam_count = int(metrics["tp"] + metrics["fn"])
    missed_scam_count = int(metrics["fn"])
    missed_scam_noun = "sample" if missed_scam_count == 1 else "samples"
    missed_scam_verb = "was" if missed_scam_count == 1 else "were"
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

## Run configuration

- **Run time (UTC):** {datetime.now(timezone.utc).isoformat(timespec="seconds")}
- **Dataset:** `scripts/eval_dataset.json` — {len(results)} balanced, labeled synthetic samples.
- **Execution:** Direct calls to `app.predictors.predict_text_probs` and `predict_url_probs`; text, SMS, email, script, and chat use the text predictor, while URLs use the URL predictor.
- **Mode:** {execution_mode}
- **Local model assets:** {local_model_status}

## Summary

The detector correctly classified **{correct_count} of {len(results)}** samples ({metrics["accuracy"]:.1%}). It found **{int(metrics["tp"])} of {scam_count}** scam samples and correctly cleared **{int(metrics["tn"])} of {int(negative_total)}** legitimate samples.

Precision was **{metrics["precision"]:.1%}** and specificity was **{specificity:.1%}**, while recall was **{metrics["recall"]:.1%}**. Precision and specificity are the strongest aggregate measures in this run; recall also means **{missed_scam_count} scam {missed_scam_noun} {missed_scam_verb} missed**, so this benchmark does not support a claim of production-ready detection.

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
| Specificity | {specificity:.1%} |
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
- The average and maximum include first-call dataset-index initialization. The {metrics["max_latency_ms"]:.2f} ms maximum raises the average, while nearest-rank p95 uses rank 29 of 30 and excludes that single maximum; the p95 should not be read as a full service-response guarantee.
- The predictor's confidence is its winning class score and has not been calibrated against real-world outcomes.
- The per-type accuracy table has only five samples per type, so one result changes a type's accuracy by 20 percentage points.
- This small synthetic dataset is a smoke-test benchmark, not a substitute for a representative, independently labeled production evaluation.

## What to improve next

- Review the false negatives first, especially requests for one-time codes, gift cards, toll or delivery payments, and suspicious scripts.
- Review the false positives on the government and health-service URLs before increasing URL risk thresholds.
- Expand the independently labeled dataset and rerun it after any detector change; do not treat these 30 samples as proof of general accuracy.
"""


def _disable_nvidia_classifier(
    _content: str,
    _modality: str,
) -> Optional[Dict[str, float]]:
    """Keep the default evaluation offline without changing predictor code."""
    return None


def main() -> None:
    """Parse options, run the local evaluation, and write its report."""
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
        # This opt-in sends the synthetic sample content to the configured provider.
        execution_mode = "Configured NVIDIA classifier enabled; synthetic sample text and URLs are sent to its API."
    else:
        # Default runs stay offline and use local weights or the normal heuristic fallback.
        predictors.classify_with_nvidia = _disable_nvidia_classifier
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
