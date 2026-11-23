import unittest
from unittest.mock import patch

from scripts.evaluate_scam_shield import (
    ALLOWED_TYPES,
    _calculate_metrics,
    classify_sample,
    render_report,
)


class EvaluationTests(unittest.TestCase):
    def test_metrics_include_confusion_counts_and_latency_summaries(self):
        results = [
            {"label": "scam", "predicted": "scam"},
            {"label": "scam", "predicted": "legitimate"},
            {"label": "legitimate", "predicted": "legitimate"},
            {"label": "legitimate", "predicted": "scam"},
        ]

        metrics = _calculate_metrics(results, [10.0, 20.0, 30.0, 40.0])

        self.assertEqual((metrics["tp"], metrics["tn"], metrics["fp"], metrics["fn"]), (1, 1, 1, 1))
        self.assertEqual(metrics["accuracy"], 0.5)
        self.assertEqual(metrics["f1"], 0.5)
        self.assertEqual(metrics["average_latency_ms"], 25.0)
        self.assertEqual(metrics["p95_latency_ms"], 40.0)

    def test_url_classification_combines_non_benign_classes_as_scam(self):
        sample = {"id": "u1", "type": "url", "label": "scam", "content": "https://bad.example"}
        with patch(
            "scripts.evaluate_scam_shield.predictors.predict_url_probs",
            return_value={"benign": 0.1, "phishing": 0.3, "malware": 0.6},
        ):
            prediction, confidence, probabilities = classify_sample(sample)

        self.assertEqual(prediction, "scam")
        self.assertEqual(confidence, 0.6)
        self.assertEqual(probabilities["malware"], 0.6)

    def test_report_summarizes_measured_results_and_specificity(self):
        results = []
        for index, sample_type in enumerate(sorted(ALLOWED_TYPES)):
            expected = "scam" if index % 2 == 0 else "legitimate"
            predicted = expected
            if index == 0:
                predicted = "legitimate"
            elif index == 1:
                predicted = "scam"
            results.append({
                "id": f"sample-{index}",
                "type": sample_type,
                "content": "sample message",
                "label": expected,
                "predicted": predicted,
                "confidence": 0.8,
            })

        metrics = _calculate_metrics(results, [10, 20, 30, 40, 50, 60])
        report = render_report(results, metrics, "offline test", "heuristic fallback")

        self.assertIn("4 of 6", report)
        self.assertIn("| Specificity | 66.7% |", report)
        self.assertIn("1 scam sample was missed", report)


if __name__ == "__main__":
    unittest.main()
