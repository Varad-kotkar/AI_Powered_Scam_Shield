import unittest
from unittest.mock import patch

from app.llm_helpers import classify_with_nvidia, friendly_chat_reply, make_llm_explanation


class LLMHelperTests(unittest.TestCase):
    def test_classifier_extracts_and_normalizes_provider_probabilities(self):
        response = 'Result: {"benign": 0.2, "phishing": 0.6}'
        with patch("app.llm_helpers.call_nvidia", return_value=response):
            probabilities = classify_with_nvidia("sample message", "text")

        self.assertAlmostEqual(probabilities["benign"], 0.25)
        self.assertAlmostEqual(probabilities["phishing"], 0.75)

    def test_local_explanations_and_chat_replies_work_without_a_provider(self):
        with patch("app.llm_helpers.LLM_PROVIDER", "disabled"):
            explanation = make_llm_explanation({
                "label": "phishing",
                "probs": {"benign": 0.2, "phishing": 0.8},
            })
            reply = friendly_chat_reply("hello")

        self.assertIn("High Risk Phishing Detected", explanation)
        self.assertIn("Hello!", reply)


if __name__ == "__main__":
    unittest.main()
