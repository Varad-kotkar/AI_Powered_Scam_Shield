import unittest
from unittest.mock import patch

from app.main import TextRequest, URLRequest
from bot.telegram_bot import _detect_text_or_url, _run_image_detection, format_result


class TelegramBotTests(unittest.TestCase):
    def test_bare_url_uses_existing_url_detector(self):
        response = {"label": "benign"}
        with patch("bot.telegram_bot.url_check", return_value=response) as url_check, patch(
            "bot.telegram_bot.text_check"
        ) as text_check:
            result = _detect_text_or_url("https://example.com/login")

        self.assertIs(result, response)
        url_check.assert_called_once_with(URLRequest(url="https://example.com/login"))
        text_check.assert_not_called()

    def test_message_with_url_uses_existing_text_detector(self):
        response = {"label": "phishing"}
        message = "I received this link https://example.com/login; is it safe?"
        with patch("bot.telegram_bot.text_check", return_value=response) as text_check, patch(
            "bot.telegram_bot.url_check"
        ) as url_check:
            result = _detect_text_or_url(message)

        self.assertIs(result, response)
        text_check.assert_called_once_with(TextRequest(text=message))
        url_check.assert_not_called()

    def test_image_bytes_are_passed_to_existing_image_detector(self):
        async def fake_image_check(upload):
            return {"image_bytes": await upload.read()}

        with patch("bot.telegram_bot.image_check", new=fake_image_check):
            result = _run_image_detection(b"sample image")

        self.assertEqual(result["image_bytes"], b"sample image")

    def test_high_risk_format_includes_red_flags_safety_and_escaped_content(self):
        formatted = format_result({
            "label": "phishing",
            "confidence": 0.91,
            "red_flags": [{
                "code": "TOAD_CALLBACK",
                "label": "Callback scam",
                "severity": "high",
                "evidence": "<script>call now</script>",
            }],
            "explanation": "This looks suspicious.",
        })

        self.assertIn("<b>Verdict:</b> PHISHING", formatted)
        self.assertIn("<b>Confidence:</b> 91.0%", formatted)
        self.assertIn("TOAD_CALLBACK", formatted)
        self.assertIn("&lt;script&gt;", formatted)
        self.assertNotIn("<script>", formatted)
        self.assertIn("1930", formatted)

    def test_long_result_keeps_safety_advice_within_telegram_limit(self):
        formatted = format_result({
            "label": "phishing",
            "confidence": 0.95,
            "red_flags": [{
                "code": "RISK",
                "label": "Risk" * 100,
                "severity": "high",
                "evidence": "evidence " * 100,
            }] * 20,
            "explanation": "explanation " * 500,
        })

        self.assertLessEqual(len(formatted), 4000)
        self.assertIn("1930", formatted)
        self.assertIn("Safety advice", formatted)


if __name__ == "__main__":
    unittest.main()
