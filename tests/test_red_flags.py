import unittest
from unittest.mock import patch

from app.main import TextRequest, URLRequest, image_check, text_check, url_check
from app.red_flags import detect_red_flags


class RedFlagDetectionTests(unittest.TestCase):
    def test_detects_urgency_and_payment_language(self):
        flags = detect_red_flags("URGENT: act now and pay by gift card.")
        codes = {flag["code"] for flag in flags}
        self.assertIn("urgency_language", codes)
        self.assertIn("payment_request", codes)

    def test_detects_shortened_urls(self):
        flags = detect_red_flags("Visit https://bit.ly/abc123")
        self.assertIn("url_shortener", {flag["code"] for flag in flags})

    def test_detects_idn_homograph_domain(self):
        homograph = "\u0440\u0430\u0443\u0440\u0430l.com"
        flags = detect_red_flags(homograph)
        self.assertIn("unicode_domain", {flag["code"] for flag in flags})
        self.assertIn("lookalike_domain", {flag["code"] for flag in flags})

    def test_detects_ascii_lookalike_domain(self):
        flags = detect_red_flags("https://paypa1-login.example")
        self.assertIn("lookalike_domain", {flag["code"] for flag in flags})

    def test_detects_mismatched_anchor_destination(self):
        html = '<a href="https://evil.example/login">https://paypal.com</a>'
        flags = detect_red_flags(html)
        mismatch = next(flag for flag in flags if flag["code"] == "link_href_mismatch")
        self.assertEqual(mismatch["severity"], "high")
        self.assertIn("evil.example", mismatch["evidence"])
        self.assertIn("paypal.com", mismatch["evidence"])

    def test_detects_external_post_but_not_same_site_post(self):
        external = '<form method="post" action="https://collector.example/submit"></form>'
        flags = detect_red_flags(external, target_url="https://merchant.example/login")
        self.assertIn("external_form_post", {flag["code"] for flag in flags})

        same_site = '<form method="post" action="https://forms.merchant.example/submit"></form>'
        flags = detect_red_flags(same_site, target_url="https://merchant.example/login")
        self.assertNotIn("external_form_post", {flag["code"] for flag in flags})

    def test_every_flag_has_the_public_schema(self):
        flags = detect_red_flags("Urgent payment: pay now.")
        self.assertTrue(flags)
        for flag in flags:
            self.assertEqual(set(flag), {"code", "label", "severity", "evidence"})
            self.assertIn(flag["severity"], {"low", "medium", "high"})
            self.assertTrue(flag["evidence"])


class DetectionResponseTests(unittest.TestCase):
    def test_text_response_adds_metadata_without_removing_existing_fields(self):
        probs = {"benign": 0.2, "phishing": 0.8}
        with patch("app.main.predict_text_probs", return_value=probs), patch(
            "app.main.make_llm_explanation", return_value="Explanation"
        ):
            response = text_check(TextRequest(text="URGENT: pay now with a gift card."))

        self.assertEqual(response["label"], "phishing")
        self.assertEqual(response["probs"], probs)
        self.assertEqual(response["confidence"], 0.8)
        self.assertEqual(response["explanation"], "Explanation")
        self.assertIn("payment_request", {flag["code"] for flag in response["red_flags"]})
        self.assertEqual(response["intent"], "text_message")

    def test_url_response_keeps_existing_fields_and_adds_red_flags(self):
        probs = {"benign": 0.1, "phishing": 0.8, "malware": 0.1}
        with patch("app.main.predict_url_probs", return_value=probs), patch(
            "app.main.make_llm_explanation", return_value="Explanation"
        ):
            response = url_check(URLRequest(url="https://bit.ly/abc"))

        self.assertEqual(response["label"], "phishing")
        self.assertEqual(response["probs"], probs)
        self.assertEqual(response["confidence"], 0.8)
        self.assertEqual(response["explanation"], "Explanation")
        self.assertIn("url_shortener", {flag["code"] for flag in response["red_flags"]})
        self.assertEqual(response["intent"], "url_check")

    def test_image_response_adds_confidence_and_red_flags_from_ocr(self):
        class Upload:
            async def read(self):
                return b"image"

        probs = {"benign": 0.2, "phishing": 0.8}

        async def run_endpoint():
            with patch("app.main.get_ocr_text_from_bytes", return_value="Urgent, pay now"), patch(
                "app.main.predict_image_probs", return_value=probs
            ), patch("app.main.make_llm_explanation", return_value="Explanation"):
                return await image_check(Upload())

        import asyncio

        response = asyncio.run(run_endpoint())
        self.assertEqual(response["label"], "phishing")
        self.assertEqual(response["confidence"], 0.8)
        self.assertIn("urgency_language", {flag["code"] for flag in response["red_flags"]})
        self.assertIn("payment_request", {flag["code"] for flag in response["red_flags"]})


if __name__ == "__main__":
    unittest.main()
