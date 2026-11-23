import asyncio
import unittest
from unittest.mock import patch

from app.main import TextRequest, URLRequest, chat_multipart, image_check, text_check, url_check
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

    def test_detects_callback_phishing_without_urls(self):
        message = "Your auto-renewal invoice is due. Call 800.555.0199 to cancel."
        flags = detect_red_flags(message)

        callback = next(flag for flag in flags if flag["code"] == "TOAD_CALLBACK")
        self.assertEqual(callback["severity"], "high")
        self.assertIn("800.555.0199", callback["evidence"])

        with_url = detect_red_flags(
            "Your invoice is due. Call 800.555.0199 or visit https://billing.example.com."
        )
        self.assertNotIn("TOAD_CALLBACK", {flag["code"] for flag in with_url})

    def test_detects_sensitive_requests_on_trusted_platforms(self):
        form_url = "https://docs.google.com/forms/d/e/example/viewform"
        flags = detect_red_flags(f"Enter your password and OTP here: {form_url}")

        abuse = next(flag for flag in flags if flag["code"] == "TRUSTED_PLATFORM_ABUSE")
        self.assertEqual(abuse["severity"], "high")
        self.assertIn("docs.google.com", abuse["evidence"])

        kyc_url = "https://forms.office.com/r/example"
        kyc_flags = detect_red_flags(f"Upload your KYC documents here: {kyc_url}")
        self.assertIn("TRUSTED_PLATFORM_ABUSE", {flag["code"] for flag in kyc_flags})

        for platform_url in (
            "https://forms.office.com/r/example",
            "https://attacker.notion.site/form",
            "https://www.canva.com/design/example",
            "https://attacker.github.io/form",
            "https://attacker.vercel.app/form",
        ):
            platform_flags = detect_red_flags(
                f"Provide your payment information here: {platform_url}"
            )
            self.assertIn(
                "TRUSTED_PLATFORM_ABUSE",
                {flag["code"] for flag in platform_flags},
                platform_url,
            )

        harmless = detect_red_flags("Read the public guide at https://docs.google.com/document/d/example")
        self.assertNotIn("TRUSTED_PLATFORM_ABUSE", {flag["code"] for flag in harmless})

    def test_detects_sensitive_oauth_scopes_and_device_code_requests(self):
        oauth_url = (
            "https://login.example.com/authorize?client_id=abc"
            "&scope=openid%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly"
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback"
        )
        oauth_flags = detect_red_flags(f"Continue sign-in: {oauth_url}")
        self.assertIn("OAUTH_DEVICE_PHISHING", {flag["code"] for flag in oauth_flags})

        benign_oauth_url = (
            "https://login.example.com/authorize?client_id=abc"
            "&scope=openid%20profile"
            "&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback"
        )
        benign_oauth_flags = detect_red_flags(f"Continue sign-in: {benign_oauth_url}")
        self.assertNotIn(
            "OAUTH_DEVICE_PHISHING",
            {flag["code"] for flag in benign_oauth_flags},
        )

        code_flags = detect_red_flags("Please send us your device login code to continue.")
        self.assertIn("OAUTH_DEVICE_PHISHING", {flag["code"] for flag in code_flags})

        warning = detect_red_flags("Do not share your device login code with anyone.")
        self.assertNotIn("OAUTH_DEVICE_PHISHING", {flag["code"] for flag in warning})

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

    def test_chat_multipart_text_scan_keeps_the_detection_response_shape(self):
        probs = {"benign": 0.2, "phishing": 0.8}
        with patch("app.main.detect_intent", return_value="text_message"), patch(
            "app.main.extract_single_url", return_value=None
        ), patch("app.main.predict_text_probs", return_value=probs), patch(
            "app.main.make_llm_explanation", return_value="Explanation"
        ):
            response = asyncio.run(
                chat_multipart(query="Your account is locked", file=None)
            )

        self.assertEqual(response["label"], "phishing")
        self.assertEqual(response["probs"], probs)
        self.assertEqual(response["confidence"], 0.8)
        self.assertEqual(response["intent"], "text_message")

    def test_chat_multipart_combines_text_and_image_predictions(self):
        class Upload:
            async def read(self):
                return b"image bytes"

        async def run_endpoint():
            with patch("app.main.detect_intent", return_value="combined"), patch(
                "app.main.extract_single_url", return_value=None
            ), patch("app.main.get_ocr_text_from_bytes", return_value="image text"), patch(
                "app.main.predict_text_probs",
                return_value={"benign": 0.7, "phishing": 0.3},
            ), patch(
                "app.main.predict_image_probs",
                return_value={"benign": 0.8, "phishing": 0.2},
            ), patch("app.main.make_llm_explanation", return_value="Combined explanation"):
                return await chat_multipart(query="Meeting details", file=Upload())

        response = asyncio.run(run_endpoint())

        self.assertEqual(response["label"], "benign")
        self.assertEqual(response["probs"], {"benign": 0.72, "phishing": 0.28})
        self.assertEqual(response["ocr"], "image text")
        self.assertEqual(response["intent"], "combined")


if __name__ == "__main__":
    unittest.main()
