import unittest

from app.predictors import _url_model_probabilities, fuse_all


class MultimodalFusionTests(unittest.TestCase):
    def test_ocr_uses_the_stronger_text_score(self):
        result = fuse_all(text_p=0.7, url_p_bin=None, img_p=None, ocr_p=0.4)

        self.assertEqual(result["fused_prob"], 0.7)
        self.assertEqual(result["label"], "phishing")

    def test_remaining_weight_is_shared_with_other_modalities(self):
        result = fuse_all(
            text_p=0.8,
            url_p_bin=0.2,
            img_p=None,
            ocr_p=0.3,
            alpha=0.75,
        )

        self.assertEqual(result["fused_prob"], 0.65)

    def test_no_available_signal_keeps_the_existing_benign_default(self):
        result = fuse_all(text_p=None, url_p_bin=None, img_p=None)

        self.assertEqual(result["fused_prob"], 0.0)
        self.assertEqual(result["label"], "benign")


class UrlModelScoreTests(unittest.TestCase):
    def test_three_class_scores_keep_the_existing_url_class_order(self):
        self.assertEqual(
            _url_model_probabilities([0.1, 0.6, 0.3]),
            {"benign": 0.1, "phishing": 0.6, "malware": 0.3},
        )

    def test_two_class_scores_keep_the_existing_malware_default(self):
        self.assertEqual(
            _url_model_probabilities([0.2, 0.8]),
            {"benign": 0.2, "phishing": 0.8, "malware": 0.0},
        )
        self.assertIsNone(_url_model_probabilities([0.2]))


if __name__ == "__main__":
    unittest.main()
