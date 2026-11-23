import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.clean_dataset import clean_file, clean_records, main as clean_main, normalize_url


class DatasetCleaningTests(unittest.TestCase):
    def test_normalizes_text_labels_urls_and_removes_empty_duplicates(self):
        records = [
            {
                "id": "row-1",
                "content": "  Ｕrgent\tpay   now ",
                "url": "HTTP://Example.COM/A/",
                "label": "Phishing",
            },
            {
                "id": "row-2",
                "content": "Urgent pay now",
                "url": "http://example.com/A/",
                "label": "scam",
            },
            {"id": "empty", "content": "   ", "label": ""},
        ]

        cleaned, empty_count, duplicate_count = clean_records(records)

        self.assertEqual(empty_count, 1)
        self.assertEqual(duplicate_count, 1)
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(cleaned[0]["content"], "Urgent pay now")
        self.assertEqual(cleaned[0]["url"], "http://example.com/A/")
        self.assertEqual(cleaned[0]["label"], "scam")

    def test_adds_https_to_bare_domains(self):
        self.assertEqual(normalize_url("Example.COM"), "https://example.com")

    def test_command_line_prints_counts_and_saves_cleaned_output(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            input_path = root / "raw.json"
            output_path = root / "raw_cleaned.json"
            input_path.write_text(
                json.dumps([
                    {"id": "1", "content": "Hello"},
                    {"id": "2", "content": "Hello"},
                    {"id": "3", "content": "   "},
                ]),
                encoding="utf-8",
            )
            output = io.StringIO()

            with patch("sys.argv", ["clean_dataset.py", str(input_path)]):
                with redirect_stdout(output):
                    clean_main()

            self.assertTrue(output_path.is_file())
            self.assertIn("Records before cleaning: 3", output.getvalue())
            self.assertIn("Empty records removed: 1", output.getvalue())
            self.assertIn("Duplicate records removed: 1", output.getvalue())
            self.assertIn("Records after cleaning: 1", output.getvalue())

    def test_clean_file_preserves_json_wrapper_and_writes_csv(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            json_input = root / "raw.json"
            json_output = root / "clean.json"
            json_input.write_text(
                json.dumps({
                    "dataset_version": 1,
                    "samples": [{"content": "  Hello   world ", "label": "Benign"}],
                }),
                encoding="utf-8",
            )

            counts = clean_file(json_input, json_output)
            cleaned_json = json.loads(json_output.read_text(encoding="utf-8"))
            self.assertEqual(counts, (1, 0, 0, 1))
            self.assertEqual(cleaned_json["dataset_version"], 1)
            self.assertEqual(cleaned_json["samples"][0]["content"], "Hello world")
            self.assertEqual(cleaned_json["samples"][0]["label"], "legitimate")

            csv_input = root / "raw.csv"
            csv_output = root / "clean.csv"
            csv_input.write_text(
                "content,label,url\nMessage,SAFE,Example.COM\n",
                encoding="utf-8",
            )
            clean_file(csv_input, csv_output)
            with csv_output.open("r", encoding="utf-8", newline="") as source:
                rows = list(csv.DictReader(source))

            self.assertEqual(rows[0]["label"], "legitimate")
            self.assertEqual(rows[0]["url"], "https://example.com")


if __name__ == "__main__":
    unittest.main()
