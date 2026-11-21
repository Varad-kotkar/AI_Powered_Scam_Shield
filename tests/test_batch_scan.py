import asyncio
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import batch_scan
from app.batch_scan import BatchInput, BatchScanResult


class BatchFileParsingTests(unittest.TestCase):
    def test_txt_lines_classify_urls_separately_from_messages(self):
        records = batch_scan.parse_batch_file(
            "items.txt",
            b"Urgent: verify your account now\nhttps://example.com/login\nwww.example.org",
        )
        self.assertEqual([item.kind for item in records], ["text", "url", "url"])
        self.assertEqual([item.index for item in records], [0, 1, 2])

    def test_csv_headers_select_message_and_url_fields(self):
        records = batch_scan.parse_batch_file(
            "items.csv",
            b"message,url\n\"Verify now\",https://example.com/login\n,https://bit.ly/abc\n",
        )
        self.assertEqual(records[0].content, "Verify now\nhttps://example.com/login")
        self.assertEqual(records[0].kind, "text")
        self.assertEqual(records[1].content, "https://bit.ly/abc")
        self.assertEqual(records[1].kind, "url")

    def test_csv_without_headers_scans_each_row(self):
        records = batch_scan.parse_batch_file("items.csv", b"hello,world\nhttps://example.com,\n")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].content, "hello world")
        self.assertEqual(records[1].kind, "url")

    def test_rejects_unsupported_extensions_and_invalid_utf8(self):
        with self.assertRaises(ValueError):
            batch_scan.parse_batch_file("items.xlsx", b"ignored")
        with self.assertRaises(ValueError):
            batch_scan.parse_batch_file("items.txt", b"\xff")

    def test_rejects_oversized_records(self):
        with self.assertRaises(ValueError):
            batch_scan.parse_batch_file("items.txt", ("x" * 10001).encode())


class LocalReviewStoreTests(unittest.TestCase):
    def test_allowlisted_record_skips_model_prediction(self):
        entry = batch_scan.AllowlistEntry(
            id="entry",
            kind="domain",
            value="example.com",
            created_at="now",
        )
        record = BatchInput(index=0, content="https://sub.example.com/login", kind="url")
        with patch.object(batch_scan, "predict_text_probs", side_effect=AssertionError), patch.object(
            batch_scan, "predict_url_probs", side_effect=AssertionError
        ):
            result = batch_scan._scan_record(record, "job", [entry])

        self.assertTrue(result.allowlisted)
        self.assertEqual(result.label, "benign")
        self.assertEqual(result.allowlist_entry_id, "entry")

    def test_allowlist_matching_and_false_positive_feedback_are_persistent(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(batch_scan, "DB_PATH", Path(directory) / "local.sqlite3"):
                entry = batch_scan.add_allowlist_entry("domain", "example.com")
                entries = batch_scan.list_allowlist_entries()
                self.assertEqual(len(entries), 1)
                self.assertEqual(
                    batch_scan.find_allowlist_match("https://sub.example.com/login", entries),
                    entry.id,
                )
                self.assertIsNone(batch_scan.find_allowlist_match("https://notexample.com", entries))

                result = BatchScanResult(
                    item_id="job-0",
                    index=0,
                    input="suspicious message",
                    kind="text",
                    label="phishing",
                    confidence=0.9,
                    probs={"benign": 0.1, "phishing": 0.9},
                    explanation="Explanation",
                    red_flags=[],
                )
                first = batch_scan.record_false_positive("job", result, "Reviewed by analyst")
                second = batch_scan.record_false_positive("job", result, "Reviewed by analyst")
                self.assertEqual(first.id, second.id)
                self.assertEqual(len(batch_scan.list_false_positive_feedback()), 1)
                self.assertEqual(batch_scan.list_false_positive_feedback()[0].reason, "Reviewed by analyst")
                self.assertTrue(batch_scan.delete_allowlist_entry(entry.id))
                self.assertEqual(batch_scan.list_allowlist_entries(), [])

    def test_false_positive_endpoint_persists_feedback_and_updates_result(self):
        with tempfile.TemporaryDirectory() as directory:
            job_id = "feedback-job"
            result = BatchScanResult(
                item_id=f"{job_id}-0",
                index=0,
                input="suspicious message",
                kind="text",
                label="phishing",
                confidence=0.9,
                probs={"benign": 0.1, "phishing": 0.9},
                explanation="Explanation",
                red_flags=[],
            )
            job = batch_scan._BatchJob(
                job_id=job_id,
                status="completed",
                total=1,
                completed=1,
                results={0: result},
            )
            batch_scan._jobs[job_id] = job
            try:
                with patch.object(batch_scan, "DB_PATH", Path(directory) / "local.sqlite3"):
                    response = asyncio.run(
                        batch_scan.mark_batch_false_positive(
                            job_id,
                            result.item_id,
                            batch_scan.FalsePositiveRequest(reason="Reviewed"),
                        )
                    )

                    self.assertEqual(response.reason, "Reviewed")
                    self.assertTrue(result.feedback_submitted)
                    self.assertEqual(len(batch_scan.list_false_positive_feedback()), 1)
            finally:
                batch_scan._jobs.pop(job_id, None)

    def test_url_allowlist_ignores_tracking_query_parameters(self):
        entry = batch_scan.AllowlistEntry(
            id="entry",
            kind="url",
            value="https://example.com/login",
            created_at="now",
        )
        self.assertEqual(
            batch_scan.find_allowlist_match(
                "Open https://example.com/login?campaign=mail",
                [entry],
            ),
            "entry",
        )


class BatchConcurrencyTests(unittest.TestCase):
    def test_active_job_limit_is_enforced_after_upload_reads(self):
        class DelayedUpload:
            filename = "items.txt"

            async def read(self, limit):
                await asyncio.sleep(0.01)
                return b"message"

        async def hold_job(job, records):
            await asyncio.Event().wait()

        async def submit_jobs():
            return await asyncio.gather(
                *[batch_scan.start_batch_scan(DelayedUpload()) for _ in range(5)],
                return_exceptions=True,
            )

        with patch.object(batch_scan, "_jobs", {}), patch.object(
            batch_scan, "MAX_ACTIVE_BATCH_JOBS", 2
        ), patch.object(batch_scan, "_process_job", side_effect=hold_job):
            responses = asyncio.run(submit_jobs())

        accepted = [item for item in responses if isinstance(item, batch_scan.BatchScanStatus)]
        rejected = [item for item in responses if isinstance(item, Exception)]
        self.assertEqual(len(accepted), 2)
        self.assertEqual([item.status_code for item in rejected], [429, 429, 429])

    def test_worker_respects_concurrency_and_reports_progress(self):
        jobs = [
            batch_scan._BatchJob(job_id=f"job-{job_number}", status="queued", total=4)
            for job_number in range(2)
        ]
        active = 0
        max_active = 0
        lock = threading.Lock()

        def fake_scan(record, job_id, allowlist):
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return BatchScanResult(
                item_id=f"{job_id}-{record.index}",
                index=record.index,
                input=record.content,
                kind=record.kind,
                label="benign",
                confidence=0.8,
                probs={"benign": 0.8, "phishing": 0.2},
                explanation="Scanned",
                red_flags=[],
            )

        records = [
            [BatchInput(index=index, content=f"message {index}", kind="text") for index in range(4)]
            for _ in jobs
        ]
        with patch.object(batch_scan, "BATCH_CONCURRENCY", 2), patch.object(
            batch_scan, "list_allowlist_entries", return_value=[]
        ), patch.object(batch_scan, "_scan_record", side_effect=fake_scan):
            async def process_jobs():
                await asyncio.gather(*[
                    batch_scan._process_job(job, job_records)
                    for job, job_records in zip(jobs, records)
                ])

            asyncio.run(process_jobs())

        self.assertLessEqual(max_active, 2)
        self.assertGreater(max_active, 1)
        for job in jobs:
            self.assertEqual(job.status, "completed")
            self.assertEqual(job.completed, 4)
            status = batch_scan._job_status(job)
            self.assertEqual(status.progress, 100.0)
            self.assertEqual(len(status.results), 4)


if __name__ == "__main__":
    unittest.main()
