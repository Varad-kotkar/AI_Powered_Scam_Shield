import asyncio
import csv
import io
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.llm_helpers import make_llm_explanation
from app.predictors import (
    fuse_all,
    predict_text_probs,
    predict_url_probs,
    url_multiclass_to_binary,
)
from app.red_flags import detect_red_flags, extract_urls

logger = logging.getLogger(__name__)
batch_router = APIRouter()

MAX_BATCH_FILE_BYTES = 5 * 1024 * 1024
MAX_BATCH_RECORDS = 500
BATCH_CONCURRENCY = min(16, max(1, int(os.getenv("MM_BATCH_CONCURRENCY", "4"))))
MAX_ACTIVE_BATCH_JOBS = 3
MAX_BATCH_JOB_HISTORY = 30
TEXT_HEADERS = {"message", "text", "content", "email", "sms", "body"}
URL_HEADERS = {"url", "link", "website"}
TEXT_HEADER_ORDER = ("message", "text", "content", "email", "sms", "body")
URL_HEADER_ORDER = ("url", "link", "website")
REPO_ROOT = Path(__file__).resolve().parent.parent


class BatchInput(BaseModel):
    index: int
    content: str
    kind: Literal["text", "url"]


class BatchScanResult(BaseModel):
    item_id: str
    index: int
    input: str
    kind: Literal["text", "url"]
    label: str
    confidence: float
    probs: Dict[str, float]
    explanation: str
    red_flags: List[Dict[str, str]]
    allowlisted: bool = False
    allowlist_entry_id: Optional[str] = None
    feedback_submitted: bool = False
    error: Optional[str] = None


class BatchScanStatus(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    total: int
    completed: int
    progress: float
    results: List[BatchScanResult]
    error: Optional[str] = None


class AllowlistEntryCreate(BaseModel):
    kind: Literal["domain", "url", "text"]
    value: str = Field(min_length=1, max_length=512)


class AllowlistEntry(BaseModel):
    id: str
    kind: Literal["domain", "url", "text"]
    value: str
    created_at: str


class FalsePositiveRequest(BaseModel):
    reason: str = Field(default="", max_length=1000)


class FalsePositiveFeedback(BaseModel):
    id: str
    job_id: str
    item_id: str
    input: str
    predicted_label: str
    confidence: float
    reason: str
    red_flags: List[Dict[str, str]]
    created_at: str


@dataclass
class _BatchJob:
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    total: int
    completed: int = 0
    results: Dict[int, BatchScanResult] = field(default_factory=dict)
    error: Optional[str] = None
    task: Optional[asyncio.Task] = None
    created_at: float = field(default_factory=time.monotonic)


_jobs: Dict[str, _BatchJob] = {}
_scan_semaphore: Optional[asyncio.Semaphore] = None
_scan_semaphore_loop: Optional[asyncio.AbstractEventLoop] = None


def _default_store_path() -> Path:
    configured = os.getenv("MM_LOCAL_STORE_PATH", "").strip()
    if not configured:
        return REPO_ROOT / "data" / "scam_shield_local.sqlite3"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


DB_PATH = _default_store_path()


def parse_batch_file(filename: str, content: bytes) -> List[BatchInput]:
    extension = Path(filename).suffix.lower()
    if extension not in {".csv", ".txt"}:
        raise ValueError("Choose a .csv or .txt file.")
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("The file must use UTF-8 encoding.") from error

    values: List[Tuple[str, Literal["text", "url"]]] = []
    if extension == ".txt":
        for line in decoded.splitlines():
            value = line.strip()
            if value:
                url = _extract_batch_url(value)
                kind: Literal["text", "url"] = "url" if url and _is_url_only(value, url) else "text"
                values.append((value, kind))
    else:
        try:
            rows = list(csv.reader(io.StringIO(decoded)))
        except csv.Error as error:
            raise ValueError("The CSV file could not be parsed.") from error

        if rows:
            headers = [header.strip().casefold() for header in rows[0]]
            has_known_headers = any(header in TEXT_HEADERS | URL_HEADERS for header in headers)
            data_rows = rows[1:] if has_known_headers else rows
            for row in data_rows:
                if has_known_headers:
                    cells = {
                        headers[index]: value.strip()
                        for index, value in enumerate(row)
                        if index < len(headers) and value.strip()
                    }
                    text_parts = [cells[name] for name in TEXT_HEADER_ORDER if cells.get(name)]
                    url_parts = [cells[name] for name in URL_HEADER_ORDER if cells.get(name)]
                    parts = text_parts + url_parts
                    value = "\n".join(parts)
                    kind = "url" if url_parts and not text_parts else "text"
                else:
                    value = " ".join(cell.strip() for cell in row if cell.strip())
                    url = _extract_batch_url(value)
                    kind = "url" if url and _is_url_only(value, url) else "text"
                if value:
                    values.append((value, kind))

    if not values:
        raise ValueError("The file contains no messages or URLs to scan.")
    if len(values) > MAX_BATCH_RECORDS:
        raise ValueError(f"A batch may contain at most {MAX_BATCH_RECORDS} records.")
    if any(len(value) > 10000 for value, _ in values):
        raise ValueError("Each message or URL must be 10,000 characters or fewer.")

    return [
        BatchInput(index=index, content=value, kind=kind)
        for index, (value, kind) in enumerate(values)
    ]


def _is_url_only(value: str, url: str) -> bool:
    value = value.strip().rstrip(".,;:!?)]}")
    url = url.strip().rstrip(".,;:!?)]}")
    without_scheme = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    alternatives = {url, without_scheme, without_scheme.removeprefix("www.")}
    return value.rstrip("/").casefold() in {item.rstrip("/").casefold() for item in alternatives}


def _extract_batch_url(content: str) -> Optional[str]:
    urls = extract_urls(content)
    return urls[0] if urls else None


def _canonical_host(value: str) -> Optional[str]:
    candidate = value.strip()
    if not candidate:
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.IGNORECASE):
        candidate = "https://" + candidate
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return host.lower().removeprefix("www.") if host else None


def _normalize_allowlist_value(kind: str, value: str) -> str:
    cleaned = " ".join(value.split()).strip()
    if kind == "text":
        if not cleaned:
            raise ValueError("Allowlisted text cannot be empty.")
        return cleaned.casefold()
    host = _canonical_host(cleaned)
    if not host:
        raise ValueError("Enter a valid domain or URL.")
    if kind == "domain":
        return host
    parsed = urlsplit(cleaned if "://" in cleaned else "https://" + cleaned)
    return f"{host}{parsed.path.rstrip('/')}"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DB_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS local_allowlist (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(kind, normalized_value)
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS false_positive_feedback (
            id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            input TEXT NOT NULL,
            predicted_label TEXT NOT NULL,
            confidence REAL NOT NULL,
            reason TEXT NOT NULL,
            red_flags_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(job_id, item_id)
        )"""
    )
    connection.commit()
    return connection


def list_allowlist_entries() -> List[AllowlistEntry]:
    connection = _connect()
    try:
        rows = connection.execute(
            "SELECT id, kind, value, created_at FROM local_allowlist ORDER BY created_at DESC"
        ).fetchall()
        return [AllowlistEntry(**dict(row)) for row in rows]
    finally:
        connection.close()


def add_allowlist_entry(kind: str, value: str) -> AllowlistEntry:
    normalized = _normalize_allowlist_value(kind, value)
    entry = AllowlistEntry(
        id=uuid.uuid4().hex,
        kind=kind,  # validated by the request model
        value=value.strip(),
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    connection = _connect()
    try:
        connection.execute(
            "INSERT INTO local_allowlist (id, kind, value, normalized_value, created_at) VALUES (?, ?, ?, ?, ?)",
            (entry.id, entry.kind, entry.value, normalized, entry.created_at),
        )
        connection.commit()
        return entry
    finally:
        connection.close()


def delete_allowlist_entry(entry_id: str) -> bool:
    connection = _connect()
    try:
        cursor = connection.execute("DELETE FROM local_allowlist WHERE id = ?", (entry_id,))
        connection.commit()
        return cursor.rowcount > 0
    finally:
        connection.close()


def find_allowlist_match(content: str, entries: List[AllowlistEntry]) -> Optional[str]:
    normalized_text = " ".join(content.split()).casefold()
    extracted_url = _extract_batch_url(content)
    for entry in entries:
        normalized_value = _normalize_allowlist_value(entry.kind, entry.value)
        if entry.kind == "text" and normalized_text == normalized_value:
            return entry.id
        if entry.kind == "url" and extracted_url:
            if _normalize_allowlist_value("url", extracted_url) == normalized_value:
                return entry.id
        if entry.kind == "domain":
            host = _canonical_host(extracted_url or content)
            if host and (host == normalized_value or host.endswith("." + normalized_value)):
                return entry.id
    return None


def record_false_positive(
    job_id: str,
    result: BatchScanResult,
    reason: str,
) -> FalsePositiveFeedback:
    feedback_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()
    connection = _connect()
    try:
        connection.execute(
            """INSERT OR IGNORE INTO false_positive_feedback
            (id, job_id, item_id, input, predicted_label, confidence, reason, red_flags_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                feedback_id,
                job_id,
                result.item_id,
                result.input,
                result.label,
                result.confidence,
                reason,
                json.dumps(result.red_flags),
                created_at,
            ),
        )
        connection.commit()
        row = connection.execute(
            """SELECT id, job_id, item_id, input, predicted_label, confidence, reason, red_flags_json, created_at
            FROM false_positive_feedback WHERE job_id = ? AND item_id = ?""",
            (job_id, result.item_id),
        ).fetchone()
        if row is None:
            raise RuntimeError("The false-positive record was not persisted.")
        return FalsePositiveFeedback(
            id=row["id"],
            job_id=row["job_id"],
            item_id=row["item_id"],
            input=row["input"],
            predicted_label=row["predicted_label"],
            confidence=row["confidence"],
            reason=row["reason"],
            red_flags=json.loads(row["red_flags_json"]),
            created_at=row["created_at"],
        )
    finally:
        connection.close()


def list_false_positive_feedback(limit: int = 100) -> List[FalsePositiveFeedback]:
    connection = _connect()
    try:
        rows = connection.execute(
            """SELECT id, job_id, item_id, input, predicted_label, confidence, reason, red_flags_json, created_at
            FROM false_positive_feedback ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            FalsePositiveFeedback(
                id=row["id"],
                job_id=row["job_id"],
                item_id=row["item_id"],
                input=row["input"],
                predicted_label=row["predicted_label"],
                confidence=row["confidence"],
                reason=row["reason"],
                red_flags=json.loads(row["red_flags_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]
    finally:
        connection.close()


def _scan_record(record: BatchInput, job_id: str, allowlist: List[AllowlistEntry]) -> BatchScanResult:
    item_id = f"{job_id}-{record.index}"
    allowlist_entry_id = find_allowlist_match(record.content, allowlist)
    if allowlist_entry_id:
        return BatchScanResult(
            item_id=item_id,
            index=record.index,
            input=record.content,
            kind=record.kind,
            label="benign",
            confidence=1.0,
            probs={"benign": 1.0, "phishing": 0.0},
            explanation="Matched a locally allowlisted entry; no model scan was run.",
            red_flags=[],
            allowlisted=True,
            allowlist_entry_id=allowlist_entry_id,
        )

    extracted_url = _extract_batch_url(record.content)
    url_only = record.kind == "url" or (extracted_url and _is_url_only(record.content, extracted_url))
    text_probs = None if url_only else predict_text_probs(record.content)
    url_probs = predict_url_probs(extracted_url) if extracted_url else None

    if url_only and url_probs:
        probs = url_probs
        label = max(probs, key=probs.get)
    elif text_probs and url_probs:
        fusion = fuse_all(
            text_probs.get("phishing"),
            url_multiclass_to_binary(url_probs),
            None,
        )
        probs = fusion["probs"]
        label = fusion["label"]
    elif text_probs:
        probs = text_probs
        label = "phishing" if probs.get("phishing", 0.0) >= probs.get("benign", 0.0) else "benign"
    elif url_probs:
        probs = url_probs
        label = max(probs, key=probs.get)
    else:
        raise ValueError("No text or URL could be extracted from this record.")

    confidence = float(probs.get(label, max(probs.values(), default=0.0)))
    red_flags = detect_red_flags(record.content, target_url=extracted_url)
    summary = {
        "content": record.content,
        "label": label,
        "probs": probs,
        "raw_text": text_probs,
        "raw_url": url_probs,
        "red_flags": red_flags,
    }
    return BatchScanResult(
        item_id=item_id,
        index=record.index,
        input=record.content,
        kind=record.kind,
        label=label,
        confidence=round(confidence, 4),
        probs=probs,
        explanation=make_llm_explanation(summary),
        red_flags=red_flags,
    )


async def _process_job(job: _BatchJob, records: List[BatchInput]) -> None:
    job.status = "running"
    try:
        allowlist = await asyncio.to_thread(list_allowlist_entries)
        semaphore = _get_scan_semaphore()

        async def scan(record: BatchInput) -> None:
            async with semaphore:
                try:
                    result = await asyncio.to_thread(_scan_record, record, job.job_id, allowlist)
                except Exception:
                    logger.exception("Batch scan failed for job %s item %s", job.job_id, record.index)
                    result = BatchScanResult(
                        item_id=f"{job.job_id}-{record.index}",
                        index=record.index,
                        input=record.content,
                        kind=record.kind,
                        label="error",
                        confidence=0.0,
                        probs={},
                        explanation="This item could not be scanned; review the backend log for details.",
                        red_flags=[],
                        error="Scan failed",
                    )
                job.results[record.index] = result
                job.completed += 1

        await asyncio.gather(*(scan(record) for record in records))
        job.status = "completed"
    except Exception:
        logger.exception("Batch scan job %s failed", job.job_id)
        job.status = "failed"
        job.error = "Batch processing failed; review the backend log for details."
    finally:
        _prune_job_history()


def _job_status(job: _BatchJob) -> BatchScanStatus:
    progress = round((job.completed / job.total) * 100, 1) if job.total else 100.0
    return BatchScanStatus(
        job_id=job.job_id,
        status=job.status,
        total=job.total,
        completed=job.completed,
        progress=progress,
        results=[job.results[index] for index in sorted(job.results)],
        error=job.error,
    )


def _prune_job_history() -> None:
    completed_jobs = sorted(
        (job for job in _jobs.values() if job.status in {"completed", "failed"}),
        key=lambda job: job.created_at,
    )
    for job in completed_jobs[:-MAX_BATCH_JOB_HISTORY]:
        _jobs.pop(job.job_id, None)


def _get_scan_semaphore() -> asyncio.Semaphore:
    global _scan_semaphore, _scan_semaphore_loop
    loop = asyncio.get_running_loop()
    semaphore = _scan_semaphore
    if semaphore is None or _scan_semaphore_loop is not loop:
        semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)
        _scan_semaphore = semaphore
        _scan_semaphore_loop = loop
    return semaphore


@batch_router.post("/batch_scan", response_model=BatchScanStatus, status_code=202)
async def start_batch_scan(file: UploadFile = File(...)) -> BatchScanStatus:
    if sum(job.status in {"queued", "running"} for job in _jobs.values()) >= MAX_ACTIVE_BATCH_JOBS:
        raise HTTPException(status_code=429, detail="Too many active batch scans. Try again when one finishes.")
    filename = file.filename or ""
    if Path(filename).suffix.lower() not in {".csv", ".txt"}:
        raise HTTPException(status_code=415, detail="Choose a .csv or .txt file.")
    content = await file.read(MAX_BATCH_FILE_BYTES + 1)
    if len(content) > MAX_BATCH_FILE_BYTES:
        raise HTTPException(status_code=413, detail="Batch files must be 5 MB or smaller.")
    try:
        records = parse_batch_file(filename, content)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    if sum(job.status in {"queued", "running"} for job in _jobs.values()) >= MAX_ACTIVE_BATCH_JOBS:
        raise HTTPException(status_code=429, detail="Too many active batch scans. Try again when one finishes.")
    job_id = uuid.uuid4().hex
    job = _BatchJob(job_id=job_id, status="queued", total=len(records))
    _prune_job_history()
    _jobs[job_id] = job
    job.task = asyncio.create_task(_process_job(job, records))
    return _job_status(job)


@batch_router.get("/batch_scan/{job_id}", response_model=BatchScanStatus)
async def get_batch_scan(job_id: str) -> BatchScanStatus:
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Batch scan not found.")
    return _job_status(job)


@batch_router.post(
    "/batch_scan/{job_id}/results/{item_id}/false_positive",
    response_model=FalsePositiveFeedback,
)
async def mark_batch_false_positive(
    job_id: str,
    item_id: str,
    request: FalsePositiveRequest,
) -> FalsePositiveFeedback:
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Batch scan not found.")
    result = next((item for item in job.results.values() if item.item_id == item_id), None)
    if not result:
        raise HTTPException(status_code=404, detail="Batch result not found.")
    if result.error:
        raise HTTPException(status_code=409, detail="Failed scans cannot be marked as false positives.")
    feedback = await asyncio.to_thread(record_false_positive, job_id, result, request.reason)
    result.feedback_submitted = True
    return feedback


@batch_router.get("/feedback/false-positives", response_model=List[FalsePositiveFeedback])
def get_false_positive_feedback(
    limit: int = Query(default=100, ge=1, le=500),
) -> List[FalsePositiveFeedback]:
    return list_false_positive_feedback(limit)


@batch_router.get("/allowlist", response_model=List[AllowlistEntry])
def get_allowlist() -> List[AllowlistEntry]:
    return list_allowlist_entries()


@batch_router.post("/allowlist", response_model=AllowlistEntry, status_code=201)
def create_allowlist_entry(request: AllowlistEntryCreate) -> AllowlistEntry:
    try:
        return add_allowlist_entry(request.kind, request.value)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="That entry is already allowlisted.") from error


@batch_router.delete("/allowlist/{entry_id}", status_code=204)
def remove_allowlist_entry(entry_id: str) -> None:
    if not delete_allowlist_entry(entry_id):
        raise HTTPException(status_code=404, detail="Allowlist entry not found.")
