#!/usr/bin/env python3
"""Clean a local JSON or CSV dataset without using external services."""

import argparse
import csv
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


URL_FIELDS = {"url", "link", "website", "target_url"}
LABEL_FIELDS = {"label", "class", "class_name", "target"}
ID_FIELDS = {"id", "index", "row", "row_id"}
JSON_LIST_KEYS = ("samples", "data", "records", "examples")

LABEL_ALIASES = {
    "fraud": "scam",
    "fraudulent": "scam",
    "malicious": "scam",
    "phish": "scam",
    "phishing": "scam",
    "scam": "scam",
    "spam": "scam",
    "benign": "legitimate",
    "ham": "legitimate",
    "legitimate": "legitimate",
    "non phishing": "legitimate",
    "not scam": "legitimate",
    "safe": "legitimate",
    "malware": "malware",
}


def normalize_text(value: str) -> str:
    """Apply compatibility Unicode normalization and collapse repeated whitespace."""
    normalized = unicodedata.normalize("NFKC", value)
    return " ".join(normalized.split())


def normalize_label(value: str) -> str:
    """Map common label spellings to the project's scam/legitimate vocabulary."""
    label = normalize_text(value).casefold().replace("_", " ").replace("-", " ")
    label = " ".join(label.split())
    return LABEL_ALIASES.get(label, label)


def normalize_url(value: str) -> str:
    """Lowercase URL scheme and host, and add HTTPS to bare website addresses."""
    value = normalize_text(value)
    if not value:
        return ""

    # Keep explicit non-web protocols as-is instead of turning them into HTTPS URLs.
    if re.match(r"^(?!https?://)[a-z][a-z0-9+.-]*://", value, re.IGNORECASE):
        return value
    candidate = value if re.match(r"^https?://", value, re.IGNORECASE) else f"https://{value}"
    parts = urlsplit(candidate)

    try:
        hostname = parts.hostname
        if not hostname:
            return value
        hostname = hostname.encode("idna").decode("ascii").lower()
        port = parts.port
    except (UnicodeError, ValueError):
        return value

    # Preserve optional URL credentials and port while normalizing only the host.
    user_info, has_user_info, _ = parts.netloc.rpartition("@")
    netloc = f"{user_info}@" if has_user_info else ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc += hostname
    if port is not None:
        netloc += f":{port}"

    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))


def normalize_value(value: Any, field_name: Optional[str] = None) -> Any:
    """Normalize strings recursively while preserving the original JSON structure."""
    if isinstance(value, str):
        normalized = normalize_text(value)
        field = (field_name or "").casefold()
        if field in URL_FIELDS:
            return normalize_url(normalized)
        if field in LABEL_FIELDS:
            return normalize_label(normalized)
        return normalized
    if isinstance(value, dict):
        return {
            key: normalize_value(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize_value(item, field_name) for item in value]
    return value


def _is_blank(value: Any) -> bool:
    """Return whether a value contains no usable text or nested values."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, dict):
        return all(_is_blank(item) for item in value.values())
    if isinstance(value, list):
        return all(_is_blank(item) for item in value)
    return False


def _is_empty_record(record: Any) -> bool:
    """Drop records without content, ignoring IDs and labels when checking emptiness."""
    if isinstance(record, dict):
        content = [
            value
            for key, value in record.items()
            if str(key).casefold() not in ID_FIELDS | LABEL_FIELDS
        ]
        return not content or all(_is_blank(value) for value in content)
    return _is_blank(record)


def _duplicate_key(record: Any) -> str:
    """Build a stable key that ignores row IDs but keeps labels and content."""
    if isinstance(record, dict):
        record = {
            key: value
            for key, value in record.items()
            if str(key).casefold() not in ID_FIELDS
        }
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def clean_records(records: List[Any]) -> Tuple[List[Any], int, int]:
    """Normalize rows, then count and remove empty and duplicate entries."""
    cleaned = []
    seen = set()
    empty_count = 0
    duplicate_count = 0

    for record in records:
        normalized = normalize_value(record)
        if _is_empty_record(normalized):
            empty_count += 1
            continue

        key = _duplicate_key(normalized)
        if key in seen:
            duplicate_count += 1
            continue
        seen.add(key)
        cleaned.append(normalized)

    return cleaned, empty_count, duplicate_count


def load_dataset(
    path: Path,
) -> Tuple[List[Any], Optional[str], Optional[Dict[str, Any]], List[str]]:
    """Read CSV rows or JSON records, remembering any JSON wrapper and CSV headers."""
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            return list(reader), None, None, reader.fieldnames or []
    if suffix != ".json":
        raise ValueError("Input file must have a .json or .csv extension.")

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload, None, None, []
    if not isinstance(payload, dict):
        raise ValueError("JSON input must be a list of records or an object containing records.")

    for key in JSON_LIST_KEYS:
        if isinstance(payload.get(key), list):
            return payload[key], key, payload, []
    return [payload], "__single_record__", None, []


def save_dataset(
    path: Path,
    records: List[Any],
    container_key: Optional[str],
    wrapper: Optional[Dict[str, Any]],
    fieldnames: List[str],
) -> None:
    """Write cleaned records in the same JSON or CSV format as the input."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.casefold() == ".csv":
        if any(not isinstance(record, dict) for record in records):
            raise ValueError("CSV output requires each record to be a column/value object.")

        # Keep the original column order and append any extra JSON-like fields found.
        columns = list(fieldnames)
        for record in records:
            for key in record:
                if key not in columns:
                    columns.append(key)
        with path.open("w", encoding="utf-8", newline="") as destination:
            writer = csv.DictWriter(destination, fieldnames=columns)
            writer.writeheader()
            writer.writerows(records)
        return

    if path.suffix.casefold() != ".json":
        raise ValueError("Output file must have a .json or .csv extension.")
    if container_key == "__single_record__":
        payload = records[0] if records else {}
    elif container_key and wrapper is not None:
        payload = dict(wrapper)
        payload[container_key] = records
    else:
        payload = records
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def clean_file(input_path: Path, output_path: Path) -> Tuple[int, int, int, int]:
    """Run the read, clean, and write steps; return before/removed/after counts."""
    if input_path.suffix.casefold() != output_path.suffix.casefold():
        raise ValueError("Output file extension must match the input file format.")
    records, container_key, wrapper, fieldnames = load_dataset(input_path)
    cleaned, empty_count, duplicate_count = clean_records(records)
    save_dataset(output_path, cleaned, container_key, wrapper, fieldnames)
    return len(records), empty_count, duplicate_count, len(cleaned)


def main() -> None:
    """Parse file paths, clean one local dataset, and print a short summary."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Raw .json or .csv dataset")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Cleaned output path (defaults to <name>_cleaned with the input format)",
    )
    args = parser.parse_args()
    output_path = args.output or args.input.with_name(
        f"{args.input.stem}_cleaned{args.input.suffix}"
    )

    try:
        before, empty_count, duplicate_count, after = clean_file(args.input, output_path)
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as error:
        parser.error(str(error))

    print(f"Records before cleaning: {before}")
    print(f"Empty records removed: {empty_count}")
    print(f"Duplicate records removed: {duplicate_count}")
    print(f"Records after cleaning: {after}")
    print(f"Cleaned dataset saved to: {output_path}")


if __name__ == "__main__":
    main()
