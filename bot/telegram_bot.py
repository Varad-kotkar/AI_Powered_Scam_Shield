"""Telegram bot that calls Scam Shield's existing detection functions."""

import asyncio
import html
import logging
import os
from io import BytesIO
from typing import Any, Dict, Mapping, Optional

from fastapi import UploadFile
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from app.intent import extract_single_url
from app.main import TextRequest, URLRequest, image_check, text_check, url_check


LOGGER = logging.getLogger(__name__)
MAX_IMAGE_BYTES = 20 * 1024 * 1024
MAX_TELEGRAM_MESSAGE_LENGTH = 4000


def _standalone_url(text: str) -> Optional[str]:
    """Return a URL only when the whole message is a URL, not a longer message."""
    extracted = extract_single_url(text)
    if not extracted:
        return None

    candidate = text.strip().strip("<>").rstrip(".,;:!?)]}")
    candidate_without_scheme = candidate.removeprefix("https://").removeprefix("http://")
    extracted_without_scheme = extracted.removeprefix("https://").removeprefix("http://")
    if candidate.casefold() in {
        extracted.casefold(),
        extracted_without_scheme.casefold(),
    } or candidate_without_scheme.casefold() == extracted_without_scheme.casefold():
        return extracted
    return None


def _detect_text_or_url(text: str) -> Dict[str, Any]:
    """Use the existing URL detector for a bare link and the text detector otherwise."""
    url = _standalone_url(text)
    if url:
        return url_check(URLRequest(url=url))
    return text_check(TextRequest(text=text))


def _run_image_detection(image_bytes: bytes) -> Dict[str, Any]:
    """Call the existing async image route using an in-memory upload."""
    upload = UploadFile(
        file=BytesIO(image_bytes),
        filename="telegram-image.jpg",
    )
    return asyncio.run(image_check(upload))


def _limit_text(value: Any, limit: int) -> str:
    """Convert untrusted response values to short, predictable display text."""
    text = str(value or "").strip()
    if len(text) > limit:
        return text[:limit - 3].rstrip() + "..."
    return text


def _confidence_value(result: Mapping[str, Any], label: str) -> float:
    """Read the response confidence, falling back to the verdict's probability."""
    confidence = result.get("confidence")
    if confidence is None:
        probabilities = result.get("probs")
        if isinstance(probabilities, Mapping):
            confidence = probabilities.get(label, 0)
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return 0.0
    if not 0.0 <= value <= 1.0:
        return 0.0
    return value


def _safety_advice(label: str, confidence: float, flags: list) -> str:
    """Give practical next steps and include India's 1930 helpline for high risk."""
    has_high_severity_flag = any(
        isinstance(flag, Mapping)
        and str(flag.get("severity", "")).casefold() in {"high", "critical"}
        for flag in flags
    )
    is_high_risk_verdict = label.casefold() in {"phishing", "malware", "scam", "fraud"}
    if has_high_severity_flag or (is_high_risk_verdict and confidence >= 0.6):
        return (
            "Do not click links, reply, share OTPs or passwords, or pay. "
            "Verify through the organization's official app or contact details. "
            "If you lost money in India, call cyber fraud helpline <b>1930</b> "
            "immediately and report at cybercrime.gov.in."
        )
    return (
        "Do not click or pay until you verify the sender and request through "
        "the organization's official app or contact details."
    )


def format_result(result: Mapping[str, Any]) -> str:
    """Format a detector response as safe, readable Telegram HTML."""
    label = _limit_text(result.get("label", "unknown"), 80)
    display_label = label.upper().replace("_", " ")
    confidence = _confidence_value(result, label)
    explanation = _limit_text(result.get("explanation"), 1000)
    explanation = explanation.replace("**", "").replace("__", "").replace("`", "")
    flags = result.get("red_flags")
    if not isinstance(flags, list):
        flags = []

    lines = [
        "<b>Scam Shield scan</b>",
        f"<b>Verdict:</b> {html.escape(display_label)}",
        f"<b>Confidence:</b> {confidence * 100:.1f}%",
        "",
        "<b>Detected red flags:</b>",
    ]
    valid_flags = [flag for flag in flags if isinstance(flag, Mapping)]
    visible_flags = valid_flags[:8]
    if visible_flags:
        for flag in visible_flags:
            flag_label = _limit_text(flag.get("label") or flag.get("code"), 100)
            code = _limit_text(flag.get("code"), 60)
            severity = _limit_text(flag.get("severity", "unknown"), 20).upper()
            evidence = _limit_text(flag.get("evidence"), 160)
            lines.append(
                f"• <b>{html.escape(flag_label)}</b> "
                f"({html.escape(code)}, {html.escape(severity)}): "
                f"{html.escape(evidence)}"
            )
        if len(valid_flags) > len(visible_flags):
            lines.append(f"• And {len(valid_flags) - len(visible_flags)} more.")
    else:
        lines.append("None identified by the red-flag rules.")

    lines.extend([
        "",
        "<b>Explanation:</b>",
        html.escape(explanation or "No explanation was returned."),
        "",
        "<b>Safety advice:</b>",
        _safety_advice(label, confidence, flags),
    ])

    # Keep within Telegram's message limit while retaining the advice and key fields.
    message = "\n".join(lines)
    if len(message) > MAX_TELEGRAM_MESSAGE_LENGTH:
        compact_lines = [
            "<b>Scam Shield scan</b>",
            f"<b>Verdict:</b> {html.escape(_limit_text(display_label, 40))}",
            f"<b>Confidence:</b> {confidence * 100:.1f}%",
            "",
            "<b>Detected red flags:</b>",
        ]
        for flag in valid_flags[:2]:
            compact_lines.append(
                f"• <b>{html.escape(_limit_text(flag.get('label') or flag.get('code'), 40))}</b> "
                f"({html.escape(_limit_text(flag.get('code'), 20))}, "
                f"{html.escape(_limit_text(flag.get('severity', 'unknown'), 10).upper())}): "
                f"{html.escape(_limit_text(flag.get('evidence'), 40))}"
            )
        if not valid_flags:
            compact_lines.append("None identified by the red-flag rules.")
        compact_lines.extend([
            "",
            "<b>Explanation:</b>",
            html.escape(_limit_text(explanation, 200) or "No explanation was returned."),
            "",
            "<b>Safety advice:</b>",
            _safety_advice(label, confidence, flags),
        ])
        return "\n".join(compact_lines)
    return message


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Explain how to submit content for a scan."""
    del context
    if update.effective_message:
        await update.effective_message.reply_text(
            "Send or forward a suspicious message or URL, or share a screenshot. "
            "I will return a Scam Shield verdict, confidence, red flags, and safety advice."
        )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Analyze each incoming or forwarded text message without blocking polling."""
    del context
    message = update.effective_message
    if not message or not message.text:
        return
    try:
        result = await asyncio.to_thread(_detect_text_or_url, message.text)
    except Exception:
        LOGGER.exception("Scam Shield text detection failed")
        await message.reply_text("I could not analyze that message. Please try again later.")
        return
    await message.reply_text(
        format_result(result),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Download and analyze an incoming or forwarded photo or image document."""
    message = update.effective_message
    if not message:
        return

    if message.photo:
        image = message.photo[-1]
    elif message.document and message.document.mime_type and message.document.mime_type.startswith("image/"):
        image = message.document
    else:
        await message.reply_text("Please send a photo or an image file.")
        return

    if image.file_size and image.file_size > MAX_IMAGE_BYTES:
        await message.reply_text("That image is too large. Please send an image smaller than 20 MB.")
        return

    try:
        telegram_file = await context.bot.get_file(image.file_id)
        image_bytes = bytes(await telegram_file.download_as_bytearray())
        if len(image_bytes) > MAX_IMAGE_BYTES:
            await message.reply_text("That image is too large. Please send an image smaller than 20 MB.")
            return
        result = await asyncio.to_thread(_run_image_detection, image_bytes)
    except Exception:
        LOGGER.exception("Scam Shield image detection failed")
        await message.reply_text("I could not analyze that image. Please try again later.")
        return

    await message.reply_text(
        format_result(result),
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


def main() -> None:
    """Start long polling after checking that the Telegram token is configured."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN is not set. Add your bot token to the environment before starting."
        )

    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(
        MessageHandler(filters.PHOTO | filters.Document.IMAGE, handle_image)
    )
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text)
    )
    application.run_polling()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    main()
