"""Standalone Streamlit interface for the existing Scam Shield detectors."""

import asyncio
import os
from io import BytesIO
from typing import Any, Dict, Mapping

import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError


def load_streamlit_secrets() -> None:
    """Make configured server-side Streamlit secrets available to existing modules."""
    setting_names = (
        "NVIDIA_API_KEY",
        "NVIDIA_ENDPOINT",
        "MM_NVIDIA_MODEL",
        "MM_NVIDIA_TIMEOUT",
        "MM_LLM_PROVIDER",
        "HUGGINGFACE_API_KEY",
        "MM_HF_MODEL",
        "GEMINI_API_KEY",
        "GEMINI_ENDPOINT",
        "MM_TEXT_MODEL_DIR",
        "MM_URL_MODEL_DIR",
        "MM_IMAGE_MODEL_PATH",
        "MM_USE_OCR",
        "MM_TESSERACT_CMD",
        "MM_N8N_OCR_ENDPOINT",
    )
    try:
        for name in setting_names:
            value = st.secrets.get(name)
            if value is not None:
                os.environ[name] = str(value)
    except StreamlitSecretNotFoundError:
        # Local runs can use the repository's .env file instead of Streamlit secrets.
        return


# Set secrets before importing application modules that read environment settings.
load_streamlit_secrets()

from fastapi import UploadFile

from app.main import TextRequest, URLRequest, image_check, text_check, url_check


def scan_text(text: str) -> Dict[str, Any]:
    """Use the same text detection function and response shape as the web API."""
    return text_check(TextRequest(text=text))


def scan_url(url: str) -> Dict[str, Any]:
    """Use the same URL detection function and response shape as the web API."""
    return url_check(URLRequest(url=url))


def scan_image(image_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Pass the uploaded screenshot to the existing asynchronous image route."""
    upload = UploadFile(file=BytesIO(image_bytes), filename=filename)
    return asyncio.run(image_check(upload))


def show_result(result: Mapping[str, Any]) -> None:
    """Display verdict, confidence, rule evidence, explanation, and raw response."""
    label = str(result.get("label", "unknown"))
    confidence = result.get("confidence", 0)
    try:
        confidence_percent = float(confidence) * 100
    except (TypeError, ValueError):
        confidence_percent = 0.0

    st.subheader("Detection result")
    verdict_column, confidence_column = st.columns(2)
    with verdict_column:
        st.metric("Verdict", label.upper())
    with confidence_column:
        st.metric("Confidence", f"{confidence_percent:.1f}%")

    probabilities = result.get("probs")
    if isinstance(probabilities, Mapping):
        st.caption("Class probabilities")
        st.json(probabilities)

    flags = result.get("red_flags")
    if isinstance(flags, list) and flags:
        st.markdown("#### Red flags")
        for flag in flags:
            if not isinstance(flag, Mapping):
                continue
            title = f"{flag.get('label', flag.get('code', 'Signal'))} · {flag.get('severity', 'unknown')}"
            st.warning(title)
            st.caption(str(flag.get("evidence", "")))
    else:
        st.info("No structured red flags were identified.")

    explanation = result.get("explanation")
    if explanation:
        st.markdown("#### Explanation")
        st.markdown(str(explanation))

    if result.get("ocr"):
        with st.expander("Text read from image (OCR)"):
            st.text(str(result["ocr"]))

    with st.expander("Raw JSON response"):
        st.json(dict(result))


def main() -> None:
    """Render the Streamlit scan form and keep scan results in the current session."""
    st.set_page_config(
        page_title="Scam Shield",
        page_icon="🛡️",
        layout="centered",
    )
    st.title("AI-Powered Scam Shield")
    st.write("Check a suspicious message, link, or screenshot.")

    scan_type = st.radio(
        "What would you like to check?",
        ("Text message", "URL", "Screenshot"),
        horizontal=True,
    )

    with st.form("scan_form"):
        text_value = ""
        url_value = ""
        uploaded_image = None

        if scan_type == "Text message":
            text_value = st.text_area(
                "Paste the message",
                placeholder="Paste suspicious SMS, email, chat, or script text here.",
                height=180,
            )
        elif scan_type == "URL":
            url_value = st.text_input(
                "Paste the URL",
                placeholder="https://example.com",
            )
        else:
            uploaded_image = st.file_uploader(
                "Upload a screenshot",
                type=["png", "jpg", "jpeg", "webp"],
            )

        submitted = st.form_submit_button("Scan", type="primary")

    if submitted:
        try:
            if scan_type == "Text message":
                if not text_value.strip():
                    st.warning("Enter a message before scanning.")
                    return
                result = scan_text(text_value)
            elif scan_type == "URL":
                if not url_value.strip():
                    st.warning("Enter a URL before scanning.")
                    return
                result = scan_url(url_value.strip())
            else:
                if uploaded_image is None:
                    st.warning("Upload a screenshot before scanning.")
                    return
                result = scan_image(uploaded_image.getvalue(), uploaded_image.name)

            st.session_state["scam_shield_result"] = result
        except Exception as error:
            st.error(f"Scan failed: {error}")
            return

    result = st.session_state.get("scam_shield_result")
    if isinstance(result, Mapping):
        st.divider()
        show_result(result)

    st.caption(
        "A benign result is not a guarantee of safety. Verify unexpected requests "
        "through an official contact method."
    )


if __name__ == "__main__":
    main()
