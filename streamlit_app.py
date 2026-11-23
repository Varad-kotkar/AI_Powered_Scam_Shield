"""Standalone Streamlit interface for the existing Scam Shield detectors."""

import asyncio
import html
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
        "TELEGRAM_BOT_URL",
        "SCAM_SHIELD_WEB_URL",
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

from app.main import (
    TextRequest,
    URLRequest,
    chat_multipart,
    image_check,
    text_check,
    url_check,
)


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


def scan_chat(query: str, image_bytes: bytes = b"", filename: str = "image.png") -> Dict[str, Any]:
    """Use the existing chat route for chat text, links, or an optional screenshot."""
    upload = None
    if image_bytes:
        upload = UploadFile(file=BytesIO(image_bytes), filename=filename)
    return asyncio.run(chat_multipart(query=query, file=upload))


def _read_setting(name: str, default: str = "") -> str:
    """Read an optional public URL from environment or Streamlit secrets."""
    value = os.getenv(name)
    if value:
        return value
    try:
        return str(st.secrets.get(name, default))
    except StreamlitSecretNotFoundError:
        return default


def add_page_styles() -> None:
    """Match the React app's white, slate, and orange visual style."""
    st.markdown(
        """
        <style>
          [data-testid="stAppViewContainer"] { background: #fff; color: #0f172a; }
          [data-testid="stHeader"] { background: rgba(255,255,255,.92); }
          [data-testid="stToolbar"], footer { visibility: hidden; }
          .block-container { max-width: 48rem; padding: 1.2rem 1rem 2rem; }
          .ss-nav {
            display:flex; align-items:center; justify-content:space-between; gap:1rem;
            border-bottom:1px solid #e2e8f0; padding:.75rem 0 1rem; margin-bottom:2.5rem;
          }
          a.ss-brand, a.ss-brand:visited, a.ss-brand:hover {
            display:flex; align-items:center; gap:.65rem; color:#0f172a!important;
            text-decoration:none!important;
          }
          .ss-shield {
            display:grid; place-items:center; width:2.35rem; height:2.35rem;
            border-radius:.75rem; background:linear-gradient(135deg,#f97316,#dc2626);
            color:white; font-size:1.2rem;
          }
          .ss-brand-title { font-size:1.05rem; font-weight:850; line-height:1.1; }
          .ss-brand-sub { margin-top:.2rem; color:#ea580c; font-size:.62rem; font-weight:700; letter-spacing:.09em; }
          .ss-nav-links { display:flex; align-items:center; gap:.6rem; font-size:.78rem; }
          .ss-nav-links a { color:#475569; text-decoration:none; padding:.4rem .55rem; border-radius:999px; }
          .ss-nav-links a:hover { background:#f1f5f9; }
          .ss-nav-links .ss-github { border:1px solid #e2e8f0; color:#0f172a; }
          .ss-hero { text-align:center; margin:0 auto 1.5rem; }
          .ss-hero h1 { margin:0; color:#0f172a; font-size:clamp(2rem,6vw,3.55rem); line-height:1.08; letter-spacing:-.045em; font-weight:850; }
          .ss-hero h1 span { color:#f97316; }
          .ss-hero p { color:#64748b; font-size:.98rem; line-height:1.6; margin:.9rem auto 0; max-width:42rem; }
          div[data-testid="stRadio"] > label { display:none; }
          div[data-testid="stRadio"] div[role="radiogroup"] {
            display:flex; flex-wrap:nowrap; width:max-content; max-width:100%; overflow-x:auto;
            margin:0 auto 1rem; gap:.2rem; padding:.3rem; border-radius:999px;
            background:#f1f5f9; box-shadow:0 3px 8px #0f172a14;
          }
          div[data-testid="stRadio"] div[role="radiogroup"] label {
            white-space:nowrap; border-radius:999px; padding:.42rem .8rem; margin:0;
            color:#475569; font-size:.83rem;
          }
          div[data-testid="stRadio"] label[data-testid="stRadioOption"] > div > div:first-child {
            display:none!important;
          }
          div[data-testid="stRadio"] label[data-testid="stRadioOption"] > div {
            padding-left:0!important;
          }
          div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
            background:#fff; color:#ea580c; box-shadow:0 1px 4px #0f172a1c;
          }
          div[data-testid="stForm"] {
            border:1px solid #e2e8f0; border-radius:1.5rem; padding:1.2rem 1.35rem;
            background:#fff; box-shadow:0 8px 26px #0f172a0a;
          }
          div[data-testid="stTextArea"] textarea, div[data-testid="stTextInput"] input {
            border:1px solid #e2e8f0; border-radius:1rem; background:#f8fafc;
          }
          div[data-testid="stTextArea"] textarea:focus, div[data-testid="stTextInput"] input:focus {
            border-color:#fb923c; box-shadow:0 0 0 1px #fb923c;
          }
          div[data-testid="stFormSubmitButton"] button {
            border:0; border-radius:.65rem; background:#0f172a; color:white; font-weight:650;
          }
          div[data-testid="stFormSubmitButton"] button:hover { background:#1e293b; color:white; }
          .ss-section { margin:2.4rem 0 1rem; color:#0f172a; font-size:1.25rem; font-weight:750; }
          .ss-verdict {
            display:flex; align-items:center; gap:.75rem; border:1px solid #fed7aa;
            border-radius:.9rem; background:#fff7ed; padding:1rem; margin:.5rem 0 1rem;
          }
          .ss-verdict-risk { border-color:#fecaca; background:#fef2f2; }
          .ss-verdict-safe { border-color:#bbf7d0; background:#f0fdf4; }
          .ss-verdict-label {
            display:inline-block; border-radius:999px; background:#f97316; color:white;
            padding:.35rem .7rem; font-size:.78rem; font-weight:700;
          }
          .ss-verdict-risk .ss-verdict-label { background:#ef4444; }
          .ss-verdict-safe .ss-verdict-label { background:#10b981; }
          .ss-card-title { margin:.6rem 0 .4rem; color:#0f172a; font-weight:700; }
          .ss-explanation {
            border:1px solid #bfdbfe; border-radius:.8rem; background:#eff6ff;
            color:#1e3a8a; padding:1rem; line-height:1.65;
          }
          .ss-flag {
            border:1px solid #e2e8f0; border-radius:.7rem; background:#fff;
            padding:.8rem; margin:.5rem 0;
          }
          .ss-muted { color:#64748b; font-size:.82rem; }
          .ss-footer { border-top:1px solid #e2e8f0; margin-top:3rem; padding-top:1rem; color:#64748b; font-size:.8rem; }
          .ss-footer a { color:#475569; text-decoration:none; margin-right:1rem; }
          @media (max-width:560px) {
            .ss-nav { align-items:flex-start; flex-direction:column; }
            .ss-nav-links { width:100%; justify-content:space-between; }
            div[data-testid="stRadio"] div[role="radiogroup"] { margin-left:0; }
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def show_result(result: Mapping[str, Any]) -> None:
    """Display verdict, confidence, rule evidence, explanation, and raw response."""
    if result.get("reply") and not result.get("label"):
        st.markdown('<div class="ss-section">Chat Response</div>', unsafe_allow_html=True)
        st.info(str(result["reply"]))
        with st.expander("View Raw Response"):
            st.json(dict(result))
        return

    label = str(result.get("label", "unknown"))
    confidence = result.get("confidence", 0)
    try:
        confidence_percent = float(confidence) * 100
    except (TypeError, ValueError):
        confidence_percent = 0.0

    st.markdown('<div class="ss-section">Detection Result</div>', unsafe_allow_html=True)
    normalized_label = label.casefold()
    verdict_style = (
        "ss-verdict-risk"
        if normalized_label in {"phishing", "malware", "scam", "fraud"}
        else "ss-verdict-safe"
    )
    with st.container(border=True):
        st.markdown(
            f'<div class="ss-verdict {verdict_style}">'
            f'<span class="ss-verdict-label">{html.escape(label.upper())}</span>'
            f'<span class="ss-muted">{confidence_percent:.1f}% confidence</span>'
            "</div>",
            unsafe_allow_html=True,
        )

        probabilities = result.get("probs")
        if isinstance(probabilities, Mapping):
            st.markdown('<div class="ss-card-title">Confidence Analysis</div>', unsafe_allow_html=True)
            for class_name, value in probabilities.items():
                try:
                    score = min(1.0, max(0.0, float(value)))
                except (TypeError, ValueError):
                    continue
                st.write(f"{str(class_name).title()} · {score * 100:.1f}%")
                st.progress(score)

        flags = result.get("red_flags")
        st.markdown('<div class="ss-card-title">Red Flags</div>', unsafe_allow_html=True)
        if isinstance(flags, list) and flags:
            for flag in flags:
                if not isinstance(flag, Mapping):
                    continue
                title = html.escape(
                    f"{flag.get('label', flag.get('code', 'Signal'))} · "
                    f"{flag.get('severity', 'unknown')}"
                )
                code = html.escape(str(flag.get("code", "")))
                evidence = html.escape(str(flag.get("evidence", "")))
                st.markdown(
                    f'<div class="ss-flag"><b>{title}</b><br>'
                    f'<span class="ss-muted">{code}</span><br>{evidence}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No structured red flags were identified.")

        explanation = result.get("explanation")
        if explanation:
            st.markdown('<div class="ss-card-title">AI Analysis</div>', unsafe_allow_html=True)
            st.markdown(
                f'<div class="ss-explanation">{html.escape(str(explanation))}</div>',
                unsafe_allow_html=True,
            )

        if result.get("ocr"):
            with st.expander("Extracted Text (OCR)"):
                st.text(str(result["ocr"]))

        with st.expander("View Raw Response"):
            st.json(dict(result))


def main() -> None:
    """Render the Scam Shield workbench and preserve scans in this browser session."""
    st.set_page_config(
        page_title="Scam Shield",
        page_icon="🛡️",
        layout="centered",
    )
    add_page_styles()

    telegram_url = _read_setting("TELEGRAM_BOT_URL")
    web_url = _read_setting("SCAM_SHIELD_WEB_URL")
    telegram_link = (
        f'<a href="{html.escape(telegram_url, quote=True)}" target="_blank" rel="noopener noreferrer">Telegram Bot</a>'
        if telegram_url
        else '<a href="#telegram">Telegram Bot</a>'
    )
    batch_link = (
        html.escape(f"{web_url.rstrip('/')}/batch-scan", quote=True)
        if web_url
        else "https://github.com/Varad-kotkar/AI_Powered_Scam_Shield"
    )
    st.markdown(
        f"""
        <header class="ss-nav">
          <a class="ss-brand" href="#">
            <span class="ss-shield">⬡</span>
            <span><span class="ss-brand-title">Scam Shield</span><br>
              <span class="ss-brand-sub">AI FRAUD DETECTION</span></span>
          </a>
          <nav class="ss-nav-links">
            <a href="{batch_link}">Batch Scan</a>
            {telegram_link}
            <a href="https://github.com/Varad-kotkar/AI_Powered_Scam_Shield#readme">Docs</a>
            <a class="ss-github" href="https://github.com/Varad-kotkar/AI_Powered_Scam_Shield"
               target="_blank" rel="noopener noreferrer">GitHub</a>
          </nav>
        </header>
        <section class="ss-hero">
          <h1>Turn messages into <span>LLM-ready verdicts</span>.</h1>
          <p>Paste suspicious text, links, or emails — or upload screenshots and chats —
             and AI Scam Shield delivers real-time fraud verdicts.</p>
        </section>
        """,
        unsafe_allow_html=True,
    )

    modes = ("Text", "SMS", "Emails", "URLs", "Script", "Images", "Chat")
    scan_type = st.radio(
        "Scan mode",
        modes,
        horizontal=True,
        label_visibility="collapsed",
        key="scan_mode",
    )

    with st.form("scan_form"):
        text_value = ""
        url_value = ""
        uploaded_image = None

        if scan_type in {"Text", "SMS", "Emails", "Script", "Chat"}:
            placeholder = {
                "Text": "Enter any suspicious message or text...",
                "SMS": "Enter any SMS message to check...",
                "Emails": "Enter any email content to analyze...",
                "Script": "Paste any script or code to analyze...",
                "Chat": "Ask about phishing, security, or scan suspicious content...",
            }[scan_type]
            text_value = st.text_area(
                "Message or content",
                placeholder=placeholder,
                height=150 if scan_type == "Chat" else 115,
                label_visibility="collapsed",
            )
        if scan_type == "URLs":
            url_value = st.text_input(
                "URL",
                placeholder="Enter any suspicious URL to check for phishing...",
                label_visibility="collapsed",
            )
        if scan_type == "Images" or (scan_type == "Chat"):
            uploaded_image = st.file_uploader(
                "Attach a screenshot" if scan_type == "Chat" else "Drop a screenshot here or browse",
                type=["png", "jpg", "jpeg", "webp"],
            )

        submitted = st.form_submit_button("Send", type="primary", use_container_width=True)

    if submitted:
        try:
            if scan_type in {"Text", "SMS", "Emails", "Script"}:
                if not text_value.strip():
                    st.warning("Enter a message before scanning.")
                    return
                result = scan_text(text_value)
            elif scan_type == "URLs":
                if not url_value.strip():
                    st.warning("Enter a URL before scanning.")
                    return
                result = scan_url(url_value.strip())
            elif scan_type == "Images":
                if uploaded_image is None:
                    st.warning("Upload a screenshot before scanning.")
                    return
                result = scan_image(uploaded_image.getvalue(), uploaded_image.name)
            else:
                image_bytes = uploaded_image.getvalue() if uploaded_image else b""
                if not text_value.strip() and not image_bytes:
                    st.warning("Enter a question or attach content to scan.")
                    return
                result = scan_chat(
                    text_value,
                    image_bytes,
                    uploaded_image.name if uploaded_image else "image.png",
                )

            st.session_state["scam_shield_result"] = result
        except Exception as error:
            st.error(f"Scan failed: {error}")
            return

    result = st.session_state.get("scam_shield_result")
    if isinstance(result, Mapping):
        st.divider()
        show_result(result)

    st.markdown(
        """
        <div class="ss-section" id="faq">Frequently asked questions</div>
        <p><b>What can I scan?</b><br>Text, SMS, emails, URLs, scripts, screenshots, and chat inputs.</p>
        <p><b>What should I do with a suspicious result?</b><br>
           Do not click links, send money, or share passwords or one-time codes.
           Verify requests through a known, official contact method.</p>
        <div class="ss-footer">
          © AI-Powered Scam Shield · A benign result is not a guarantee of safety.
          <p><a href="#faq">Privacy</a><a href="#faq">Terms</a></p>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
