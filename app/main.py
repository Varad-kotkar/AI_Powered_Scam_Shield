import os
from typing import Dict, Optional
from fastapi import FastAPI, UploadFile, File, Form, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.models_loader import get_registry
from app.predictors import (
    predict_text_probs,
    predict_url_probs,
    predict_image_probs,
    get_ocr_text_from_bytes,
    url_multiclass_to_binary,
    fuse_all
)
from app.intent import detect_intent, extract_single_url
from app.llm_helpers import make_llm_explanation, friendly_chat_reply
from app.red_flags import detect_red_flags
from app.batch_scan import batch_router

app = FastAPI(
    title="AI-Powered Scam Shield: An Intelligent Cyber Fraud Detection System",
    description="FastAPI Backend for AI-Powered Scam Shield - Multimodal cyber fraud & scam detection for text, URLs, and screenshots",
    version="1.0.0"
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# An endpoint is an HTTP path the frontend or another client can call.
# These request models keep the existing JSON payload shapes for scans.
class TextRequest(BaseModel):
    text: str


class URLRequest(BaseModel):
    url: str


router = APIRouter()


def _detection_fields(
    content: str,
    label: str,
    probs: Dict[str, float],
    target_url: Optional[str] = None,
) -> Dict[str, object]:
    """Build metadata shared by detection responses without changing old fields."""
    # probs maps each label to its score; confidence is the score for the chosen label.
    confidence = probs.get(label, max(probs.values(), default=0.0))
    return {
        "confidence": round(float(confidence), 4),
        # red_flags are structured evidence from explicit rules, separate from the model score.
        "red_flags": detect_red_flags(content, target_url=target_url),
    }


@router.get("/")
def root():
    """Expose service status and the interactive API documentation path."""
    return {
        "status": "online",
        "service": "AI-Powered Scam Shield: An Intelligent Cyber Fraud Detection System",
        "docs_url": "/docs"
    }

@router.get("/health")
def health():
    """Report which local model files loaded without starting predictions."""
    reg = get_registry()
    return {
        "status": "healthy",
        "models": {
            "text_model": bool(reg.text_model),
            "url_model": bool(reg.url_model),
            "image_model": bool(reg.image_model),
        }
    }

@router.post("/text_check")
def text_check(req: TextRequest):
    # This endpoint keeps the existing response schema used by the web UI and other clients.
    probs = predict_text_probs(req.text)
    # The larger probability wins; a tie stays classified as phishing for caution.
    label = "phishing" if probs.get("phishing", 0.0) >= probs.get("benign", 0.0) else "benign"
    fields = _detection_fields(req.text, label, probs)
    summary = {"text": probs, "label": label, "probs": probs, **fields}
    explanation = make_llm_explanation(summary)
    return {
        "label": label,
        "probs": probs,
        **fields,
        "explanation": explanation,
        "intent": "text_message"
    }

@router.post("/url_check")
def url_check(req: URLRequest):
    """Analyze one URL and keep the established label/probabilities response fields."""
    probs = predict_url_probs(req.url)
    # URL scans can return benign, phishing, or malware; select the highest score.
    label = max(probs, key=probs.get) if probs else "benign"
    fields = _detection_fields(req.url, label, probs, target_url=req.url)
    summary = {"url": probs, "label": label, "probs": probs, **fields}
    explanation = make_llm_explanation(summary)
    return {
        "label": label,
        "probs": probs,
        **fields,
        "explanation": explanation,
        "url": req.url,
        "intent": "url_check"
    }

@router.post("/image_check")
async def image_check(image_file: UploadFile = File(...)):
    # OCR (optical character recognition) reads visible words from the screenshot.
    # Those words can help classify the image and are also checked for red-flag evidence.
    contents = await image_file.read()
    ocr_text = get_ocr_text_from_bytes(contents)
    probs = predict_image_probs(contents, ocr_text)
    label = "phishing" if probs.get("phishing", 0.0) >= probs.get("benign", 0.0) else "benign"
    fields = _detection_fields(ocr_text or "", label, probs)
    summary = {"img": probs, "label": label, "probs": probs, **fields}
    if not ocr_text:
        summary["image_ocr_available"] = False
    explanation = make_llm_explanation(summary, ocr_text=ocr_text)
    return {
        "label": label,
        "probs": probs,
        **fields,
        "explanation": explanation,
        "ocr": ocr_text,
        "intent": "image_check"
    }

async def _combined_detection_response(
    query: str,
    file: Optional[UploadFile],
) -> Dict[str, object]:
    """Analyze the remaining mixed-input cases and return the combined response."""
    extracted_url = extract_single_url(query)
    file_bytes = await file.read() if file is not None else None
    ocr_text = get_ocr_text_from_bytes(file_bytes) if file_bytes else None

    text_probs = predict_text_probs(query) if query.strip() else None
    url_probs = predict_url_probs(extracted_url) if extracted_url else None
    img_probs = predict_image_probs(file_bytes, ocr_text) if file_bytes else None

    text_p = text_probs.get("phishing") if text_probs else None
    url_p_bin = url_multiclass_to_binary(url_probs) if url_probs else None
    img_p = img_probs.get("phishing") if img_probs else None

    # A text-only request gets the same response shape as the dedicated text endpoint.
    if text_probs and not url_probs and not img_probs:
        label = "phishing" if text_p >= 0.5 else "benign"
        fields = _detection_fields(query, label, text_probs)
        summary = {"text": text_probs, "label": label, "probs": text_probs, **fields}
        explanation = make_llm_explanation(summary)
        return {
            "label": label,
            "probs": text_probs,
            **fields,
            "explanation": explanation,
            "intent": "text_message"
        }

    # URL malware and phishing scores are combined before multimodal fusion.
    fusion = fuse_all(text_p, url_p_bin, img_p, None)
    fields = _detection_fields(
        "\n".join(part for part in (query, ocr_text or "") if part),
        fusion["label"],
        fusion["probs"],
        target_url=extracted_url,
    )
    summary = {
        "fused_prob": fusion["fused_prob"],
        "label": fusion["label"],
        "probs": fusion["probs"],
        "raw_text": text_probs,
        "raw_url": url_probs,
        "raw_img": img_probs,
        **fields,
    }
    if file_bytes and not ocr_text:
        summary["image_ocr_available"] = False
    explanation = make_llm_explanation(summary, ocr_text=ocr_text)

    return {
        "label": fusion["label"],
        "probs": fusion["probs"],
        **fields,
        "explanation": explanation,
        "ocr": ocr_text,
        "url": extracted_url,
        "intent": "combined"
    }


@router.post("/chat_multipart")
async def chat_multipart(
    query: str = Form(""),
    file: Optional[UploadFile] = File(None)
):
    """Route chat input to conversation, URL, image, or combined analysis."""
    has_file = file is not None
    intent = detect_intent(query, has_file=has_file)
    extracted_url = extract_single_url(query)

    # Ordinary questions use a conversational answer instead of a scam verdict.
    if intent == "chat" and not has_file:
        reply = friendly_chat_reply(query)
        return {
            "reply": reply,
            "intent": "chat"
        }

    # URL-only requests keep the URL response fields and include the full query as evidence.
    if intent == "url_check" and extracted_url and not has_file:
        probs = predict_url_probs(extracted_url)
        label = max(probs, key=probs.get) if probs else "benign"
        fields = _detection_fields(query, label, probs, target_url=extracted_url)
        summary = {"url": probs, "label": label, "probs": probs, **fields}
        explanation = make_llm_explanation(summary)
        return {
            "label": label,
            "probs": probs,
            **fields,
            "explanation": explanation,
            "url": extracted_url,
            "intent": "url_check"
        }

    # Image-only requests use image prediction; mixed input is handled by the helper.
    if intent == "image_check" and has_file:
        contents = await file.read()
        ocr_text = get_ocr_text_from_bytes(contents)
        probs = predict_image_probs(contents, ocr_text)
        label = "phishing" if probs.get("phishing", 0.0) >= probs.get("benign", 0.0) else "benign"
        fields = _detection_fields(ocr_text or query, label, probs)
        summary = {"img": probs, "label": label, "probs": probs, **fields}
        if not ocr_text:
            summary["image_ocr_available"] = False
        explanation = make_llm_explanation(summary, ocr_text=ocr_text)
        return {
            "label": label,
            "probs": probs,
            **fields,
            "explanation": explanation,
            "ocr": ocr_text,
            "intent": "image_check"
        }

    return await _combined_detection_response(query, file)


# Register the same endpoints with and without /api so existing clients keep working.
app.include_router(router)
app.include_router(router, prefix="/api")
app.include_router(batch_router)
app.include_router(batch_router, prefix="/api")
