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

# Pydantic Schemas
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
    confidence = probs.get(label, max(probs.values(), default=0.0))
    return {
        "confidence": round(float(confidence), 4),
        "red_flags": detect_red_flags(content, target_url=target_url),
    }

@router.get("/")
def root():
    return {
        "status": "online",
        "service": "AI-Powered Scam Shield: An Intelligent Cyber Fraud Detection System",
        "docs_url": "/docs"
    }

@router.get("/health")
def health():
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
    probs = predict_text_probs(req.text)
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
    probs = predict_url_probs(req.url)
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

@router.post("/chat_multipart")
async def chat_multipart(
    query: str = Form(""),
    file: Optional[UploadFile] = File(None)
):
    has_file = file is not None
    intent = detect_intent(query, has_file=has_file)
    extracted_url = extract_single_url(query)

    # 1. Plain chat mode
    if intent == "chat" and not has_file:
        reply = friendly_chat_reply(query)
        return {
            "reply": reply,
            "intent": "chat"
        }

    # 2. URL check mode
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

    # 3. Image check mode
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

    # 4. Multimodal / Combined mode
    file_bytes = await file.read() if has_file else None
    ocr_text = get_ocr_text_from_bytes(file_bytes) if file_bytes else None

    text_probs = predict_text_probs(query) if query.strip() else None
    url_probs = predict_url_probs(extracted_url) if extracted_url else None
    img_probs = predict_image_probs(file_bytes, ocr_text) if file_bytes else None

    text_p = text_probs.get("phishing") if text_probs else None
    url_p_bin = url_multiclass_to_binary(url_probs) if url_probs else None
    img_p = img_probs.get("phishing") if img_probs else None

    # If only text was provided
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

# Register routes with and without /api prefix for seamless proxy compatibility
app.include_router(router)
app.include_router(router, prefix="/api")
app.include_router(batch_router)
app.include_router(batch_router, prefix="/api")
