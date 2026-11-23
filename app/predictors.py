"""Model, provider, and rule-based prediction paths used by the API."""

import os
import re
from io import BytesIO
from typing import Optional, Dict, Any, List
from PIL import Image
import torch
import requests
from app.models_loader import get_registry, img_transform, DEVICE
from app.llm_helpers import classify_with_nvidia

USE_OCR = os.getenv("MM_USE_OCR", "1") == "1"
N8N_OCR_ENDPOINT = os.getenv("MM_N8N_OCR_ENDPOINT", "http://localhost:5678/webhook/ocr")
TESSERACT_CMD = os.getenv("MM_TESSERACT_CMD", r"C:\Program Files\Tesseract-OCR\tesseract.exe")
N8N_TIMEOUT = int(os.getenv("MM_N8N_TIMEOUT", "5"))
# The default fusion gives most weight to text and shares the rest across other inputs.
DEFAULT_ALPHA = float(os.getenv("MM_FUSION_ALPHA", "0.80"))
URL_BINARY_WEIGHT = float(os.getenv("MM_URL_BINARY_WEIGHT", "0.5"))

# ---------------- OCR Helpers ----------------
def ocr_n8n(image_bytes: bytes) -> Optional[str]:
    """Try the configured OCR service and return extracted text when available."""
    try:
        # The OCR endpoint expects an image file under the "file" field in its payload.
        files = {"file": ("img.png", image_bytes, "image/png")}
        r = requests.post(N8N_OCR_ENDPOINT, files=files, timeout=N8N_TIMEOUT)
        if r.status_code == 200:
            j = r.json()
            return j.get("ocr_text") or j.get("text") or j.get("ocr") or None
    except Exception:
        pass
    return None

def ocr_local(image_bytes: bytes) -> Optional[str]:
    """Use local Tesseract OCR when the configured OCR service is unavailable."""
    try:
        # OCR means optical character recognition: convert visible image words to text.
        import pytesseract
        pytesseract.pytesseract.tesseract_cmd = TESSERACT_CMD
        img = Image.open(BytesIO(image_bytes)).convert("RGB")
        txt = pytesseract.image_to_string(img)
        return txt if txt and txt.strip() else None
    except Exception:
        return None

def get_ocr_text_from_bytes(image_bytes: bytes) -> Optional[str]:
    """Run OCR in preferred-provider order, while honoring the global OCR switch."""
    if not USE_OCR:
        return None
    # Prefer the configured endpoint; local Tesseract is the fallback if it is unavailable.
    txt = ocr_n8n(image_bytes)
    if txt and txt.strip():
        return txt.strip()
    txt = ocr_local(image_bytes)
    if txt and txt.strip():
        return txt.strip()
    return None

# ---------------- Heuristic Fallback Scanners ----------------
def heuristic_text_score(text: str) -> float:
    """Estimate phishing risk from simple phrases when learned models are unavailable."""
    t = text.lower()
    # This starts from a small baseline, then adds a weight for each matching pattern.
    score = 0.05
    suspicious_patterns = [
        (r"\b(urgent|immediate action|suspended|verify your account|unauthorized|blocked)\b", 0.35),
        (r"\b(click here|log in now|reset password|claim reward|lottery|prize|winner)\b", 0.30),
        (r"\b(wire transfer|gift card|crypto|bitcoin|western union|ssn|social security)\b", 0.35),
        (r"\b(bank of|paypal|netflix|apple id|microsoft|amazon|google account)\b", 0.20),
        (r"https?://[^\s]+", 0.15),
        (r"\b(dear customer|dear user|dear client|valued customer)\b", 0.15),
        (r"\b(24 hours|limited time|immediately|expire|penalty)\b", 0.20)
    ]
    for pat, weight in suspicious_patterns:
        if re.search(pat, t):
            score += weight
    # Keep the fallback score away from absolute certainty because keywords are imperfect.
    return float(min(0.98, max(0.02, score)))


def _looks_like_brand_impersonation(url: str) -> bool:
    """Check whether a known brand appears outside its expected domain."""
    brands = (
        "paypal", "netflix", "apple", "microsoft",
        "google", "amazon", "chase", "wellsfargo",
    )
    contains_brand = any(brand in url for brand in brands)
    uses_brand_domain = any(
        url.endswith(f".{brand}.com") or f".{brand}.com/" in url
        for brand in brands
    )
    return contains_brand and not uses_brand_domain


def heuristic_url_score(url: str) -> Dict[str, float]:
    """Score common suspicious URL patterns and return normalized class probabilities."""
    u = url.lower()
    phish_score = 0.05
    malware_score = 0.02

    # Suspicious keywords in URL
    if any(k in u for k in ["login", "verify", "secure", "update", "banking", "wallet", "signin", "auth", "confirm", "free", "gift"]):
        phish_score += 0.35
    # Brand impersonation checks
    if _looks_like_brand_impersonation(u):
        phish_score += 0.40
    # Suspicious TLDs
    if re.search(r"\.(xyz|top|work|click|cf|tk|ml|gq|ga|buzz|rest|live|fit|bar)\b", u):
        phish_score += 0.25
        malware_score += 0.15
    # Raw IP address used as host
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u):
        phish_score += 0.45
        malware_score += 0.20
    # Malware extensions
    if re.search(r"\.(exe|scr|apk|vbs|bat|cmd|ps1|iso|dmg)$", u.split("?")[0]):
        malware_score += 0.70
        phish_score += 0.20
    # Abnormal length or excess hyphens/subdomains
    if u.count(".") > 3 or u.count("-") > 3:
        phish_score += 0.20

    phish_score = min(0.95, max(0.02, phish_score))
    malware_score = min(0.95, max(0.01, malware_score))
    benign_score = max(0.01, 1.0 - (phish_score + malware_score))
    total = phish_score + malware_score + benign_score

    # probs are class probabilities; normalization makes them add up to one.
    return {
        "benign": round(float(benign_score / total), 4),
        "phishing": round(float(phish_score / total), 4),
        "malware": round(float(malware_score / total), 4),
    }

from app.dataset_intel import get_dataset_intel

# ---------------- Model Predictors ----------------
def predict_text_probs(text: Optional[str]) -> Dict[str, float]:
    """Try dataset intelligence and NVIDIA first, then local transformer, then rules."""
    if not text or not str(text).strip():
        return {"benign": 0.99, "phishing": 0.01}
    
    # Dataset intelligence adds a small signal when text matches a known scam phrase.
    intel = get_dataset_intel().check_text(text)
    intel_boost = 0.25 if (intel and intel.get("matched")) else 0.0

    # The LLM can interpret context and indirect wording; no key, timeout, or invalid
    # output returns None, so the local transformer or heuristic can still answer.
    nvidia_probs = classify_with_nvidia(text, "text")
    if nvidia_probs:
        p_phish = min(0.99, nvidia_probs["phishing"] + intel_boost)
        return {"benign": round(1.0 - p_phish, 4), "phishing": round(p_phish, 4)}

    reg = get_registry()
    if reg.text_tokenizer and reg.text_model:
        try:
            enc = reg.text_tokenizer(text, truncation=True, padding="max_length", max_length=256, return_tensors="pt")
            enc = {k: v.to(DEVICE) for k, v in enc.items()}
            with torch.no_grad():
                logits = reg.text_model(**enc).logits
                probs = torch.softmax(logits, dim=1)[0].cpu().numpy().tolist()
            if len(probs) >= 2:
                # The second output is the trained phishing class score.
                p_phish = min(0.99, float(probs[1]) + intel_boost)
                return {"benign": round(1.0 - p_phish, 4), "phishing": round(p_phish, 4)}
        except Exception as e:
            print(f"[predictors] Text model inference error: {e}")
    
    # Keep a local rule-based fallback when both hosted and learned models are unavailable.
    p_phish = heuristic_text_score(text)
    if intel_boost > 0:
        p_phish = min(0.98, p_phish + intel_boost)
    return {"benign": round(1.0 - p_phish, 4), "phishing": round(p_phish, 4)}

def _url_model_probabilities(scores: List[float]) -> Optional[Dict[str, float]]:
    """Map model output positions to the public URL class names."""
    if len(scores) == 3:
        # The three-class URL model orders its outputs as benign, phishing, malware.
        return {
            "benign": round(float(scores[0]), 4),
            "phishing": round(float(scores[1]), 4),
            "malware": round(float(scores[2]), 4),
        }
    if len(scores) == 2:
        # Older URL model files only distinguish benign from phishing.
        return {
            "benign": round(float(scores[0]), 4),
            "phishing": round(float(scores[1]), 4),
            "malware": 0.0,
        }
    return None


def predict_url_probs(url: Optional[str]) -> Dict[str, float]:
    """Check known URL intelligence before provider, local model, and heuristic paths."""
    if not url or not str(url).strip():
        return {"benign": 0.99, "phishing": 0.01, "malware": 0.0}

    # A known-data match can decide the scan before calling any model.
    intel = get_dataset_intel().check_url(url)
    if intel:
        if intel.get("matched"):
            ttype = intel.get("threat_type", "phishing")
            if ttype == "malware":
                return {"benign": 0.01, "phishing": 0.15, "malware": 0.84}
            return {"benign": 0.02, "phishing": 0.95, "malware": 0.03}

    # A hosted classification can use context beyond URL keywords. If unavailable,
    # continue to the local model and then the transparent URL rules below.
    nvidia_probs = classify_with_nvidia(url, "url")
    if nvidia_probs:
        return {label: round(probability, 4) for label, probability in nvidia_probs.items()}

    reg = get_registry()
    if reg.url_tokenizer and reg.url_model:
        try:
            enc = reg.url_tokenizer(url, truncation=True, padding="max_length", max_length=64, return_tensors="pt")
            enc = {k: v.to(DEVICE) for k, v in enc.items()}
            with torch.no_grad():
                logits = reg.url_model(**enc).logits
                scores = torch.softmax(logits, dim=1)[0].cpu().numpy().tolist()
            model_probs = _url_model_probabilities(scores)
            if model_probs is not None:
                return model_probs
        except Exception as e:
            print(f"[predictors] URL model inference error: {e}")

    if intel and intel.get("threat_type") == "benign":
        h_score = heuristic_url_score(url)
        if h_score.get("phishing", 0.0) < 0.40:
            return {"benign": 0.96, "phishing": 0.03, "malware": 0.01}
    
    # Fallback heuristic
    return heuristic_url_score(url)

def predict_image_probs(image_bytes: bytes, ocr_text: Optional[str] = None) -> Dict[str, float]:
    """Classify image OCR text or pixels, using a cautious estimate if neither is readable."""
    # If OCR succeeds, the text model can recognize suspicious wording in the screenshot.
    if ocr_text and ocr_text.strip():
        nvidia_probs = classify_with_nvidia(ocr_text, "text")
        if nvidia_probs:
            return {label: round(probability, 4) for label, probability in nvidia_probs.items()}

    reg = get_registry()
    if reg.image_model:
        try:
            img = Image.open(BytesIO(image_bytes)).convert("RGB")
            x = img_transform(img).unsqueeze(0).to(DEVICE)
            with torch.no_grad():
                logits = reg.image_model(x)
                probs = torch.softmax(logits, dim=1)[0].cpu().numpy().tolist()
            if len(probs) >= 2:
                return {"benign": round(float(probs[0]), 4), "phishing": round(float(probs[1]), 4)}
        except Exception as e:
            print(f"[predictors] Image model inference error: {e}")
    # If pixel classification failed, at least apply the text rules to readable OCR.
    ocr_txt = ocr_text or get_ocr_text_from_bytes(image_bytes)
    if ocr_txt:
        p_phish = heuristic_text_score(ocr_txt)
        return {"benign": round(1.0 - p_phish, 4), "phishing": round(p_phish, 4)}
    # Without pixels or readable words, use a cautious estimate rather than claim certainty.
    return {"benign": 0.45, "phishing": 0.55}

# ---------------- Multimodal Fusion ----------------
def url_multiclass_to_binary(url_probs: Dict[str, float]) -> float:
    """Treat both phishing and malware probabilities as suspicious URL risk."""
    p_phish = url_probs.get("phishing", 0.0)
    p_malware = url_probs.get("malware", 0.0)
    return float(min(1.0, p_phish + p_malware))


def _select_text_signal(text_p: Optional[float], ocr_p: Optional[float]) -> Optional[float]:
    """Use the stronger text signal when both typed text and OCR text are present."""
    if text_p is not None and ocr_p is not None:
        return max(text_p, ocr_p)
    return text_p if text_p is not None else ocr_p


def _blend_available_probabilities(available: Dict[str, float], alpha: float) -> float:
    """Give text its configured weight and share the remainder across other inputs."""
    if "text" not in available:
        return sum(available.values()) / len(available)

    other_modalities = [name for name in available if name != "text"]
    if not other_modalities:
        return available["text"]

    # alpha is the text share; divide the remaining weight equally among other inputs.
    other_weight = (1.0 - alpha) / len(other_modalities)
    blended = alpha * available["text"]
    for name in other_modalities:
        blended += other_weight * available[name]
    return blended


def fuse_all(
    text_p: Optional[float],
    url_p_bin: Optional[float],
    img_p: Optional[float],
    ocr_p: Optional[float] = None,
    alpha: float = DEFAULT_ALPHA
) -> Dict[str, Any]:
    """Combine the available modality scores without treating missing inputs as zero."""
    # These probabilities are risk scores for each input type; OCR is grouped with text.
    # Keep raw modality scores for callers that display or inspect the original probs.
    modalities = {"text": text_p, "url": url_p_bin, "img": img_p, "ocr": ocr_p}
    text_signal = _select_text_signal(text_p, ocr_p)

    # A missing input is not the same as a zero-risk input, so leave it out of the blend.
    available: Dict[str, float] = {}
    if text_signal is not None:
        available["text"] = text_signal
    if url_p_bin is not None:
        available["url"] = url_p_bin
    if img_p is not None:
        available["img"] = img_p
    if not available:
        return {"fused_prob": 0.0, "label": "benign", **modalities}

    fused = _blend_available_probabilities(available, alpha)
    fused = float(min(1.0, max(0.0, fused)))
    # The existing decision threshold is 0.5; keep it unchanged for compatibility.
    label = "phishing" if fused >= 0.5 else "benign"
    return {
        "fused_prob": round(fused, 4),
        "label": label,
        "probs": {
            "benign": round(1.0 - fused, 4),
            "phishing": round(fused, 4)
        },
        **modalities
    }
