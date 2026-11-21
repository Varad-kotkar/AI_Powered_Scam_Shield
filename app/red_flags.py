import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit


RedFlag = Dict[str, str]

_URL_PATTERN = re.compile(
    r"""(?ix)
    (?:https?://|www\.)[^\s<>"']+
    |
    (?<![\w@.-])(?:[\w-]+\.)+[\w-]{2,}(?:/[^\s<>"']*)?
    """
)
_TRAILING_URL_PUNCTUATION = ".,;:!?)]}"
_SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy",
    "lnkd.in", "tiny.cc", "bit.do", "forms.gle", "t.ly",
}
_BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.in"),
    "apple": ("apple.com",),
    "binance": ("binance.com",),
    "chase": ("chase.com",),
    "coinbase": ("coinbase.com",),
    "dhl": ("dhl.com",),
    "facebook": ("facebook.com",),
    "fedex": ("fedex.com",),
    "google": ("google.com", "google.co.uk", "google.ca", "google.in"),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com",),
    "microsoft": ("microsoft.com", "microsoft.co.uk", "microsoft.ca", "microsoft.in"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com", "paypal.co.uk", "paypal.ca", "paypal.in"),
    "ups": ("ups.com",),
    "wellsfargo": ("wellsfargo.com",),
    "whatsapp": ("whatsapp.com",),
}
_CONFUSABLES = str.maketrans({
    "а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "к": "k",
    "м": "m", "о": "o", "р": "p", "ѕ": "s", "т": "t", "у": "y",
    "х": "x", "в": "b", "ԁ": "d", "ӏ": "l", "ı": "i", "０": "0",
    "１": "1", "0": "o", "1": "l", "3": "e", "5": "s",
})
_URGENCY_PATTERNS = (
    r"\burgent(?:ly)?\b",
    r"\bact\s+now\b",
    r"\bimmediate(?:ly)?\b",
    r"\bwithin\s+\d+\s*(?:minutes?|hours?|days?)\b",
    r"\b(?:account|access|service)\s+(?:will\s+be\s+)?suspended\b",
    r"\bfinal\s+notice\b",
    r"\bexpires?\s+(?:today|soon|in\s+\d+)\b",
    r"\blimited[- ]time\b",
)
_PAYMENT_PATTERNS = (
    r"\b(?:wire|bank)\s+transfer\b",
    r"\bgift\s+cards?\b",
    r"\b(?:bitcoin|crypto(?:currency)?)\b",
    r"\bpay\s+now\b",
    r"\bpayment\s+(?:due|required|failed|overdue)\b",
    r"\b(?:send|transfer)\s+(?:the\s+)?money\b",
    r"\b(?:pay|send|transfer)\s+(?:(?:usd|inr|rs\.?|[$€£])\s*)?\d[\d,.]*\b",
    r"\b(?:processing|release|delivery)\s+fee\b",
    r"\binvoice\s+(?:attached|overdue|due)\b",
)
_CREDENTIAL_PATTERNS = (
    r"\b(?:verify|confirm|reset)\s+(?:your\s+)?(?:password|credentials?|account)\b",
    r"\b(?:share|send|enter)\s+(?:your\s+)?(?:password|one[- ]time\s+code|otp)\b",
)


class _HTMLSignalsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[Tuple[str, str]] = []
        self.forms: List[Tuple[str, str]] = []
        self._active_link: Optional[Tuple[str, List[str]]] = None
        self._active_form: Optional[Dict[str, str]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "a" and attributes.get("href"):
            self._active_link = (attributes["href"], [])
        elif tag.lower() == "form":
            self._active_form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").lower(),
            }

    def handle_data(self, data: str) -> None:
        if self._active_link:
            self._active_link[1].append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._active_link:
            href, text_parts = self._active_link
            self.links.append((href, " ".join(" ".join(text_parts).split())))
            self._active_link = None
        elif tag.lower() == "form" and self._active_form:
            self.forms.append((self._active_form["action"], self._active_form["method"]))
            self._active_form = None


def _hostname(value: str) -> Optional[str]:
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("//"):
        candidate = "http:" + candidate
    elif re.match(r"^[a-z][a-z0-9+.-]*:", candidate, re.IGNORECASE):
        if not re.match(r"^https?://", candidate, re.IGNORECASE):
            return None
    else:
        candidate = "http://" + candidate
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    return host.rstrip(".").lower() if host else None


def _same_site(first: str, second: str) -> bool:
    first = first.removeprefix("www.")
    second = second.removeprefix("www.")
    return first == second or first.endswith("." + second) or second.endswith("." + first)


def _skeleton(label: str) -> str:
    normalized = label.casefold().translate(_CONFUSABLES)
    return normalized.replace("rn", "m").replace("vv", "w")


def _one_edit_apart(first: str, second: str) -> bool:
    if abs(len(first) - len(second)) > 1:
        return False
    if first == second:
        return True
    left = right = edits = 0
    while left < len(first) and right < len(second):
        if first[left] == second[right]:
            left += 1
            right += 1
            continue
        edits += 1
        if edits > 1:
            return False
        if len(first) > len(second):
            left += 1
        elif len(second) > len(first):
            right += 1
        else:
            left += 1
            right += 1
    if left < len(first) or right < len(second):
        edits += 1
    return edits <= 1


def _ascii_hostname(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def _urls_in(text: str) -> List[str]:
    return [
        match.group(0).rstrip(_TRAILING_URL_PUNCTUATION)
        for match in _URL_PATTERN.finditer(text)
    ]


def detect_red_flags(content: str = "", target_url: Optional[str] = None) -> List[RedFlag]:
    flags: List[RedFlag] = []
    seen: Set[Tuple[str, str]] = set()

    def add_flag(code: str, label: str, severity: str, evidence: str) -> None:
        evidence = evidence[:200]
        key = (code, evidence.casefold())
        if key not in seen:
            seen.add(key)
            flags.append({
                "code": code,
                "label": label,
                "severity": severity,
                "evidence": evidence,
            })

    for code, label, patterns, severity in (
        ("urgency_language", "Urgency or pressure language", _URGENCY_PATTERNS, "medium"),
        ("payment_request", "Unusual or pressured payment request", _PAYMENT_PATTERNS, "high"),
        ("credential_request", "Credential or one-time-code request", _CREDENTIAL_PATTERNS, "high"),
    ):
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                add_flag(code, label, severity, match.group(0))
                break

    parser = _HTMLSignalsParser()
    parser.feed(content)

    urls = _urls_in(content)
    if target_url:
        urls.append(target_url)
    for url in urls:
        host = _hostname(url)
        if not host:
            continue
        clean_host = host.removeprefix("www.")
        if any(clean_host == shortener or clean_host.endswith("." + shortener) for shortener in _SHORTENER_DOMAINS):
            add_flag("url_shortener", "URL uses a link-shortening service", "medium", host)

        ascii_host = _ascii_hostname(host)
        decoded_labels = []
        for label in ascii_host.split("."):
            try:
                decoded_labels.append(label.encode("ascii").decode("idna"))
            except UnicodeError:
                decoded_labels.append(label)
        has_unicode = any(not label.isascii() for label in decoded_labels)
        if has_unicode or any(label.startswith("xn--") for label in ascii_host.split(".")):
            add_flag("unicode_domain", "Unicode or punycode domain may conceal its true name", "medium", host)

        for brand, official_domains in _BRAND_DOMAINS.items():
            if any(host == official or host.endswith("." + official) for official in official_domains):
                continue
            if any(
                _one_edit_apart(part, brand)
                for label in decoded_labels[:-1]
                for part in re.split(r"[^a-z0-9]+", _skeleton(label))
                if len(part) >= len(brand) - 1
            ):
                add_flag("lookalike_domain", "Domain resembles a well-known brand", "high", f"{host} resembles {brand}")
                break

    source_host = _hostname(target_url) if target_url else None
    for href, visible_text in parser.links:
        href_host = _hostname(href)
        visible_urls = _urls_in(visible_text)
        visible_host = _hostname(visible_urls[0]) if visible_urls else None
        if href_host and visible_host and not _same_site(href_host, visible_host):
            add_flag(
                "link_href_mismatch",
                "Displayed link destination differs from its actual target",
                "high",
                f"Displayed: {visible_host}; target: {href_host}",
            )

    for action, method in parser.forms:
        if method != "post":
            continue
        action_host = _hostname(action)
        if action_host and (source_host is None or not _same_site(source_host, action_host)):
            add_flag(
                "external_form_post",
                "Form submits data to an external domain",
                "high",
                f"POST target: {action_host}",
            )

    return flags
