import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import SplitResult, parse_qs, urlsplit


# Each public red_flags item keeps the same API schema used by the UI and API clients.
RedFlag = Dict[str, str]

_URL_PATTERN = re.compile(
    r"""(?ix)
    (?:https?://|www\.)[^\s<>"']+
    |
    (?<![\w@.-])(?:[\w-]+\.)+[\w-]{2,}(?:/[^\s<>"']*)?
    """
)
# Trim punctuation that commonly follows a URL in a sentence.
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
_TOAD_LURE_PATTERN = re.compile(
    r"\b(?:billing|invoice|auto[\s-]?renew(?:al|ed|ing)?|"
    r"subscription\s+(?:renewal|charge)|recurring\s+charge)\b",
    re.IGNORECASE,
)
_CALLBACK_PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?"
    r"(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{4}(?!\d)"
)
_TRUSTED_PLATFORM_DOMAINS = (
    ("docs.google.com", "/forms"),
    ("forms.office.com", None),
    ("notion.site", None),
    ("canva.com", None),
    ("github.io", None),
    ("vercel.app", None),
)
_OTP_REQUEST_PATTERN = (
    r"\b(?:enter|share|submit|send|provide|type|verify|confirm)\b"
    r".{0,40}\b(?:otp|one[- ]time(?:\s+(?:password|code))?|"
    r"verification code|security code)\b"
)
_CREDENTIAL_REQUEST_PATTERN = (
    r"\b(?:enter|submit|provide|share|send|verify|confirm)\b"
    r".{0,40}\b(?:credentials?|username|password|login details)\b"
)
_KYC_REQUEST_PATTERN = (
    r"\b(?:submit|upload|provide|complete|verify|send)\b"
    r".{0,40}\b(?:kyc|know your customer|identity documents?|proof of identity)\b"
)
_PAYMENT_DETAILS_REQUEST_PATTERN = (
    r"\b(?:enter|submit|provide|update|confirm|verify|pay)\b"
    r".{0,40}\b(?:payment|billing|credit|debit|bank(?:ing)?)(?:\s+card)?"
    r"\s+(?:details?|information|info)\b"
)
_SENSITIVE_SCOPE_PATTERN = re.compile(
    r"(?:^|[\s/:._-])(?:mail|gmail|drive|files|contacts|calendar|"
    r"offline_access|repo|admin|sites\.read(?:\.all)?)(?=$|[\s/:._,-])",
    re.IGNORECASE,
)
_DEVICE_CODE_REQUEST_PATTERNS = (
    r"\b(?:send|share|give|provide|read(?:\s+back)?|tell|request|ask\s+for|enter)\b"
    r".{0,35}\b(?:device|login|sign[- ]?in|verification)\s+(?:login\s+)?code\b",
    r"\b(?:device|login|sign[- ]?in|verification)\s+(?:login\s+)?code\b"
    r".{0,35}\b(?:send|share|give|provide|read|tell|request|ask)\b",
)


class _HTMLSignalsParser(HTMLParser):
    """Collect link destinations and form targets without executing page code."""

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
    """Return a normalized host for a URL or bare domain, if one is present."""
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
    """Treat a host and its subdomains as the same site for form/link checks."""
    first = first.removeprefix("www.")
    second = second.removeprefix("www.")
    return first == second or first.endswith("." + second) or second.endswith("." + first)


def _skeleton(label: str) -> str:
    """Make common lookalike characters easier to compare with brand names."""
    normalized = label.casefold().translate(_CONFUSABLES)
    return normalized.replace("rn", "m").replace("vv", "w")


def _one_edit_apart(first: str, second: str) -> bool:
    """Return whether two names differ by at most one insertion, deletion, or replacement."""
    if abs(len(first) - len(second)) > 1:
        return False
    if first == second:
        return True
    # Compare one character at a time and stop once more than one edit is needed.
    left = 0
    right = 0
    edits = 0
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
    """Convert Unicode host names to IDNA form before URL comparisons."""
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def _urls_in(text: str) -> List[str]:
    """Extract URL-like values and remove sentence punctuation from their ends."""
    return [
        match.group(0).rstrip(_TRAILING_URL_PUNCTUATION)
        for match in _URL_PATTERN.finditer(text)
    ]


def extract_urls(text: str) -> List[str]:
    """Expose the URL extraction used by red-flag detection."""
    return _urls_in(text)


def _add_flag(
    flags: List[RedFlag],
    seen: Set[Tuple[str, str]],
    code: str,
    label: str,
    severity: str,
    evidence: str,
) -> None:
    """Append one public-schema flag, limiting evidence and removing duplicates."""
    # A red flag is rule evidence, not the overall confidence score or final verdict.
    evidence = evidence[:200]
    key = (code, evidence.casefold())
    if key in seen:
        return
    seen.add(key)
    flags.append({
        "code": code,
        "label": label,
        "severity": severity,
        "evidence": evidence,
    })


def _add_language_flags(
    content: str,
    flags: List[RedFlag],
    seen: Set[Tuple[str, str]],
) -> None:
    """Find urgency, payment, and credential phrases in the submitted text."""
    # Severity describes the rule's review priority; it is not a probability.
    for code, label, patterns, severity in (
        ("urgency_language", "Urgency or pressure language", _URGENCY_PATTERNS, "medium"),
        ("payment_request", "Unusual or pressured payment request", _PAYMENT_PATTERNS, "high"),
        ("credential_request", "Credential or one-time-code request", _CREDENTIAL_PATTERNS, "high"),
    ):
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                _add_flag(flags, seen, code, label, severity, match.group(0))
                break


def _add_toad_callback_flag(
    content: str,
    target_url: Optional[str],
    flags: List[RedFlag],
    seen: Set[Tuple[str, str]],
) -> None:
    """Flag billing lures paired with a phone number only when no URL is present."""
    lure = _TOAD_LURE_PATTERN.search(content)
    phone = _CALLBACK_PHONE_PATTERN.search(content)
    if not lure or not phone or target_url:
        return

    # Phone numbers with dots can resemble domains, so remove them before URL detection.
    content_without_phone = _CALLBACK_PHONE_PATTERN.sub(" ", content)
    if _urls_in(content_without_phone):
        return

    _add_flag(
        flags,
        seen,
        "TOAD_CALLBACK",
        "Billing lure includes a callback phone number",
        "high",
        f"{lure.group(0)}; callback number: {phone.group(0)}",
    )


def _url_parts(url: str) -> Optional[SplitResult]:
    """Parse full URLs and bare domains using only urllib's standard parser."""
    candidate = url.strip()
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    elif not re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.IGNORECASE):
        candidate = "https://" + candidate
    try:
        return urlsplit(candidate)
    except ValueError:
        return None


def _find_sensitive_request(content: str) -> Optional[re.Match]:
    """Find a credential, OTP, KYC, or payment request phrase."""
    patterns = _CREDENTIAL_PATTERNS + _PAYMENT_PATTERNS + (
        _OTP_REQUEST_PATTERN,
        _CREDENTIAL_REQUEST_PATTERN,
        _KYC_REQUEST_PATTERN,
        _PAYMENT_DETAILS_REQUEST_PATTERN,
    )
    for pattern in patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match
    return None


def _trusted_platform_for_url(url: str) -> Optional[str]:
    """Return a known free platform domain, with a path check for Google Forms."""
    parts = _url_parts(url)
    host = parts.hostname.lower().rstrip(".") if parts and parts.hostname else ""
    for domain, required_path in _TRUSTED_PLATFORM_DOMAINS:
        is_platform_host = host == domain or host.endswith("." + domain)
        if not is_platform_host:
            continue
        if required_path and not (
            parts.path == required_path or parts.path.startswith(required_path + "/")
        ):
            continue
        return domain
    return None


def _add_trusted_platform_flags(
    content: str,
    urls: List[str],
    flags: List[RedFlag],
    seen: Set[Tuple[str, str]],
) -> None:
    """Flag sensitive requests that send people to common free-form platforms."""
    # A platform is not suspicious by itself; the sensitive request supplies the risk context.
    request = _find_sensitive_request(content)
    if not request:
        return

    for url in urls:
        platform = _trusted_platform_for_url(url)
        if platform:
            _add_flag(
                flags,
                seen,
                "TRUSTED_PLATFORM_ABUSE",
                "Sensitive request uses a trusted free platform",
                "high",
                f"{url} paired with request: {request.group(0)}",
            )


def _has_sensitive_oauth_scope(url: str) -> bool:
    """Check for OAuth consent parameters paired with an access-heavy scope."""
    parts = _url_parts(url)
    if not parts:
        return False

    parameters = parse_qs(parts.query, keep_blank_values=True)
    parameter_names = {name.casefold() for name in parameters}
    if not {"client_id", "scope", "redirect_uri"} <= parameter_names:
        return False

    # Scope text lists the account permissions being requested by the consent link.
    scopes = " ".join(
        value
        for name, values in parameters.items()
        if name.casefold() == "scope"
        for value in values
    )
    return bool(_SENSITIVE_SCOPE_PATTERN.search(scopes))


def _find_device_code_request(content: str) -> Optional[re.Match]:
    """Find a request for a sign-in code, ignoring explicit warnings not to share it."""
    for pattern in _DEVICE_CODE_REQUEST_PATTERNS:
        match = re.search(pattern, content, re.IGNORECASE)
        if not match:
            continue
        preceding_words = content[max(0, match.start() - 16):match.start()]
        if re.search(r"\b(?:do\s+not|don't|never|not)\s+$", preceding_words, re.IGNORECASE):
            continue
        return match
    return None


def _add_oauth_device_flag(
    content: str,
    urls: List[str],
    flags: List[RedFlag],
    seen: Set[Tuple[str, str]],
) -> None:
    """Flag sensitive OAuth consent links or messages asking for device login codes."""
    evidence = [
        f"OAuth URL: {url}"
        for url in urls
        if _has_sensitive_oauth_scope(url)
    ]
    device_request = _find_device_code_request(content)
    if device_request:
        evidence.append(f"Device-code request: {device_request.group(0)}")
    if evidence:
        _add_flag(
            flags,
            seen,
            "OAUTH_DEVICE_PHISHING",
            "OAuth consent or device-code phishing pattern",
            "high",
            "; ".join(evidence),
        )


def _add_url_flags(url: str, flags: List[RedFlag], seen: Set[Tuple[str, str]]) -> None:
    """Check one URL for shorteners, Unicode tricks, and brand lookalikes."""
    host = _hostname(url)
    if not host:
        return

    clean_host = host.removeprefix("www.")
    if any(
        clean_host == shortener or clean_host.endswith("." + shortener)
        for shortener in _SHORTENER_DOMAINS
    ):
        _add_flag(flags, seen, "url_shortener", "URL uses a link-shortening service", "medium", host)

    # Decode IDNA labels before comparing them with familiar brand spellings.
    ascii_host = _ascii_hostname(host)
    decoded_labels = []
    for label in ascii_host.split("."):
        try:
            decoded_labels.append(label.encode("ascii").decode("idna"))
        except UnicodeError:
            decoded_labels.append(label)
    has_unicode = any(not label.isascii() for label in decoded_labels)
    has_punycode = any(label.startswith("xn--") for label in ascii_host.split("."))
    if has_unicode or has_punycode:
        _add_flag(
            flags,
            seen,
            "unicode_domain",
            "Unicode or punycode domain may conceal its true name",
            "medium",
            host,
        )

    for brand, official_domains in _BRAND_DOMAINS.items():
        is_official_domain = any(
            host == official or host.endswith("." + official)
            for official in official_domains
        )
        if is_official_domain:
            continue
        resembles_brand = any(
            _one_edit_apart(part, brand)
            for label in decoded_labels[:-1]
            for part in re.split(r"[^a-z0-9]+", _skeleton(label))
            if len(part) >= len(brand) - 1
        )
        if resembles_brand:
            _add_flag(
                flags,
                seen,
                "lookalike_domain",
                "Domain resembles a well-known brand",
                "high",
                f"{host} resembles {brand}",
            )
            break


def _add_html_flags(
    parser: _HTMLSignalsParser,
    source_host: Optional[str],
    flags: List[RedFlag],
    seen: Set[Tuple[str, str]],
) -> None:
    """Compare visible links with their targets and inspect external POST forms."""
    for href, visible_text in parser.links:
        href_host = _hostname(href)
        visible_urls = _urls_in(visible_text)
        visible_host = _hostname(visible_urls[0]) if visible_urls else None
        if href_host and visible_host and not _same_site(href_host, visible_host):
            _add_flag(
                flags,
                seen,
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
            _add_flag(
                flags,
                seen,
                "external_form_post",
                "Form submits data to an external domain",
                "high",
                f"POST target: {action_host}",
            )


def detect_red_flags(content: str = "", target_url: Optional[str] = None) -> List[RedFlag]:
    """Return ordered, deduplicated risk indicators for text, URLs, and HTML."""
    # These transparent indicators accompany the detector's verdict and confidence.
    flags: List[RedFlag] = []
    seen: Set[Tuple[str, str]] = set()
    _add_language_flags(content, flags, seen)
    _add_toad_callback_flag(content, target_url, flags, seen)

    parser = _HTMLSignalsParser()
    parser.feed(content)

    # Keep URL checks before HTML checks so the public response order stays stable.
    urls = _urls_in(content)
    if target_url:
        urls.append(target_url)
    for url in urls:
        _add_url_flags(url, flags, seen)

    _add_trusted_platform_flags(content, urls, flags, seen)
    _add_oauth_device_flag(content, urls, flags, seen)
    source_host = _hostname(target_url) if target_url else None
    _add_html_flags(parser, source_host, flags, seen)
    return flags
