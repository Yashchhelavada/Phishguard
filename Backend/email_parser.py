"""
Email URL Parser & Structure Analyzer
Extracts all URLs from raw email content and flags social-engineering signals.
"""

import re
from typing import List, Dict
from urllib.parse import urlparse


URL_RE = re.compile(
    r"https?://[^\s<>\"'(){}\[\]|\\^`]*"
    r"|"
    r"(?:www\.)[^\s<>\"'(){}\[\]|\\^`]*"
    r"|"
    r"(?:[a-zA-Z0-9\-]+\.)"
    r"(?:com|org|net|edu|gov|io|co|uk|us|xyz|tk|ml|ga|cf|gq|top|info|biz|de|fr|jp|cn|ru)"
    r"[^\s<>\"'(){}\[\]]*",
    re.IGNORECASE,
)

HTML_LINK_RE = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

URGENCY_WORDS = [
    "urgent", "immediately", "act now", "click now", "expires",
    "suspended", "verify", "confirm", "limited time", "final notice",
    "account blocked", "unauthorized access", "suspicious activity",
    "your account will be closed",
]

CREDENTIAL_WORDS = [
    "password", "username", "login credentials", "social security",
    "credit card", "bank account", "billing information", "ssn",
    "date of birth", "mother's maiden name",
]


class EmailURLParser:

    def extract_urls(self, text: str) -> List[str]:
        """Return a deduplicated list of cleaned URLs found in `text`."""
        raw  = URL_RE.findall(text)
        seen = set()
        out  = []
        for url in raw:
            url = url.rstrip(".,;:!?)\"'>")
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            if url not in seen and len(url) > 12:
                seen.add(url)
                out.append(url)
        return out

    def analyze_email_structure(self, text: str) -> Dict:
        """Return structural risk signals about the email body."""
        lower = text.lower()

        # Urgency language
        urgency_hits = [w for w in URGENCY_WORDS if w in lower]

        # Credential harvesting language
        cred_hits = [w for w in CREDENTIAL_WORDS if w in lower]

        # Mismatched anchor text vs href (classic phishing tell)
        spoofed = []
        for m in HTML_LINK_RE.finditer(text):
            href  = m.group(1).strip()
            label = re.sub(r"<[^>]+>", "", m.group(2)).strip().lower()
            # If the link label looks like a URL but differs from href
            if re.search(r"https?://|www\.", label) and href.lower() != label:
                spoofed.append({"displayed": label[:80], "actual": href[:80]})

        urls      = self.extract_urls(text)
        risk_score = self._email_risk(urgency_hits, cred_hits, spoofed, urls)

        return {
            "total_urls_found":       len(urls),
            "has_urgency_language":   bool(urgency_hits),
            "urgency_phrases":        urgency_hits[:5],
            "requests_credentials":   bool(cred_hits),
            "credential_phrases":     cred_hits[:3],
            "spoofed_links":          spoofed[:5],
            "email_risk_score":       round(risk_score, 2),
            "email_risk_label":       self._risk_label(risk_score),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _email_risk(urgency, creds, spoofed, urls) -> float:
        score = 0.0
        if urgency: score += 0.25
        if creds:   score += 0.30
        if spoofed: score += 0.35
        if len(urls) > 8: score += 0.10
        return min(score, 1.0)

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 0.65: return "HIGH"
        if score >= 0.35: return "MEDIUM"
        return "LOW"
