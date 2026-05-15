"""
ML Phishing Detector
─────────────────────────────────────────────────────────────────────────────
Extracts 30+ lexical / structural features from a URL and classifies it
using a trained RandomForest pipeline.  On first run a synthetic training
corpus is generated; afterwards the fitted model is cached to disk.
"""

import re
import math
import pickle
import os
import warnings
from urllib.parse import urlparse
from typing import List, Dict

import numpy as np

warnings.filterwarnings("ignore")

# ── Feature definitions ────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "update", "confirm",
    "account", "banking", "password", "credential", "wallet", "paypal",
    "netflix", "amazon", "apple", "microsoft", "google", "support",
    "helpdesk", "verify-identity", "suspended", "urgent", "click-here",
    "limited-time", "winner", "free-prize", "restore", "billing",
]

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "work", "date",
    "download", "racing", "bid", "stream", "party", "cricket",
    "science", "faith", "review", "trade", "win", "club",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link", "tiny.cc",
    "rb.gy", "cutt.ly",
}

LEGITIMATE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "microsoft.com",
    "apple.com", "amazon.com", "wikipedia.org", "reddit.com",
    "stackoverflow.com", "netflix.com", "paypal.com",
}

IP_PATTERN   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
PORT_PATTERN = re.compile(r":\d{2,5}$")


# ── Feature extractor ──────────────────────────────────────────────────────────

class URLFeatureExtractor:

    def extract(self, url: str) -> Dict[str, float]:
        try:
            parsed  = urlparse(url)
            full    = url.lower()
            netloc  = parsed.netloc.lower()
            domain  = netloc.split(":")[0]           # strip optional port
            path    = parsed.path.lower()
            query   = parsed.query.lower()
            parts   = domain.split(".")
            apex    = parts[-2] if len(parts) >= 2 else domain
            tld     = parts[-1] if parts else ""

            if domain.startswith("www."):
                domain = domain[4:]

            return {
                # --- lengths ---
                "url_length":              len(url),
                "domain_length":           len(domain),
                "path_length":             len(path),
                "query_length":            len(query),

                # --- character counts ---
                "num_dots":                url.count("."),
                "num_hyphens":             url.count("-"),
                "num_underscores":         url.count("_"),
                "num_slashes":             url.count("/"),
                "num_at_signs":            url.count("@"),
                "num_question_marks":      url.count("?"),
                "num_ampersands":          url.count("&"),
                "num_equal_signs":         url.count("="),
                "num_percent":             url.count("%"),
                "num_digits_in_url":       sum(c.isdigit() for c in url),

                # --- binary flags ---
                "has_ip_address":          1 if IP_PATTERN.match(domain) else 0,
                "has_https":               1 if parsed.scheme == "https" else 0,
                "has_port":                1 if parsed.port else 0,
                "has_at_sign":             1 if "@" in url else 0,
                "has_double_slash_in_path":1 if "//" in path else 0,
                "has_hex_encoding":        1 if "%" in url else 0,
                "is_url_shortener":        1 if any(s in domain for s in URL_SHORTENERS) else 0,
                "is_legitimate_domain":    1 if any(domain == d or domain.endswith("."+d)
                                                    for d in LEGITIMATE_DOMAINS) else 0,

                # --- domain structure ---
                "num_subdomains":          max(len(parts) - 2, 0),
                "apex_has_digit":          1 if any(c.isdigit() for c in apex) else 0,
                "apex_has_hyphen":         1 if "-" in apex else 0,
                "suspicious_tld":          1 if tld in SUSPICIOUS_TLDS else 0,

                # --- keyword signals ---
                "has_suspicious_keyword":  1 if any(k in full for k in SUSPICIOUS_KEYWORDS) else 0,
                "suspicious_keyword_count":sum(1 for k in SUSPICIOUS_KEYWORDS if k in full),

                # --- entropy / ratios ---
                "apex_entropy":            self._entropy(apex),
                "digit_letter_ratio":      (sum(c.isdigit() for c in url) /
                                            max(sum(c.isalpha() for c in url), 1)),
                "special_char_ratio":      (sum(not c.isalnum() for c in url) /
                                            max(len(url), 1)),
            }
        except Exception:
            return {k: 0 for k in self.extract("http://example.com")}

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        probs = [text.count(c) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def to_vector(self, url: str) -> np.ndarray:
        return np.array(list(self.extract(url).values()), dtype=float).reshape(1, -1)


# ── Classifier ─────────────────────────────────────────────────────────────────

class PhishingDetector:
    MODEL_PATH = "phishing_model.pkl"

    def __init__(self):
        self.extractor  = URLFeatureExtractor()
        self.model      = None
        self.is_trained = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def train_or_load(self):
        if os.path.exists(self.MODEL_PATH):
            self._load()
        else:
            self._train()

    def predict(self, url: str) -> dict:
        features = self.extractor.extract(url)
        X        = np.array(list(features.values()), dtype=float).reshape(1, -1)

        if self.model and self.is_trained:
            proba        = self.model.predict_proba(X)[0]
            phish_prob   = float(proba[1])
            confidence   = round(float(max(proba)) * 100, 2)
        else:
            phish_prob = self._heuristic(features)
            confidence = 60.0

        return {
            "phishing_probability": round(phish_prob, 4),
            "confidence":           confidence,
            "features":             features,
            "top_indicators":       self._indicators(features),
        }

    # ── Private helpers ────────────────────────────────────────────────────────

    def _load(self):
        with open(self.MODEL_PATH, "rb") as f:
            self.model = pickle.load(f)
        self.is_trained = True
        print("[ML] ✅ Model loaded from disk")

    def _train(self):
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report

        print("[ML] 🧠 Training RandomForest phishing classifier …")

        phishing = self._phishing_corpus()
        legit    = self._legit_corpus()

        X = np.array([self.extractor.to_vector(u)[0] for u in phishing + legit])
        y = np.array([1] * len(phishing) + [0] * len(legit))

        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        self.model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    RandomForestClassifier(
                n_estimators=300,
                max_depth=12,
                min_samples_split=4,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )),
        ])
        self.model.fit(X_tr, y_tr)

        y_pred = self.model.predict(X_te)
        print(classification_report(y_te, y_pred, target_names=["Legit", "Phishing"]))

        with open(self.MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)

        self.is_trained = True
        print("[ML] ✅ Model trained and saved")

    @staticmethod
    def _heuristic(features: dict) -> float:
        score = 0.0
        if features.get("has_ip_address"):              score += 0.30
        if features.get("has_suspicious_keyword"):      score += 0.20
        if features.get("suspicious_tld"):              score += 0.20
        if features.get("num_subdomains", 0) > 3:       score += 0.10
        if features.get("url_length", 0) > 75:          score += 0.10
        if features.get("has_at_sign"):                  score += 0.10
        if features.get("is_url_shortener"):             score += 0.05
        if features.get("has_hex_encoding"):             score += 0.05
        return min(score, 0.95)

    @staticmethod
    def _indicators(features: dict) -> List[str]:
        checks = [
            (features.get("has_ip_address"),                  "IP address used as domain (T1566)"),
            (features.get("has_suspicious_keyword"),          "Suspicious keywords in URL"),
            (features.get("suspicious_tld"),                  "Suspicious top-level domain"),
            ((features.get("num_subdomains", 0) > 3),         "Excessive subdomains"),
            ((features.get("url_length", 0) > 75),            "Abnormally long URL"),
            (features.get("has_at_sign"),                     "@ symbol (credential spoofing)"),
            (features.get("is_url_shortener"),                "URL shortener detected"),
            (features.get("has_hex_encoding"),                "Hex/percent encoding in URL"),
            ((features.get("apex_entropy", 0) > 3.8),        "High domain entropy (randomised)"),
            (not features.get("has_https"),                   "No HTTPS / plain HTTP"),
            (features.get("apex_has_digit"),                  "Digits in domain name"),
            (features.get("has_double_slash_in_path"),        "Double slash in path"),
        ]
        return [msg for flag, msg in checks if flag][:6]

    # ── Training corpora ───────────────────────────────────────────────────────

    @staticmethod
    def _phishing_corpus() -> List[str]:
        base = [
            "http://paypa1-secure-login.xyz/update",
            "http://192.168.1.1/login/verify",
            "http://secure-apple-id.tk/signin",
            "http://amazon-account-suspended.ml/verify",
            "http://microsoft-support-update.cf/reset",
            "http://www.paypal.com.phishing-site.xyz/login",
            "http://netflix-update-billing.top/account",
            "http://login.secure-verify.tk/signin.php?id=123",
            "http://bank-secure-login.xyz/auth/verify?token=abc123&session=xyz",
            "http://account-verify-urgent.ml/login/secure/confirm",
            "http://secure.paypal.com.evil-site.com/signin",
            "http://appleid.apple.com.phish.xyz/auth",
            "http://bit.ly/fake-login-page",
            "http://192.168.0.1@evil-site.com/login",
            "http://update-your-account-immediately.xyz/login",
            "http://free-prize-winner-2024.tk/claim",
            "http://verify-your-identity-now.ml/confirm?id=1234",
            "http://suspended-account-restore.cf/login",
            "http://secure-helpdesk-support.gq/ticket",
            "http://login.microsoftonline.com.evil.xyz/auth",
            "http://facebook-login-verify.tk/account",
            "http://google-account-recovery.ml/signin",
            "http://amazon-order-confirm.xyz/order?id=fake9999",
            "http://click-here-to-claim-reward.top/win",
            "http://12.34.56.78/phishing/page",
            "http://secure-banking-login.xyz/verify",
            "http://password-reset-urgent.ml/reset",
            "http://credential-update-required.cf/login",
            "http://your-account-has-been-compromised.tk/fix",
            "http://limited-time-offer-free.work/claim",
            "http://verification-needed.support/login.php",
            "http://sign-in-paypal.com.account-update.xyz/",
            "http://www.microsoft-verify-365.top/signin",
            "http://secure%20login.banking.com.xyz/auth",
            "http://www.paypa1.com/cgi-bin/webscr?cmd=_login-run",
            "http://customer-support-helpdesk.xyz/ticket?id=88abc",
            "http://win-prize-1000usd.gq/claim",
            "http://update-billing-info.work/account",
            "http://secure-document-view.ml/docid=1234&token=abcd",
            "http://dlv3r-package-notify.xyz/track?parcel=abc123",
            "http://icloud-account-verify.cf/signin",
            "http://online-banking-secure.gq/login",
            "http://re-verify-account-suspended.tk/restore",
            "http://mail-verification-required.ml/verify-now",
            "http://tax-refund-gov-irs.xyz/claim",
        ]
        # Augment by repeating with minor variation for sufficient training size
        augmented = []
        for u in base:
            augmented.append(u)
            augmented.append(u + "?ref=email&src=phish")
            augmented.append(u.replace("http://", "http://www."))
        return augmented

    @staticmethod
    def _legit_corpus() -> List[str]:
        base = [
            "https://www.google.com",
            "https://mail.google.com/mail/u/0/",
            "https://www.github.com/username/repo",
            "https://stackoverflow.com/questions/123456/how-to-code",
            "https://www.amazon.com/dp/B09XYZ123",
            "https://en.wikipedia.org/wiki/Phishing",
            "https://www.reddit.com/r/netsec/comments/xyz",
            "https://docs.python.org/3/library/urllib.html",
            "https://www.microsoft.com/en-us/windows",
            "https://www.apple.com/iphone",
            "https://www.linkedin.com/in/username",
            "https://twitter.com/username",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.netflix.com/browse",
            "https://www.paypal.com/signin",
            "https://accounts.google.com/signin",
            "https://login.microsoftonline.com/",
            "https://appleid.apple.com/",
            "https://news.ycombinator.com",
            "https://arxiv.org/abs/2401.00001",
            "https://www.kaggle.com/datasets",
            "https://huggingface.co/models",
            "https://fastapi.tiangolo.com/",
            "https://developer.mozilla.org/en-US/docs/Web",
            "https://www.cloudflare.com/",
            "https://aws.amazon.com/s3/",
            "https://www.nytimes.com/section/technology",
            "https://www.bbc.com/news",
            "https://www.forbes.com/technology/",
            "https://www.wired.com/story/security",
            "https://www.cisco.com/c/en/us/products/security",
            "https://www.ibm.com/security",
            "https://www.paloaltonetworks.com/",
            "https://www.crowdstrike.com/",
            "https://www.splunk.com/",
            "https://www.elastic.co/",
            "https://grafana.com/",
            "https://prometheus.io/",
            "https://kubernetes.io/docs/",
            "https://hub.docker.com/",
        ]
        augmented = []
        for u in base:
            augmented.append(u)
            augmented.append(u + "/page/1")
            augmented.append(u + "?lang=en")
        return augmented
