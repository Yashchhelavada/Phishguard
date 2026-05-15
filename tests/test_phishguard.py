"""
PhishGuard Test Suite
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from ml_detector import PhishingDetector, URLFeatureExtractor
from email_parser import EmailURLParser
from database import Database


# ── ML Detector ───────────────────────────────────────────────────────────────

class TestURLFeatureExtractor:
    def setup_method(self):
        self.ext = URLFeatureExtractor()

    def test_known_phishing_url(self):
        f = self.ext.extract("http://paypa1-secure-login.xyz/update?token=abc")
        assert f["has_https"] == 0
        assert f["suspicious_tld"] == 1
        assert f["has_suspicious_keyword"] == 1

    def test_known_legit_url(self):
        f = self.ext.extract("https://www.google.com/search?q=test")
        assert f["has_https"] == 1
        assert f["is_legitimate_domain"] == 1
        assert f["has_ip_address"] == 0

    def test_ip_address_detection(self):
        f = self.ext.extract("http://192.168.1.1/login")
        assert f["has_ip_address"] == 1

    def test_url_shortener_detection(self):
        f = self.ext.extract("https://bit.ly/fakepage")
        assert f["is_url_shortener"] == 1

    def test_at_sign_detection(self):
        f = self.ext.extract("http://legit.com@evil.com/path")
        assert f["has_at_sign"] == 1

    def test_feature_vector_shape(self):
        v = self.ext.to_vector("https://example.com")
        assert v.shape == (1, 31), f"Expected (1, 31), got {v.shape}"


class TestPhishingDetector:
    def setup_method(self):
        self.detector = PhishingDetector()
        self.detector.train_or_load()

    def test_phishing_url_flagged(self):
        result = self.detector.predict("http://paypa1-secure-login.xyz/verify")
        assert result["phishing_probability"] > 0.5
        assert "top_indicators" in result

    def test_legit_url_passes(self):
        result = self.detector.predict("https://www.google.com")
        assert result["phishing_probability"] < 0.5

    def test_ip_url_flagged(self):
        result = self.detector.predict("http://192.168.1.1/banking")
        assert result["phishing_probability"] > 0.5

    def test_result_keys(self):
        result = self.detector.predict("https://example.com")
        assert "phishing_probability" in result
        assert "confidence" in result
        assert "features" in result
        assert "top_indicators" in result

    def test_probability_range(self):
        for url in ["https://google.com", "http://evil.tk/phish", "http://bit.ly/x"]:
            r = self.detector.predict(url)
            assert 0.0 <= r["phishing_probability"] <= 1.0


# ── Email Parser ──────────────────────────────────────────────────────────────

class TestEmailParser:
    def setup_method(self):
        self.parser = EmailURLParser()

    def test_extract_plain_urls(self):
        text = "Visit http://evil.xyz/login for more info. Also check https://google.com"
        urls = self.parser.extract_urls(text)
        assert len(urls) == 2
        assert any("evil.xyz" in u for u in urls)

    def test_urgency_detection(self):
        email = "URGENT: Your account has been suspended. Act now to verify your identity!"
        analysis = self.parser.analyze_email_structure(email)
        assert analysis["has_urgency_language"] is True

    def test_credential_detection(self):
        email = "Please enter your password and credit card number to continue."
        analysis = self.parser.analyze_email_structure(email)
        assert analysis["requests_credentials"] is True

    def test_clean_email(self):
        email = "Hi, just checking in. Hope you are well. See you at the meeting."
        analysis = self.parser.analyze_email_structure(email)
        assert analysis["has_urgency_language"] is False
        assert analysis["requests_credentials"] is False
        assert analysis["email_risk_label"] == "LOW"

    def test_no_urls_returns_empty(self):
        urls = self.parser.extract_urls("This email has no URLs at all.")
        assert urls == []


# ── Database ──────────────────────────────────────────────────────────────────

class TestDatabase:
    def setup_method(self):
        self.db = Database()
        self.db.DB_PATH = ":memory:"   # use in-memory SQLite for tests
        self.db.init_db()

    def test_save_and_retrieve(self):
        ml  = {"phishing_probability": 0.9, "confidence": 90.0, "top_indicators": ["test"]}
        vt  = {"malicious": 5, "total": 72, "flagged_engines": []}
        fin = {"verdict": "PHISHING", "risk_level": "HIGH",
               "confidence_score": 88.0, "mitre_technique": "T1566"}

        scan_id = self.db.save_scan("http://evil.xyz", ml, vt, fin)
        assert scan_id is not None

        scan = self.db.get_scan(scan_id)
        assert scan["final_verdict"] == "PHISHING"
        assert scan["url"] == "http://evil.xyz"

    def test_stats_structure(self):
        stats = self.db.get_stats()
        assert "total_scans" in stats
        assert "phishing_detected" in stats
        assert "threat_rate" in stats

    def test_history_empty(self):
        history = self.db.get_history()
        assert isinstance(history, list)
