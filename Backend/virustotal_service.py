"""
VirusTotal API v3 — async client
Free tier: 4 req/min, 500 req/day
"""

import asyncio
import base64
from typing import Optional, Dict

import httpx


class VirusTotalService:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._headers = {
            "x-apikey": api_key,
            "Accept":   "application/json",
        }

    @staticmethod
    def _url_id(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async def scan_url(self, url: str) -> Optional[Dict]:
        if not self.api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # ── Step 1: Try cached report first (saves quota) ─────────────
                uid     = self._url_id(url)
                cached  = await client.get(
                    f"{self.BASE_URL}/urls/{uid}",
                    headers=self._headers,
                )
                if cached.status_code == 200:
                    return self._parse_url_report(cached.json()["data"], url)

                # ── Step 2: Submit for fresh scan ─────────────────────────────
                submit = await client.post(
                    f"{self.BASE_URL}/urls",
                    headers=self._headers,
                    data={"url": url},
                )
                if submit.status_code != 200:
                    return {"error": f"VT submit failed ({submit.status_code})",
                            "malicious": 0, "total": 0}

                analysis_id = submit.json()["data"]["id"]

                # ── Step 3: Poll for completion (3 attempts, 3 s apart) ───────
                for _ in range(3):
                    await asyncio.sleep(3)
                    poll = await client.get(
                        f"{self.BASE_URL}/analyses/{analysis_id}",
                        headers=self._headers,
                    )
                    if poll.status_code == 200:
                        data = poll.json()["data"]
                        if data["attributes"]["status"] == "completed":
                            return self._parse_analysis(data, url)

                return {"error": "VT analysis timeout", "malicious": 0, "total": 0}

        except httpx.TimeoutException:
            return {"error": "VirusTotal request timed out", "malicious": 0, "total": 0}
        except Exception as exc:
            return {"error": str(exc), "malicious": 0, "total": 0}

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_url_report(self, data: dict, url: str) -> dict:
        attrs   = data["attributes"]
        stats   = attrs["last_analysis_stats"]
        results = attrs.get("last_analysis_results", {})
        return self._build_result(stats, results, url)

    def _parse_analysis(self, data: dict, url: str) -> dict:
        attrs   = data["attributes"]
        stats   = attrs.get("stats", {})
        results = attrs.get("results", {})
        return self._build_result(stats, results, url)

    def _build_result(self, stats: dict, results: dict, url: str) -> dict:
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless",   0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        flagged = [
            {"engine": eng, "result": info.get("result", "flagged"), "category": info.get("category")}
            for eng, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        ]

        return {
            "malicious":      malicious,
            "suspicious":     suspicious,
            "harmless":       harmless,
            "undetected":     undetected,
            "total":          total,
            "flagged_engines": flagged[:15],
            "vt_link":        f"https://www.virustotal.com/gui/url/{self._url_id(url)}",
        }
