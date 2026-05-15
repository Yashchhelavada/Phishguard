"""
Phishing Detector API — FastAPI Backend
Combines ML model + VirusTotal API for multi-layer phishing detection
"""

import os
import asyncio
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ml_detector import PhishingDetector
from virustotal_service import VirusTotalService
from email_parser import EmailURLParser
from database import Database

# ── Startup / Shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    ml_detector.train_or_load()
    print("✅ Phishing Detector API is ready")
    yield

app = FastAPI(title="Phishing Detector", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Services ──────────────────────────────────────────────────────────────────

VT_API_KEY = os.getenv("VT_API_KEY", "")

db           = Database()
ml_detector  = PhishingDetector()
vt_service   = VirusTotalService(api_key=VT_API_KEY)
email_parser = EmailURLParser()

# ── Request / Response Models ──────────────────────────────────────────────────

class URLScanRequest(BaseModel):
    url: str

class EmailScanRequest(BaseModel):
    email_content: str

# ── Helper ────────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url
    return url

def calculate_final_verdict(ml_result: dict, vt_result: Optional[dict]) -> dict:
    ml_score = ml_result["phishing_probability"]

    if vt_result and vt_result.get("total", 0) > 0:
        vt_ratio = vt_result["malicious"] / vt_result["total"]
        # Weight: 60% ML + 40% VirusTotal
        final_score = (ml_score * 0.6) + (vt_ratio * 0.4)
    else:
        final_score = ml_score

    if final_score >= 0.65:
        verdict, risk_level, color = "PHISHING",   "HIGH",   "#ef4444"
    elif final_score >= 0.35:
        verdict, risk_level, color = "SUSPICIOUS", "MEDIUM", "#f59e0b"
    else:
        verdict, risk_level, color = "SAFE",       "LOW",    "#22c55e"

    return {
        "verdict":          verdict,
        "risk_level":       risk_level,
        "color":            color,
        "confidence_score": round(final_score * 100, 2),
        "mitre_technique":  "T1566 - Phishing" if verdict != "SAFE" else None,
    }

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model_trained": ml_detector.is_trained,
        "vt_enabled": bool(VT_API_KEY),
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.post("/api/scan/url")
async def scan_url(request: URLScanRequest):
    url = normalize_url(request.url)

    # 1. ML analysis (instant, local)
    ml_result = ml_detector.predict(url)

    # 2. VirusTotal (network call, if key provided)
    vt_result = None
    if VT_API_KEY:
        vt_result = await vt_service.scan_url(url)

    # 3. Combine into final verdict
    final = calculate_final_verdict(ml_result, vt_result)

    # 4. Persist
    scan_id = db.save_scan(url, ml_result, vt_result, final)

    return {
        "url":          url,
        "scan_id":      scan_id,
        "ml_analysis":  ml_result,
        "vt_analysis":  vt_result,
        "final_verdict": final,
        "timestamp":    datetime.utcnow().isoformat(),
    }

@app.post("/api/scan/email")
async def scan_email(request: EmailScanRequest):
    # Structural email analysis
    email_analysis = email_parser.analyze_email_structure(request.email_content)
    urls = email_parser.extract_urls(request.email_content)

    if not urls:
        return {
            "urls_found":   0,
            "results":      [],
            "email_analysis": email_analysis,
            "message":      "No URLs found in email content",
        }

    results = []
    for url in urls[:20]:   # cap at 20 URLs per email
        ml_result = ml_detector.predict(url)
        vt_result = None
        if VT_API_KEY:
            vt_result = await vt_service.scan_url(url)
            await asyncio.sleep(0.5)   # respect VT rate limit

        final   = calculate_final_verdict(ml_result, vt_result)
        scan_id = db.save_scan(url, ml_result, vt_result, final)

        results.append({
            "url":           url,
            "scan_id":       scan_id,
            "ml_analysis":   ml_result,
            "vt_analysis":   vt_result,
            "final_verdict": final,
        })

    # Sort: highest risk first
    results.sort(key=lambda r: r["final_verdict"]["confidence_score"], reverse=True)

    return {
        "urls_found":     len(urls),
        "urls_scanned":   len(results),
        "results":        results,
        "email_analysis": email_analysis,
        "timestamp":      datetime.utcnow().isoformat(),
    }

@app.get("/api/history")
async def get_history(limit: int = 100, offset: int = 0):
    return db.get_history(limit, offset)

@app.get("/api/stats")
async def get_stats():
    return db.get_stats()

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: int):
    result = db.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result

@app.delete("/api/history/clear")
async def clear_history():
    db.clear_history()
    return {"message": "History cleared"}

# ── Serve frontend ─────────────────────────────────────────────────────────────

frontend_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(os.path.join(frontend_path, "index.html"))

# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Phishing Detector on http://localhost:8000")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
