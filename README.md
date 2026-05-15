<div align="center">

# 🛡️ PhishGuard

### AI-Powered Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566-red?style=flat-square)](https://attack.mitre.org/techniques/T1566/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-394EFF?style=flat-square)](https://www.virustotal.com)

**Multi-layer phishing URL detection combining a trained ML classifier with VirusTotal's 70+ antivirus engine consensus — served through a real-time browser dashboard.**

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [API Reference](#-api-reference) · [MITRE ATT&CK](#-mitre-attck-mapping)

</div>

---

## 📸 Dashboard Preview

> **URL Scanner** — paste any link, get an instant AI verdict with a risk score ring, top indicators, and VirusTotal engine breakdown.

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡️ PhishGuard   [Scanner] [Email Scan] [History] [Analytics]  │
├─────────────────────────────────────────────────────────────────┤
│  Stats:  Total: 42  │  Phishing: 18  │  Suspicious: 7  │  Safe: 17  │
├──────────────────────────────┬──────────────────────────────────┤
│  🔍 URL Scanner              │  🧪 Quick Test Samples           │
│  ┌────────────────────────┐  │                                  │
│  │ http://paypa1-login.tk │  │  [🚨 paypa1-secure-login.xyz]   │
│  └────────────┬───────────┘  │  [🚨 192.168.1.1/banking]       │
│              [Scan]          │  [✅ google.com]                 │
│  ┌──────────────────────────┐│                                  │
│  │  🚨 PHISHING   HIGH RISK ││  MITRE ATT&CK Coverage:         │
│  │     ████████░░  87%      ││  T1566   Phishing                │
│  │  ML: 91.2%  VT: 14/72   ││  T1566.002 Spearphishing Link    │
│  └──────────────────────────┘│  T1204   User Execution          │
└──────────────────────────────┴──────────────────────────────────┘
```

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **ML Classifier** | RandomForest trained on 30+ lexical & structural URL features |
| 🔬 **VirusTotal Integration** | Free API v3 — cross-references 70+ antivirus engines |
| 📧 **Email Phishing Analyser** | Paste raw email → auto-extracts all URLs → scans each one |
| 📊 **Live Dashboard** | Real-time stats, scan history table, analytics charts |
| 🗄️ **Scan History** | SQLite persistence with filterable, exportable log |
| 📈 **Analytics** | Donut/line/bar charts with 14-day threat activity |
| 🏷️ **MITRE ATT&CK Tags** | Every detected threat tagged with ATT&CK technique IDs |
| 🐳 **Docker Ready** | One-command `docker compose up` deployment |
| 🆓 **100% Free & Local** | No paid services, no cloud, runs entirely on your machine |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│              Browser Dashboard                   │
│   URL Scanner │ Email Scanner │ Analytics        │
└──────────────────────┬──────────────────────────┘
                       │  REST API (HTTP/JSON)
┌──────────────────────▼──────────────────────────┐
│              FastAPI Backend                     │
│                                                  │
│  ┌─────────────────┐   ┌─────────────────────┐  │
│  │   ML Engine     │   │  VirusTotal Client  │  │
│  │  RandomForest   │   │    API v3 (async)   │  │
│  │  300 estimators │   │  70+ AV engines     │  │
│  │  30+ features   │   │  500 scans/day free │  │
│  └────────┬────────┘   └──────────┬──────────┘  │
│           │                       │              │
│  ┌────────▼───────────────────────▼──────────┐  │
│  │           Score Fusion Engine              │  │
│  │  score = 0.6 × ML_prob + 0.4 × VT_ratio  │  │
│  │  ≥0.65 → PHISHING  ≥0.35 → SUSPICIOUS    │  │
│  └───────────────────┬────────────────────── ┘  │
│                       │                          │
│  ┌────────────────────▼────────────────────── ┐  │
│  │      SQLite Database (scan history)        │  │
│  └────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

### Detection Pipeline

```
URL Input
   │
   ├─► Feature Extraction (30+ features)
   │       url_length, domain_entropy, suspicious_keywords,
   │       has_ip, subdomains, suspicious_tld, https, shortener …
   │
   ├─► RandomForest Classifier → ML probability (0.0–1.0)
   │
   ├─► VirusTotal API v3 → malicious/total engine ratio
   │
   └─► Weighted Fusion → Final Score → Verdict + MITRE Tag
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+ 
- pip
- (Optional) Docker + Docker Compose
- (Optional) Free [VirusTotal API key](https://www.virustotal.com/gui/join-us)

### Option A — Shell Script (Recommended)

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard

# Run (ML-only mode, no API key needed)
chmod +x start.sh
./start.sh

# Run with VirusTotal (70-engine cross-check)
VT_API_KEY=your_api_key ./start.sh
```

Open **http://localhost:8000** → dashboard loads instantly.

### Option B — Manual Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r ../requirements.txt

export VT_API_KEY=your_key       # optional
python app.py
```

### Option C — Docker

```bash
# With VirusTotal
VT_API_KEY=your_key docker compose up --build

# Without VirusTotal
docker compose up --build
```

---

## 🧠 ML Model — Feature Engineering

The classifier extracts **30+ features** from every URL before scoring:

| Category | Features |
|---|---|
| **Length metrics** | URL length, domain length, path length, query length |
| **Character counts** | dots, hyphens, @, %, =, ?, & per URL |
| **Binary flags** | has IP address, has HTTPS, has port, has @ sign, URL shortener |
| **Domain structure** | subdomain count, digit in apex, hyphen in apex |
| **Keyword signals** | 25 phishing keywords (login, verify, secure, suspend …) |
| **TLD analysis** | Suspicious TLDs: .xyz .tk .ml .ga .cf .gq .top … |
| **Entropy** | Shannon entropy of domain (random names = high entropy) |
| **Ratios** | digit/letter ratio, special character ratio |

**Algorithm:** `RandomForestClassifier(n_estimators=300, max_depth=12, class_weight='balanced')`

### Improving Accuracy with Real Data

The model ships with a synthetic corpus. Swap in real data for production-grade accuracy:

```bash
# Download PhishTank dataset (100,000+ verified phishing URLs — free)
wget https://data.phishtank.com/data/online-valid.csv

# Or use the Kaggle phishing URL dataset
# https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
```

Then update `ml_detector.py` to load from the CSV instead of the synthetic corpus.

---

## 📧 Email Phishing Analyser

Paste any raw email (headers + body + HTML). PhishGuard will:

1. **Extract all URLs** using regex patterns (handles plain text, HTML anchors, obfuscated links)
2. **Structural analysis** — urgency language, credential-harvesting phrases, spoofed anchor text
3. **Scan each URL** through the full ML + VT pipeline (up to 20 URLs per email)
4. **Risk summary** — per-URL verdicts sorted highest risk first

**Detects classic phishing signals:**
- `urgent`, `act now`, `account suspended`, `final notice`
- Requests for passwords, SSN, credit card, billing info
- Anchor text showing `paypal.com` but linking to `paypa1-evil.xyz`

---

## 📡 API Reference

All endpoints return JSON. Base URL: `http://localhost:8000/api`

### `GET /health`
Backend and model status.
```json
{
  "status": "ok",
  "model_trained": true,
  "vt_enabled": true,
  "timestamp": "2026-04-09T10:30:00"
}
```

### `POST /scan/url`
Scan a single URL.
```bash
curl -X POST http://localhost:8000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypa1-secure-login.xyz/verify"}'
```
```json
{
  "url": "http://paypa1-secure-login.xyz/verify",
  "scan_id": 42,
  "ml_analysis": {
    "phishing_probability": 0.934,
    "confidence": 93.4,
    "top_indicators": [
      "Suspicious keywords in URL",
      "Suspicious top-level domain",
      "No HTTPS / plain HTTP"
    ]
  },
  "vt_analysis": {
    "malicious": 14,
    "suspicious": 3,
    "harmless": 2,
    "total": 72,
    "vt_link": "https://www.virustotal.com/gui/url/..."
  },
  "final_verdict": {
    "verdict": "PHISHING",
    "risk_level": "HIGH",
    "confidence_score": 89.2,
    "mitre_technique": "T1566 - Phishing"
  }
}
```

### `POST /scan/email`
```bash
curl -X POST http://localhost:8000/api/scan/email \
  -H "Content-Type: application/json" \
  -d '{"email_content": "Click here: http://evil.tk/login"}'
```

### `GET /history?limit=100&offset=0`
Paginated scan history, newest first.

### `GET /stats`
Aggregate stats + 14-day activity + top 10 threats.

### `DELETE /history/clear`
Wipe all scan history.

---

## 🗺️ MITRE ATT&CK Mapping

| Technique ID | Name | How PhishGuard Detects It |
|---|---|---|
| **T1566** | Phishing | Core detection — all high-score URLs |
| **T1566.002** | Spearphishing Link | URL-in-email detection via email scanner |
| **T1598** | Gather Victim Info via Service | Credential-harvesting keyword detection |
| **T1204** | User Execution | Urgency-language signals in email body |

---

## 📂 Project Structure

```
phishguard/
│
├── backend/
│   ├── app.py                  # FastAPI app — all routes & scoring logic
│   ├── ml_detector.py          # URL feature extraction + RandomForest model
│   ├── virustotal_service.py   # Async VirusTotal API v3 client
│   ├── email_parser.py         # URL extractor + email structure analyser
│   ├── database.py             # SQLite persistence layer
│   └── static/
│       └── index.html          # Single-page dashboard (vanilla JS + Chart.js)
│
├── requirements.txt            # 7 Python dependencies, all free
├── start.sh                    # One-command startup script
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 🔧 Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **API** | FastAPI (Python) | Async, auto-docs at `/docs`, production-grade |
| **ML** | scikit-learn RandomForest | Interpretable, no GPU needed, ships fast |
| **Threat Intel** | VirusTotal API v3 | 70+ engines, free tier sufficient |
| **Database** | SQLite (stdlib) | Zero setup, portable, no server needed |
| **Frontend** | Vanilla JS + Chart.js | No build step, loads instantly |
| **Container** | Docker + Compose | Reproducible, one-command deploy |

---

## 🔮 Roadmap

- [ ] Load real PhishTank / Kaggle dataset for higher accuracy
- [ ] WHOIS domain age enrichment (`python-whois`)
- [ ] DNS record analysis (short TTL = suspicious)
- [ ] Transformer-based URL classifier (BERT fine-tune)
- [ ] Browser extension for real-time protection
- [ ] MISP / OpenCTI threat intelligence feed export
- [ ] Bulk URL scanner (CSV upload)
- [ ] Slack / Discord webhook alerts

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first.

```bash
# Fork → Clone → Branch
git checkout -b feature/your-feature

# Make changes, then
git commit -m "feat: describe your change"
git push origin feature/your-feature
# Open a Pull Request
```

---

## 📄 License

[MIT](LICENSE) — free to use, modify, and redistribute.

---

<div align="center">

**Built with ❤️ for the cybersecurity community**

If this helped your learning or portfolio, please ⭐ star the repo!

</div>
