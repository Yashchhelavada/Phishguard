#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  PhishGuard — quick start script
#  Usage:
#    ./start.sh                        # no VirusTotal
#    VT_API_KEY=your_key ./start.sh    # with VirusTotal
# ─────────────────────────────────────────────────────────────────

set -e

echo "🛡️  PhishGuard — AI Phishing Detector"
echo "────────────────────────────────────────"

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌ Python 3 not found. Install from https://python.org"; exit 1
fi

cd "$(dirname "$0")/backend"

# Virtual environment
if [ ! -d ".venv" ]; then
  echo "📦 Creating virtual environment…"
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "📦 Installing dependencies…"
pip install -q -r ../requirements.txt

if [ -n "$VT_API_KEY" ]; then
  echo "✅ VirusTotal API key detected"
  export VT_API_KEY
else
  echo "ℹ️  No VT_API_KEY set — ML-only mode (add key for 70-engine scans)"
fi

echo ""
echo "🚀 Starting server at http://localhost:8000"
echo "   Press Ctrl+C to stop"
echo ""

python app.py
