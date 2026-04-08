#!/usr/bin/env bash
# PHALANX v3 launcher
# Usage:
#   ./run.sh                          # interactive REPL
#   ./run.sh --tui                    # terminal UI
#   ./run.sh --scan 192.168.1.1       # direct autonomous scan
#   ./run.sh --scan example.com --scan-type web
#   ./run.sh --no-agentic             # REPL without LangGraph engine

set -euo pipefail
cd "$(dirname "$0")" || exit 1

# ── Python version check ────────────────────────────────────────────────────
PYTHON="${PYTHON_BIN:-python3}"
PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10 ]]; then
    echo "ERROR: Python 3.10+ required (found ${PY_VERSION}). Please upgrade Python."
    exit 1
fi

# ── Optional system tool warnings ───────────────────────────────────────────
warn_missing() { echo "  [WARN] '$1' not found – $2"; }
command -v ollama       &>/dev/null || warn_missing "ollama"       "LLM unavailable – install from https://ollama.com"
command -v nmap         &>/dev/null || warn_missing "nmap"         "sudo apt install nmap"
command -v nikto        &>/dev/null || warn_missing "nikto"        "sudo apt install nikto"
command -v whois        &>/dev/null || warn_missing "whois"        "sudo apt install whois"
command -v gobuster     &>/dev/null || warn_missing "gobuster"     "sudo apt install gobuster"
command -v whatweb      &>/dev/null || warn_missing "whatweb"      "sudo apt install whatweb"
command -v subfinder    &>/dev/null || warn_missing "subfinder"    "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
command -v theHarvester &>/dev/null || warn_missing "theHarvester" "sudo apt install theharvester"
command -v searchsploit &>/dev/null || warn_missing "searchsploit" "sudo apt install exploitdb"
command -v ffuf         &>/dev/null || warn_missing "ffuf"         "sudo apt install ffuf"
command -v sqlmap       &>/dev/null || warn_missing "sqlmap"       "sudo apt install sqlmap"
command -v wpscan       &>/dev/null || warn_missing "wpscan"       "gem install wpscan"
command -v nc           &>/dev/null || warn_missing "nc"           "sudo apt install netcat-openbsd"
command -v openssl      &>/dev/null || warn_missing "openssl"      "sudo apt install openssl"
command -v dig          &>/dev/null || warn_missing "dig"          "sudo apt install dnsutils"

# ── Virtual environment ──────────────────────────────────────────────────────
USE_UV=false
command -v uv &>/dev/null && USE_UV=true

if [[ ! -d ".venv" ]]; then
    echo "🚀 Creating virtual environment…"
    if $USE_UV; then
        uv venv
    else
        "$PYTHON" -m venv .venv
    fi
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "📦 Installing dependencies…"
if $USE_UV; then
    uv pip install -r requirements.txt --quiet
else
    pip install -r requirements.txt --quiet
fi

echo "🌟 Starting PHALANX v3…"
exec python phalanx.py "$@"
