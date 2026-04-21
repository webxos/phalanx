#!/bin/bash
set -e

echo "📦 Setting up Python virtual environment..."
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "✅ Virtual environment created."
fi

source "$VENV_DIR/bin/activate"

echo "📦 Installing dependencies (inside venv)..."
pip install --upgrade pip
pip install -r requirements.txt

# Install Playwright browsers if needed (ignore errors)
if python -c "import playwright" &> /dev/null; then
    echo "📦 Installing Playwright browsers..."
    playwright install chromium || echo "⚠ Playwright browser installation failed, JS rendering may not work."
fi

echo "🌟 Starting PHALANX v3.2..."

# Check if Docker Compose is available and start sandbox
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    echo "🐳 Docker Compose detected – starting sandbox containers..."
    docker compose up -d
    # Wait for Metasploitable 2 container to be healthy (or just give it time)
    echo "⏳ Waiting for Metasploitable 2 container to be ready..."
    sleep 5
    # Optionally check container status
    if docker ps | grep -q phalanx-metasploitable2; then
        echo "✅ Metasploitable 2 container is running."
    else
        echo "⚠ Metasploitable 2 container did not start properly. Demo may fail."
    fi
else
    echo "⚠ Docker or Docker Compose not found – sandbox disabled."
fi

# Run locally (inside venv)
python phalanx.py "$@"

deactivate
echo "PHALANX session ended. Logs available at: ~/.phalanx/logs/phalanx.log"
