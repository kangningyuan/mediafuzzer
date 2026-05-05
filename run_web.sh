#!/bin/bash
# MediaFuzzer Webapp Startup Script
# Usage: bash run_web.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

cd "$PROJECT_ROOT"

# Activate project virtual environment
VENV_DIR="$PROJECT_ROOT/.venv"
if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
else
    echo "Error: Virtual environment not found at $VENV_DIR"
    echo "Please run: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Load .env if exists (set API keys etc.)
if [ -f .env ]; then
    set -a
    source <(grep -v '^#' .env | grep -v '^$')
    set +a
fi

# Ensure project root is on PYTHONPATH
export PYTHONPATH="$PROJECT_ROOT:${PYTHONPATH:-}"

# Ensure required directories exist
mkdir -p output apk

echo "============================================"
echo "  MediaFuzzer Webapp"
echo "============================================"
echo ""
echo "  URL: http://localhost:5000"
echo "  APK directory: $PROJECT_ROOT/apk/"
echo "  Output directory: $PROJECT_ROOT/output/"
echo ""
echo "  Press Ctrl+C to stop"
echo "============================================"
echo ""

# Graceful shutdown
PID=""
cleanup() {
    echo ""
    if [ -n "$PID" ]; then
        echo "Shutting down MediaFuzzer Webapp..."
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        echo "Stopped."
    fi
    exit 0
}

trap cleanup SIGINT SIGTERM

python -m webapp.app &
PID=$!
wait $PID
