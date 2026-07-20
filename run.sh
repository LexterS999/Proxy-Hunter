#!/usr/bin/env bash

set -e

cd "$(dirname "$0")"

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
LOG_FILE="$LOG_DIR/run_$TIMESTAMP.log"

exec > >(tee -a "$LOG_FILE") 2>&1

echo "════════════════════════════════════════════════════════════════"
echo "  Proxy-Hunter Optimized Pipeline"
echo "  Started at: $(date)"
echo "════════════════════════════════════════════════════════════════"

PYTHON_CMD="python3"
if [ -f "venv/bin/python" ]; then
    PYTHON_CMD="venv/bin/python"
    echo "✅ Using virtual environment: venv"
else
    echo "ℹ️  Using system Python: $(command -v python3)"
fi

# Проверка зависимостей (убрали geoip2)
echo "➤ Checking required Python modules..."
$PYTHON_CMD -c "import requests, bs4" 2>/dev/null || {
    echo "⚠️  Some dependencies are missing. Installing..."
    $PYTHON_CMD -m pip install -r requirements.txt --quiet
}

# Запуск пайплайна
echo ""
echo "➤ [$(date +%H:%M:%S)] Running optimized pipeline..."
if $PYTHON_CMD src/pipeline_optimized.py; then
    echo "✓ [$(date +%H:%M:%S)] Pipeline completed successfully!"
else
    echo "✗ [$(date +%H:%M:%S)] Pipeline failed!"
    exit 1
fi

# Проверка выходных файлов
echo ""
if [ -f "configs/output_archive.txt" ] && [ -f "configs/output_simple.txt" ]; then
    ARCHIVE_SIZE=$(wc -c < "configs/output_archive.txt")
    SIMPLE_SIZE=$(wc -c < "configs/output_simple.txt")
    echo "✅ Output files created:"
    echo "   configs/output_archive.txt - $ARCHIVE_SIZE bytes"
    echo "   configs/output_simple.txt - $SIMPLE_SIZE bytes"
    echo ""
    echo "📄 First 5 lines of output_archive.txt:"
    head -n 5 "configs/output_archive.txt" | sed 's/^/   /'
else
    echo "❌ ERROR: Output files missing!"
    echo "   Check pipeline logs for details."
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ✅ Pipeline completed successfully!"
echo "  Finished at: $(date)"
echo "════════════════════════════════════════════════════════════════"

# Очистка старых логов
find "$LOG_DIR" -name "run_*.log" -mtime +7 -delete 2>/dev/null || true
