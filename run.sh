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

# Определяем команду Python
PYTHON_CMD="python3"
if [ -f "venv/bin/python" ]; then
    PYTHON_CMD="venv/bin/python"
    echo "✅ Using virtual environment: venv"
else
    echo "ℹ️  Using system Python: $(command -v python3)"
fi

# Проверяем наличие необходимых модулей
echo "➤ Checking required Python modules..."
$PYTHON_CMD -c "import requests, bs4, geoip2" 2>/dev/null || {
    echo "⚠️  Some dependencies are missing. Installing..."
    $PYTHON_CMD -m pip install -r requirements.txt --quiet
}

# Запуск основного пайплайна
echo ""
echo "➤ [$(date +%H:%M:%S)] Running optimized pipeline..."
if $PYTHON_CMD src/pipeline_optimized.py; then
    echo "✓ [$(date +%H:%M:%S)] Pipeline completed successfully!"
else
    echo "✗ [$(date +%H:%M:%S)] Pipeline failed!"
    exit 1
fi

# Проверка наличия выходного файла
echo ""
if [ -f "configs/output.txt" ]; then
    FILE_SIZE=$(wc -c < "configs/output.txt")
    LINE_COUNT=$(wc -l < "configs/output.txt")
    echo "✅ Output file created: configs/output.txt"
    echo "   Size: $FILE_SIZE bytes"
    echo "   Lines: $LINE_COUNT"
    
    # Показываем первые 5 строк для подтверждения
    echo ""
    echo "📄 First 5 lines of output:"
    head -n 5 "configs/output.txt" | sed 's/^/   /'
else
    echo "❌ ERROR: configs/output.txt was not created!"
    echo "   Check pipeline logs for details."
    exit 1
fi

# ================================================================
# 🆕 Вывод статистики качества (с защитой от повреждённого файла)
# ================================================================
echo ""
echo "📊 Quality Summary:"
$PYTHON_CMD -c "
import json
import sys
try:
    with open('configs/quality_history.json') as f:
        data = json.load(f)
    runs = data.get('runs', [])
    if runs:
        latest = runs[-1]
        print(f'  Total runs: {len(runs)}')
        print(f'  Latest run: {latest.get(\"timestamp\", \"?\")}')
        print(f'  Final configs: {latest.get(\"total_final\", 0)}')
        print(f'  Avg score: {latest.get(\"avg_score\", 0):.1f}')
        print(f'  P50 latency: {latest.get(\"p50_latency\", 0):.0f}ms')
        print(f'  P95 latency: {latest.get(\"p95_latency\", 0):.0f}ms')
        print(f'  P99 latency: {latest.get(\"p99_latency\", 0):.0f}ms')
    else:
        print('  No history data yet')
except (json.JSONDecodeError, FileNotFoundError):
    print('  ⚠️  History file is missing or corrupted. Run pipeline to generate new data.')
"
# ================================================================

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ✅ Pipeline completed successfully!"
echo "  Finished at: $(date)"
echo "  Output: configs/output.txt"
echo "════════════════════════════════════════════════════════════════"

# Очистка старых логов (старше 7 дней)
find "$LOG_DIR" -name "run_*.log" -mtime +7 -delete 2>/dev/null || true
