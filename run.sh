#!/usr/bin/env bash

# Запрещаем падать на ошибках в пайплайне — логируем всё
# set -e оставляем, но tee с unbuffered вывод покажет весь процесс
set -o pipefail
set -x  # <-- печатает каждую команду для трассировки

cd "$(dirname "$0")"

LOG_DIR="logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
LOG_FILE="$LOG_DIR/run_$TIMESTAMP.log"
DEBUG_FILE="pipeline_debug.log"

# Фикс: гарантируем полное логирование (раньше свёрнуто в INFO)
export LOG_LEVEL=DEBUG
export PYTHONUNBUFFERED=1

exec > >(tee -a "$LOG_FILE" "$DEBUG_FILE") 2>&1

echo "════════════════════════════════════════════════════════════════"
echo "  Proxy-Hunter Optimized Pipeline"
echo "  Started at: $(date)"
echo "  LOG_LEVEL=$LOG_LEVEL  PYTHONUNBUFFERED=$PYTHONUNBUFFERED"
echo "════════════════════════════════════════════════════════════════"

PYTHON_CMD="python3"
if [ -f "venv/bin/python" ]; then
    PYTHON_CMD="venv/bin/python"
    echo "✅ Using virtual environment: venv"
else
    echo "ℹ️  Using system Python: $(command -v python3)"
fi

# Проверка зависимостей
echo "➤ Checking required Python modules..."
$PYTHON_CMD -c "import aiohttp, bs4, xxhash, aiofiles, tqdm" 2>/dev/null || {
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
if [ -f "configs/output_archive.txt" ]; then
    FILE_SIZE=$(wc -c < "configs/output_archive.txt")
    LINE_COUNT=$(wc -l < "configs/output_archive.txt")
    echo "✅ Output file created: configs/output_archive.txt"
    echo "   Size: $FILE_SIZE bytes"
    echo "   Lines: $LINE_COUNT"
    echo ""
    echo "📄 First 5 lines of output:"
    head -n 5 "configs/output_archive.txt" | sed 's/^/   /'
else
    echo "❌ ERROR: configs/output_archive.txt was not created!"
    echo "   Check pipeline logs for details."
    exit 1
fi

if [ -f "configs/output_simple.txt" ]; then
    SIMPLE_SIZE=$(wc -c < "configs/output_simple.txt")
    SIMPLE_LINES=$(wc -l < "configs/output_simple.txt")
    echo ""
    echo "✅ Simple output: configs/output_simple.txt ($SIMPLE_LINES lines, $SIMPLE_SIZE bytes)"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ✅ Pipeline completed successfully!"
echo "  Finished at: $(date)"
echo "════════════════════════════════════════════════════════════════"

# Очистка старых логов
find "$LOG_DIR" -name "run_*.log" -mtime +7 -delete 2>/dev/null || true
