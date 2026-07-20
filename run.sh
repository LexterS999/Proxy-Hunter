#!/bin/bash

# Proxy-Hunter - Скрипт запуска
# Запускает полный цикл: сбор -> парсинг -> скоринг -> проверка -> дедупликация -> архив

set -e

cd "$(dirname "$0")"

# Активируем виртуальное окружение
if [ -d "venv" ]; then
    source venv/bin/activate 2>/dev/null || . venv/Scripts/activate
fi

# Определяем Python
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo "Ошибка: Python не найден"
    exit 1
fi

# [CHANGE] проверяем только реально используемые зависимости (geoip2 удалён из проекта)
$PYTHON_CMD -c "import aiohttp, bs4, xxhash, msgpack, tqdm" 2>/dev/null || {
    echo "Ошибка: зависимости не установлены. Запустите install.sh"
    exit 1
}

echo "🚀 Запуск Proxy-Hunter..."
echo "=========================="

# Запуск оптимизированного пайплайна
$PYTHON_CMD src/pipeline_optimized.py

# [CHANGE] проверяем реальные выходные файлы (ранее проверялся несуществующий output.txt)
if [ -f "configs/output_archive.txt" ] || [ -f "configs/output_simple.txt" ]; then
    echo ""
    echo "✅ Готово! Результаты:"
    [ -f "configs/output_archive.txt" ] && echo "   - configs/output_archive.txt"
    [ -f "configs/output_simple.txt" ] && echo "   - configs/output_simple.txt"
    [ -f "configs/xray_balanced.json" ] && echo "   - configs/xray_balanced.json"
else
    echo "⚠️ Пайплайн завершён, но выходные файлы не созданы (возможно, нет новых конфигов)"
fi
