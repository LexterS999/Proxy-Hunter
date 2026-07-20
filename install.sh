#!/bin/bash

# Proxy-Hunter - Скрипт установки
# Автоматически устанавливает все зависимости и настраивает окружение

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Proxy-Hunter - Установка${NC}"
echo "=================================="

# Определяем ОС
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Cygwin;;
    MINGW*)     MACHINE=MinGw;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo -e "${YELLOW}📋 Система: ${MACHINE}${NC}"

# [CHANGE] корректный URL репозитория (ранее был чужой YawStar/Proxy-Hunter)
REPO_URL="https://github.com/LexterS999/Proxy-Hunter.git"
INSTALL_DIR="$HOME/proxy-hunter"

# Проверяем, установлен ли git
if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ Git не установлен. Установите git и повторите попытку.${NC}"
    exit 1
fi

# Клонируем репозиторий (если ещё не склонирован)
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}📥 Клонирование репозитория...${NC}"
    git clone "$REPO_URL" "$INSTALL_DIR"
else
    echo -e "${YELLOW}📥 Обновление репозитория...${NC}"
    cd "$INSTALL_DIR"
    git pull
fi

cd "$INSTALL_DIR"

# Устанавливаем Python зависимости
echo -e "${YELLOW}📦 Установка Python зависимостей...${NC}"

# Проверяем Python
if command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
elif command -v python &> /dev/null; then
    PYTHON_CMD=python
else
    echo -e "${RED}❌ Python не найден. Установите Python 3.8+.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python: $PYTHON_CMD${NC}"

# Создаём виртуальное окружение
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}🔧 Создание виртуального окружения...${NC}"
    $PYTHON_CMD -m venv venv
fi

# Активируем и устанавливаем зависимости
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate

echo -e "${YELLOW}📦 Установка зависимостей из requirements.txt...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}✅ Зависимости установлены${NC}"

# Создаём необходимые директории
echo -e "${YELLOW}📁 Создание директорий...${NC}"
mkdir -p configs
mkdir -p configs/bloom_shards
mkdir -p logs

# Создаём скрипт запуска
# [CHANGE] синхронизирован с реальным пайплайном (pipeline_optimized.py),
# удалены вызовы несуществующих скриптов (enrich_configs.py, rename_configs.py,
# config_to_singbox.py, security_filter.py, generate_charts.py)
echo -e "${YELLOW}📝 Создание скрипта запуска...${NC}"
cat > run.sh << 'EOF'
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

# [CHANGE] проверяем только реально используемые зависимости (geoip2 удалён)
$PYTHON_CMD -c "import aiohttp, bs4, xxhash, msgpack, tqdm" 2>/dev/null || {
    echo "Ошибка: зависимости не установлены. Запустите install.sh"
    exit 1
}

echo "🚀 Запуск Proxy-Hunter..."
echo "=========================="

# [CHANGE] запуск реального пайплайна
$PYTHON_CMD src/pipeline_optimized.py

# [CHANGE] проверяем реальные выходные файлы пайплайна
if [ -f "configs/output_archive.txt" ] || [ -f "configs/output_simple.txt" ]; then
    echo ""
    echo "✅ Готово! Результаты:"
    [ -f "configs/output_archive.txt" ] && echo "   - configs/output_archive.txt"
    [ -f "configs/output_simple.txt" ] && echo "   - configs/output_simple.txt"
    [ -f "configs/xray_balanced.json" ] && echo "   - configs/xray_balanced.json"
else
    echo "⚠️ Пайплайн завершён, но выходные файлы не созданы (возможно, нет новых конфигов)"
fi
EOF

chmod +x run.sh

echo -e "${GREEN}✅ Установка завершена!${NC}"
echo ""
echo -e "${BLUE}📖 Использование:${NC}"
echo "   cd $INSTALL_DIR"
echo "   ./run.sh"
echo ""
echo -e "${BLUE}🔧 Настройка:${NC}"
echo "   Отредактируйте src/user_settings.py для изменения параметров"
echo ""
echo -e "${GREEN}🎉 Готово к работе!${NC}"
