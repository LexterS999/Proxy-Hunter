#!/usr/bin/env bash

set -e

CYAN='\033[0;36m'
BRIGHT_CYAN='\033[1;36m'
GREEN='\033[0;32m'
BRIGHT_GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[1;35m'
WHITE='\033[1;37m'
NC='\033[0m'

echo ""
echo -e "${MAGENTA}═════════════════════════════════════════════${NC}"
echo -e "${BRIGHT_CYAN} Multi Wizard - Ultimate Setup${NC}"
echo -e "${MAGENTA}═════════════════════════════════════════════${NC}"
echo -e "${WHITE} Designed by: ${BRIGHT_GREEN}👽 Anonymous${NC}"
echo -e "${MAGENTA}═════════════════════════════════════════════${NC}"
echo ""

# Исправленный URL репозитория (ваш актуальный)
REPO_URL="https://github.com/your-username/Proxy-Hunter.git"   # <-- ИЗМЕНИТЕ НА ВАШ РЕПОЗИТОРИЙ
INSTALL_DIR="$HOME/multi-proxy-config-fetcher"
VENV_DIR="$INSTALL_DIR/venv"

# ... (остальная часть install.sh без изменений до create_runner_script) ...

create_runner_script() {
    print_status "Creating runner script..."
    local termux_lock_start=""
    local termux_lock_end=""
    if [ "$PLATFORM" = "termux" ]; then
        termux_lock_start="termux-wake-lock 2>/dev/null || true"
        termux_lock_end="termux-wake-unlock 2>/dev/null || true"
    fi

    cat > "$INSTALL_DIR/run.sh" << EOF
#!/usr/bin/env bash

set -e

cd "$INSTALL_DIR"

LOG_DIR="$INSTALL_DIR/logs"
mkdir -p "\$LOG_DIR"
TIMESTAMP=\$(date +%Y-%m-%d_%H-%M-%S)
LOG_FILE="\$LOG_DIR/run_\$TIMESTAMP.log"

exec > >(tee -a "\$LOG_FILE")
exec 2>&1

echo "════════════════════════════════════════════════════════════════"
echo "  Multi Proxy Config Fetcher - Pipeline Execution"
echo "  Started at: \$(date)"
echo "════════════════════════════════════════════════════════════════"

$termux_lock_start

run_step() {
    local step_name="\$1"
    local step_cmd="\$2"
    echo "➤ [\$(date +%H:%M:%S)] Running: \$step_name"
    if eval "\$step_cmd"; then
        echo "✓ [\$(date +%H:%M:%S)] Completed: \$step_name"
        echo ""
        return 0
    else
        echo "✗ [\$(date +%H:%M:%S)] Failed: \$step_name"
        echo ""
        return 1
    fi
}

PYTHON_CMD="$PYTHON_EXEC"

# Запуск оптимизированного пайплайна
run_step "Optimized Pipeline" "\$PYTHON_CMD src/pipeline_optimized.py"

# Проверка выходных файлов
if [ -f "configs/output_archive.txt" ] && [ -f "configs/output_simple.txt" ]; then
    echo "✅ Output files created successfully."
else
    echo "❌ ERROR: Some output files missing!"
    exit 1
fi

echo "════════════════════════════════════════════════════════════════"
echo "  🎉 Pipeline completed successfully!"
echo "  Finished at: \$(date)"
echo "════════════════════════════════════════════════════════════════"

$termux_lock_end

find "\$LOG_DIR" -name "run_*.log" -mtime +7 -delete 2>/dev/null || true

EOF

    chmod +x "$INSTALL_DIR/run.sh" 2>/dev/null || true
    print_success "Runner script created!"
}

# ... (остальная часть install.sh без изменений) ...
