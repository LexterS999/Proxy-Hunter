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

REPO_URL="https://github.com/your-username/Proxy-Hunter.git"   # <-- ИЗМЕНИТЕ НА ВАШ РЕПОЗИТОРИЙ
INSTALL_DIR="$HOME/multi-proxy-config-fetcher"
VENV_DIR="$INSTALL_DIR/venv"

# Если передан флаг --install-xray-only, устанавливаем только Xray и выходим
if [[ "$1" == "--install-xray-only" ]]; then
    echo "Installing Xray-core only..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  XRAY_FILE="Xray-linux-64.zip" ;;
        aarch64) XRAY_FILE="Xray-linux-arm64-v8a.zip" ;;
        armv7l)  XRAY_FILE="Xray-linux-arm32-v7a.zip" ;;
        *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K(.*?)(?=")')
    if [ -z "$XRAY_VERSION" ]; then
        echo "Failed to get latest Xray version"
        exit 1
    fi
    echo "Downloading Xray $XRAY_VERSION ($XRAY_FILE)..."
    wget -q "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_FILE}" -O /tmp/xray.zip
    echo "Extracting Xray..."
    mkdir -p /tmp/xray
    unzip -q -o /tmp/xray.zip -d /tmp/xray
    chmod +x /tmp/xray/xray
    sudo mv /tmp/xray/xray /usr/local/bin/
    rm -rf /tmp/xray /tmp/xray.zip
    xray version 2>&1 | head -1
    exit 0
fi

detect_platform() {
    if command -v termux-info >/dev/null 2>&1; then
        echo "termux"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OS" == "Windows_NT" ]] || uname -s | grep -q "MINGW\|MSYS\|CYGWIN"; then
        echo "windows"
    else
        echo "unknown"
    fi
}

print_status() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

check_python_version() {
    if command -v python3 &>/dev/null; then
        version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [[ "$version" < "3.8" ]]; then
            print_error "Python 3.8+ required, found $version"
            exit 1
        fi
    else
        print_error "Python3 not found"
        exit 1
    fi
}

fix_dpkg_issues() {
    print_status "Checking and fixing package manager issues..."
    if [ "$PLATFORM" = "termux" ]; then
        dpkg --configure -a 2>/dev/null || true
        pkg clean 2>/dev/null || true
        if [ -f "$PREFIX/etc/tls/openssl.cnf.dpkg-old" ]; then
            rm -f "$PREFIX/etc/tls/openssl.cnf.dpkg-old"
        fi
        DEBIAN_FRONTEND=noninteractive pkg update -y 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive pkg upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null || true
        print_success "Package manager issues resolved!"
    fi
}

setup_repository() {
    print_status "Setting up repository..."
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Directory exists. Pulling latest changes..."
        cd "$INSTALL_DIR"
        git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
        git fetch --all 2>/dev/null || true
        git reset --hard origin/main 2>/dev/null || true
        git pull origin main 2>/dev/null || true
    else
        print_status "Cloning repository..."
        git clone "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || {
            print_error "Failed to clone repository!"
            exit 1
        }
        cd "$INSTALL_DIR"
    fi
    print_success "Repository setup complete!"
}

create_directory_structure() {
    print_status "Creating directory structure..."
    mkdir -p "$INSTALL_DIR/configs" 2>/dev/null || true
    mkdir -p "$INSTALL_DIR/assets" 2>/dev/null || true
    mkdir -p "$INSTALL_DIR/logs" 2>/dev/null || true
    mkdir -p "$INSTALL_DIR/src" 2>/dev/null || true
    print_success "Directory structure created!"
}

setup_python_environment() {
    print_status "Setting up Python environment..."
    if [ "$PLATFORM" = "termux" ]; then
        if ! check_command python; then
            DEBIAN_FRONTEND=noninteractive pkg install -y python 2>/dev/null || true
        fi
        PYTHON_SYS="python"
        PIP_SYS="pip"
    else
        if check_command python3; then
            PYTHON_SYS="python3"
            PIP_SYS="pip3"
        elif check_command python; then
            PYTHON_SYS="python"
            PIP_SYS="pip"
        else
            print_error "Python not found!"
            exit 1
        fi
    fi
    print_status "Creating virtual environment..."
    $PYTHON_SYS -m venv "$VENV_DIR" 2>/dev/null || {
        print_warning "venv module not available, installing globally..."
        VENV_DIR=""
    }
    if [ -n "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/python" ]; then
        PYTHON_EXEC="$VENV_DIR/bin/python"
        PIP_EXEC="$VENV_DIR/bin/pip"
        print_success "Virtual environment ready!"
    else
        PYTHON_EXEC="$PYTHON_SYS"
        PIP_EXEC="$PIP_SYS"
    fi
    print_status "Upgrading pip..."
    $PIP_EXEC install --upgrade pip setuptools wheel 2>/dev/null || true
    print_status "Installing Python dependencies..."
    $PIP_EXEC install -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || {
        print_warning "Some dependencies failed to install, retrying..."
        $PIP_EXEC install --no-cache-dir -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || true
    }
    print_success "Python environment ready!"
}

install_dependencies_termux() {
    print_status "Installing Termux dependencies..."
    fix_dpkg_issues
    DEBIAN_FRONTEND=noninteractive pkg update -y 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive pkg upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive pkg install -y git python cronie curl unzip termux-api termux-services 2>/dev/null || true
    print_success "Termux dependencies installed!"
}

install_dependencies_linux() {
    print_status "Installing Linux dependencies..."
    if check_command apt; then
        sudo apt update -y 2>/dev/null || true
        sudo apt install -y git python3 python3-pip python3-venv cron wget curl unzip 2>/dev/null || true
    elif check_command pacman; then
        sudo pacman -Syu --noconfirm 2>/dev/null || true
        sudo pacman -S --noconfirm git python python-pip cronie wget curl unzip 2>/dev/null || true
    elif check_command yum; then
        sudo yum update -y 2>/dev/null || true
        sudo yum install -y git python3 python3-pip cronie wget curl unzip 2>/dev/null || true
    elif check_command dnf; then
        sudo dnf update -y 2>/dev/null || true
        sudo dnf install -y git python3 python3-pip cronie wget curl unzip 2>/dev/null || true
    else
        print_error "Unsupported package manager!"
        exit 1
    fi
    print_success "Linux dependencies installed!"
}

install_dependencies_macos() {
    print_status "Installing macOS dependencies..."
    if ! check_command brew; then
        print_status "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>/dev/null || true
    fi
    brew install git python wget curl 2>/dev/null || true
    print_success "macOS dependencies installed!"
}

install_xray() {
    print_status "Installing Xray-core..."
    if command -v xray >/dev/null 2>&1; then
        print_success "Xray already installed: $(xray version 2>&1 | head -1)"
        return 0
    fi

    if ! check_command unzip; then
        print_error "unzip not found. Please install unzip first."
        exit 1
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  XRAY_FILE="Xray-linux-64.zip" ;;
        aarch64) XRAY_FILE="Xray-linux-arm64-v8a.zip" ;;
        armv7l)  XRAY_FILE="Xray-linux-arm32-v7a.zip" ;;
        *)       print_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K(.*?)(?=")')
    if [ -z "$XRAY_VERSION" ]; then
        print_error "Failed to get latest Xray version"
        exit 1
    fi

    print_status "Downloading Xray $XRAY_VERSION ($XRAY_FILE)..."
    wget -q "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_FILE}" -O /tmp/xray.zip || {
        print_error "Download failed"
        exit 1
    }

    print_status "Extracting Xray..."
    mkdir -p /tmp/xray
    unzip -q -o /tmp/xray.zip -d /tmp/xray
    chmod +x /tmp/xray/xray
    sudo mv /tmp/xray/xray /usr/local/bin/ 2>/dev/null || {
        print_error "Failed to move xray to /usr/local/bin/ (permission denied?)"
        exit 1
    }
    rm -rf /tmp/xray /tmp/xray.zip

    print_success "Xray installed successfully!"
    xray version 2>&1 | head -1
}

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

setup_termux_service() {
    print_status "Setting up Termux persistent service..."
    mkdir -p "$PREFIX/var/service" 2>/dev/null || true
    mkdir -p "$PREFIX/var/service/multiproxy" 2>/dev/null || true
    mkdir -p "$PREFIX/var/service/multiproxy/log" 2>/dev/null || true
    cat > "$PREFIX/var/service/multiproxy/run" << 'EOFSERVICE'
#!/data/data/com.termux/files/usr/bin/sh
exec 2>&1

INSTALL_DIR="$HOME/multi-proxy-config-fetcher"
INTERVAL=43200

termux-wake-lock 2>/dev/null || true

while true; do
    if [ -d "$INSTALL_DIR" ]; then
        cd "$INSTALL_DIR"
        bash run.sh
    fi
    sleep $INTERVAL
done
EOFSERVICE
    chmod +x "$PREFIX/var/service/multiproxy/run" 2>/dev/null || true
    cat > "$PREFIX/var/service/multiproxy/log/run" << 'EOFLOG'
#!/data/data/com.termux/files/usr/bin/sh
LOG_DIR="$HOME/multi-proxy-config-fetcher/logs"
mkdir -p "$LOG_DIR"
exec svlogd -tt "$LOG_DIR"
EOFLOG
    chmod +x "$PREFIX/var/service/multiproxy/log/run" 2>/dev/null || true
    mkdir -p ~/.termux/boot 2>/dev/null || true
    cat > ~/.termux/boot/start-multiproxy << 'EOFBOOT'
#!/data/data/com.termux/files/usr/bin/sh
sleep 10
termux-wake-lock
sv-enable multiproxy
sv up multiproxy
EOFBOOT
    chmod +x ~/.termux/boot/start-multiproxy 2>/dev/null || true
    sv-enable multiproxy 2>/dev/null || true
    sleep 2
    sv up multiproxy 2>/dev/null || true
    print_success "Termux service configured and started!"
}

setup_cron_linux() {
    print_status "Setting up cron job for Linux..."
    local cron_entry="0 */12 * * * /bin/bash $INSTALL_DIR/run.sh >> $INSTALL_DIR/logs/cron.log 2>&1"
    if ! check_command crontab; then
        print_warning "crontab not found!"
        return 1
    fi
    (crontab -l 2>/dev/null | grep -v "multi-proxy-config-fetcher"; echo "$cron_entry") | crontab - 2>/dev/null || true
    if check_command systemctl; then
        sudo systemctl enable cron 2>/dev/null || sudo systemctl enable cronie 2>/dev/null || true
        sudo systemctl start cron 2>/dev/null || sudo systemctl start cronie 2>/dev/null || true
    fi
    print_success "Cron job configured! (runs every 12 hours)"
}

setup_cron_macos() {
    print_status "Setting up LaunchAgent for macOS..."
    mkdir -p "$HOME/Library/LaunchAgents" 2>/dev/null || true
    cat > "$HOME/Library/LaunchAgents/com.anonymous.multiproxy.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.anonymous.multiproxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$INSTALL_DIR/run.sh</string>
    </array>
    <key>StartCalendarInterval</key>
    <array>
        <dict>
            <key>Hour</key>
            <integer>8</integer>
            <key>Minute</key>
            <integer>0</integer>
        </dict>
        <dict>
            <key>Hour</key>
            <integer>20</integer>
            <key>Minute</key>
            <integer>0</integer>
        </dict>
    </array>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/launchd.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/launchd_error.log</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
EOF
    launchctl unload "$HOME/Library/LaunchAgents/com.anonymous.multiproxy.plist" 2>/dev/null || true
    launchctl load "$HOME/Library/LaunchAgents/com.anonymous.multiproxy.plist" 2>/dev/null || true
    print_success "LaunchAgent configured! (runs at 08:00 and 20:00)"
}

create_management_script() {
    print_status "Creating management script..."
    cat > "$INSTALL_DIR/manage.sh" << 'EOFMANAGE'
#!/usr/bin/env bash

INSTALL_DIR="$HOME/multi-proxy-config-fetcher"
cd "$INSTALL_DIR"

PLATFORM=""
if command -v termux-info >/dev/null 2>&1; then
    PLATFORM="termux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
else
    PLATFORM="linux"
fi

case "$1" in
    start)
        echo "🚀 Starting pipeline..."
        bash run.sh
        ;;
    status)
        echo "📊 System Status:"
        echo ""
        echo "📁 Output files:"
        ls -lh configs/*.txt configs/*.json 2>/dev/null | awk '{print "   ", $9, "-", $5}'
        echo ""
        echo "📝 Recent logs:"
        ls -lt logs/*.log 2>/dev/null | head -3 | awk '{print "   ", $9}'
        ;;
    logs)
        if [ "$PLATFORM" = "termux" ]; then
            sv check multiproxy 2>/dev/null && tail -50 logs/current || tail -50 logs/run_*.log 2>/dev/null | tail -50
        elif [ -f "logs/cron.log" ]; then
            tail -50 logs/cron.log
        else
            ls -t logs/run_*.log 2>/dev/null | head -1 | xargs tail -50
        fi
        ;;
    clean)
        echo "🧹 Cleaning old logs..."
        find logs -name "*.log" -mtime +7 -delete 2>/dev/null
        echo "✓ Done!"
        ;;
    update)
        echo "🔄 Updating repository..."
        git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
        git fetch --all
        git reset --hard origin/main
        git pull origin main
        echo "✓ Updated!"
        ;;
    restart-service)
        if [ "$PLATFORM" = "termux" ]; then
            echo "🔄 Restarting service..."
            sv restart multiproxy
            echo "✓ Service restarted!"
        else
            echo "⚠️  Service restart only available on Termux"
        fi
        ;;
    help|*)
        echo "Multi Wizard - Management Script"
        echo ""
        echo "Usage: bash manage.sh [command]"
        echo ""
        echo "Commands:"
        echo "  start           - Run pipeline manually"
        echo "  status          - Show system status"
        echo "  logs            - Show recent logs"
        echo "  clean           - Remove old logs"
        echo "  update          - Update from GitHub"
        if [ "$PLATFORM" = "termux" ]; then
            echo "  restart-service - Restart Termux service"
        fi
        echo "  help            - Show this help"
        ;;
esac
EOFMANAGE

    chmod +x "$INSTALL_DIR/manage.sh" 2>/dev/null || true
    print_success "Management script created!"
}

print_final_instructions() {
    echo ""
    echo -e "${MAGENTA}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BRIGHT_GREEN}  🎉 Multi Wizard Installation Complete!${NC}"
    echo -e "${MAGENTA}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BRIGHT_CYAN}📁 Installation directory:${NC} $INSTALL_DIR"
    echo ""
    echo -e "${BRIGHT_CYAN}🔧 Quick commands:${NC}"
    echo "   cd $INSTALL_DIR"
    echo "   bash manage.sh start    # Run now"
    echo "   bash manage.sh status   # Check status"
    echo "   bash manage.sh logs     # View logs"
    echo ""
    if [ "$PLATFORM" = "termux" ]; then
        echo -e "${BRIGHT_CYAN}📱 Termux Service:${NC}"
        echo "   sv status multiproxy    # Check service"
        echo "   sv restart multiproxy   # Restart service"
        echo ""
        echo -e "${YELLOW}⚠️  CRITICAL STEPS:${NC}"
        echo "   1. Install Termux:Boot from F-Droid"
        echo "   2. Open Termux:Boot once"
        echo "   3. Settings → Apps → Termux → Battery → Unrestricted"
        echo ""
        echo -e "${GREEN}✓ Service runs every 12 hours automatically${NC}"
    elif [ "$PLATFORM" = "macos" ]; then
        echo -e "${GREEN}✓ LaunchAgent runs at 08:00 and 20:00 daily${NC}"
    else
        echo -e "${GREEN}✓ Cron job runs every 12 hours${NC}"
    fi
    echo ""
    echo -e "${MAGENTA}════════════════════════════════════════════════════════════════${NC}"
}

main() {
    PLATFORM=$(detect_platform)
    print_status "Detected platform: $PLATFORM"
    echo ""
    if [ "$PLATFORM" = "unknown" ]; then
        print_error "Unsupported platform!"
        exit 1
    fi
    if [ "$PLATFORM" = "windows" ]; then
        print_error "Windows detected! Please use WSL2 or Git Bash."
        exit 1
    fi
    check_python_version
    case $PLATFORM in
        termux)
            install_dependencies_termux
            ;;
        linux)
            install_dependencies_linux
            ;;
        macos)
            install_dependencies_macos
            ;;
    esac
    setup_repository
    create_directory_structure
    setup_python_environment
    install_xray
    create_runner_script
    create_management_script
    case $PLATFORM in
        termux)
            setup_termux_service
            ;;
        linux)
            setup_cron_linux
            ;;
        macos)
            setup_cron_macos
            ;;
    esac
    print_final_instructions
}

main "$@"
