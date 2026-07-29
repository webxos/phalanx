#!/bin/bash
# PHALANX v3.6 – Fully Automated Launcher (FINAL PRODUCTION)
# This script sets up and runs PHALANX.
# Use environment variables to customise behaviour:
#   PHALANX_USE_DOCKER=1       Enable Docker sandbox (default: 0)
#   PHALANX_USE_VENV=1         Use Python virtual environment (default: 0)
#   PHALANX_SKIP_PULL=1        Skip pulling Ollama models (default: 0 in interactive, 1 in auto)
#   PHALANX_PULL_MODELS=1      Force pulling models even in auto mode (default: 0)
#   PHALANX_DEFAULT_MODEL      Default Ollama model (default: qwen2.5:0.5b)
#   PHALANX_FAST_MODEL         Fast Ollama model (default: same)
#   PHALANX_SKIP_TOOLS=1       Skip installing system tools (default: 0)
#   PHALANX_SKIP_GO_TOOLS=1    Skip installing Go tools (default: 0)
#   PHALANX_INSTALL_REVERSE=1  Install reverse engineering tools (default: 0)
#   PHALANX_INSTALL_VPN=1      Install OpenVPN (for LavaWall VPN feature) (default: 0)
#   PHALANX_SETUP_OGHIDRA=1    Download and configure OGhidra (default: 0)
#   PHALANX_SETUP_VERIFY=1     Set up verify-claims benchmark suite (default: 0)
#   PHALANX_AUTO=1             Skip interactive prompts (use env vars)
#   PHALANX_EXTRA_ARGS         Additional arguments passed to phalanx.py
#   PHALANX_SKIP_WINSTEALTH=1  Skip building WinStealth (default: 0)
#   PHALANX_DEBUG=1            Enable verbose output (set -x)
#   PHALANX_ALLOW_SHELL=1      Enable shell tool (dangerous, opt-in)

set -euo pipefail

# Enable debug mode if requested
if [ "${PHALANX_DEBUG:-0}" = "1" ]; then
    set -x
fi

# ------------------------------------------------------------------
# Environment defaults (can be overridden)
# ------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
export PHALANX_VERSION="3.6"

PHALANX_USE_DOCKER="${PHALANX_USE_DOCKER:-0}"
PHALANX_USE_VENV="${PHALANX_USE_VENV:-0}"
PHALANX_SKIP_PULL="${PHALANX_SKIP_PULL:-1}"          # default: skip in non‑interactive
PHALANX_PULL_MODELS="${PHALANX_PULL_MODELS:-0}"      # force pull even in auto
PHALANX_DEFAULT_MODEL="${PHALANX_DEFAULT_MODEL:-qwen2.5:0.5b}"
PHALANX_FAST_MODEL="${PHALANX_FAST_MODEL:-$PHALANX_DEFAULT_MODEL}"
PHALANX_SKIP_TOOLS="${PHALANX_SKIP_TOOLS:-0}"
PHALANX_SKIP_GO_TOOLS="${PHALANX_SKIP_GO_TOOLS:-0}"
PHALANX_INSTALL_REVERSE="${PHALANX_INSTALL_REVERSE:-0}"
PHALANX_INSTALL_VPN="${PHALANX_INSTALL_VPN:-0}"
PHALANX_SETUP_OGHIDRA="${PHALANX_SETUP_OGHIDRA:-0}"
PHALANX_SETUP_VERIFY="${PHALANX_SETUP_VERIFY:-0}"
PHALANX_AUTO="${PHALANX_AUTO:-0}"
PHALANX_EXTRA_ARGS="${PHALANX_EXTRA_ARGS:-}"
PHALANX_SKIP_WINSTEALTH="${PHALANX_SKIP_WINSTEALTH:-0}"
PHALANX_ALLOW_SHELL="${PHALANX_ALLOW_SHELL:-0}"

export PHALANX_DEFAULT_MODEL
export PHALANX_FAST_MODEL
export PHALANX_SKIP_PULL
export PHALANX_INSTALL_REVERSE
export PHALANX_INSTALL_VPN
export PHALANX_SETUP_OGHIDRA
export PHALANX_SETUP_VERIFY
export PHALANX_SKIP_WINSTEALTH
export PHALANX_ALLOW_SHELL
export PHALANX_VERSION

# ------------------------------------------------------------------
# Helper: check if a command exists
# ------------------------------------------------------------------
command_exists() {
    command -v "$1" &>/dev/null
}

# ------------------------------------------------------------------
# Helper: check if a port is in use on the host
# ------------------------------------------------------------------
check_port_in_use() {
    local port="$1"
    if command_exists ss; then
        ss -lntn | grep -q ":$port "
    elif command_exists netstat; then
        netstat -lntn | grep -q ":$port "
    else
        # Fallback: try to bind to the port with nc
        nc -z 127.0.0.1 "$port" 2>/dev/null && return 0 || return 1
    fi
}

# ------------------------------------------------------------------
# Improved sudo runner with fallback and existence check
# ------------------------------------------------------------------
run_sudo() {
    # If sudo is not available, try running directly (we might be root)
    if ! command_exists sudo; then
        if [ "$EUID" -eq 0 ]; then
            # We are root, just run the command directly
            "$@"
            return $?
        else
            echo "[!] sudo not found and not root. Please install sudo or run as root." >&2
            return 1
        fi
    fi

    # Try passwordless sudo first (non-interactive)
    if sudo -n true 2>/dev/null; then
        sudo "$@"
    else
        # Otherwise, prompt for password interactively
        echo "[!] sudo requires a password. Please enter it now (or use NOPASSWD in sudoers)." >&2
        sudo "$@"
    fi
}

# ------------------------------------------------------------------
# Helper: run pip install with the correct command and flags
# ------------------------------------------------------------------
pip_install() {
    $PIP_CMD install $PIP_INSTALL_ARGS "$@" || echo "[!] Failed to install $@ via pip."
}

# ------------------------------------------------------------------
# Early validation
# ------------------------------------------------------------------
if ! command_exists python3; then
    echo "[!] python3 not found. Please install Python 3.10+ and ensure it is in PATH." >&2
    exit 1
fi

# ------------------------------------------------------------------
# Docker fallback: if Docker is enabled but not available, disable
# ------------------------------------------------------------------
if [ "$PHALANX_USE_DOCKER" = "1" ] && ! command_exists docker; then
    echo "[!] Docker not available. Falling back to local execution."
    export PHALANX_USE_DOCKER=0
fi

# ------------------------------------------------------------------
# Clean up existing containers to avoid name conflicts
# ------------------------------------------------------------------
cleanup_containers() {
    # If docker-compose.yml exists and docker compose is available, use it
    if [ -f "docker-compose.yml" ] && command_exists docker && docker compose version &>/dev/null; then
        echo "[*] Stopping and removing containers via docker compose down..."
        docker compose down --remove-orphans 2>/dev/null || true
    elif [ -f "docker-compose.yml" ] && command_exists docker-compose; then
        echo "[*] Stopping and removing containers via docker-compose down..."
        docker-compose down --remove-orphans 2>/dev/null || true
    fi

    # Additionally, remove known containers if they still exist
    local containers=("phalanx-ollama" "phalanx-target" "phalanx-kali")
    for c in "${containers[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
            echo "[*] Removing existing container: $c"
            docker rm -f "$c" 2>/dev/null || true
        fi
    done
}

# ------------------------------------------------------------------
# Ensure Metasploitable2 container exists and is running
# This function is now only called AFTER docker compose up,
# and only if the container is not already running.
# ------------------------------------------------------------------
ensure_metasploitable_container() {
    # Ensure network exists
    if ! docker network inspect phalanx-net &>/dev/null; then
        echo "[*] Creating Docker network phalanx-net..."
        docker network create phalanx-net
    fi

    if ! docker ps -a --format '{{.Names}}' | grep -q "^phalanx-target$"; then
        echo "[*] Creating Metasploitable2 container (phalanx-target)..."
        docker run -d --name phalanx-target --network phalanx-net tleemcjr/metasploitable2:latest
    fi

    # Start container if not running, with retry
    if ! docker ps --format '{{.Names}}' | grep -q "^phalanx-target$"; then
        echo "[*] Starting existing phalanx-target container..."
        for i in {1..3}; do
            docker start phalanx-target && break
            echo "  Retry $i..."
            sleep 2
        done
    fi

    # Verify it's running
    if docker ps --format '{{.Names}}' | grep -q "^phalanx-target$"; then
        echo "[+] Metasploitable2 container is running."
    else
        echo "[!] Metasploitable2 container could not be started. Check Docker logs."
    fi
}

# ------------------------------------------------------------------
# Project root and paths
# ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PROJECT_ROOT="$SCRIPT_DIR"
PHALANX_DIR="${PROJECT_ROOT}/phalanx"
mkdir -p "${PHALANX_DIR}"/{config,agents,skills,docs,reports,sandbox-data,tools,wordlists,scripts,swarm_logs,playbooks,defense_logs,policies,bench,golden}

echo "[*] PHALANX v${PHALANX_VERSION} – Automated setup starting..."
echo "[*] Project root: $PROJECT_ROOT"

# ------------------------------------------------------------------
# Platform detection
# ------------------------------------------------------------------
OS="$(uname -s)"
if [[ "$OS" == "Linux" ]]; then
    if grep -q "Kali" /etc/os-release 2>/dev/null; then
        PLATFORM="kali"
    else
        PLATFORM="linux"
    fi
elif [[ "$OS" == "Darwin" ]]; then
    PLATFORM="macos"
else
    PLATFORM="wsl"   # Assume WSL2 on Windows
fi
echo "[*] Detected platform: $PLATFORM"

# ------------------------------------------------------------------
# Package manager detection (with validation)
# ------------------------------------------------------------------
detect_package_manager() {
    if command_exists apt-get; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists brew; then
        echo "brew"
    else
        echo "unknown"
    fi
}
PKG_MANAGER=$(detect_package_manager)
echo "[*] Package manager: $PKG_MANAGER"

# ------------------------------------------------------------------
# Interactive selection (if not in auto mode)
# ------------------------------------------------------------------
if [ "$PHALANX_AUTO" != "1" ]; then
    echo ""
    echo "PHALANX v${PHALANX_VERSION} Setup"
    echo "------------------"
    read -p "Use Docker? (y/n) [n]: " use_docker
    read -p "Use Python virtual environment? (y/n) [n]: " use_venv
    read -p "Install reverse engineering tools (jadx, apktool, radare2, frida-tools, js-beautify)? (y/n) [y]: " install_reverse
    read -p "Install OpenVPN (for LavaWall VPN feature)? (y/n) [n]: " install_vpn
    read -p "Pull Ollama models (default qwen2.5:0.5b)? (y/n) [y]: " pull_models
    read -p "Set up OGhidra (requires Ghidra installed)? (y/n) [n]: " setup_oghidra
    read -p "Set up verify-claims benchmark suite? (y/n) [n]: " setup_verify
    export PHALANX_USE_DOCKER=$([ "$use_docker" = "y" ] && echo 1 || echo 0)
    export PHALANX_USE_VENV=$([ "$use_venv" = "y" ] && echo 1 || echo 0)
    export PHALANX_INSTALL_REVERSE=$([ "$install_reverse" != "n" ] && echo 1 || echo 0)
    export PHALANX_INSTALL_VPN=$([ "$install_vpn" = "y" ] && echo 1 || echo 0)
    export PHALANX_SKIP_PULL=$([ "$pull_models" = "n" ] && echo 1 || echo 0)
    export PHALANX_PULL_MODELS=$([ "$pull_models" = "y" ] && echo 1 || echo 0)
    export PHALANX_SETUP_OGHIDRA=$([ "$setup_oghidra" = "y" ] && echo 1 || echo 0)
    export PHALANX_SETUP_VERIFY=$([ "$setup_verify" = "y" ] && echo 1 || echo 0)
    echo ""
else
    # In auto mode, we use environment variables already set.
    # But we can override PHALANX_SKIP_PULL with PHALANX_PULL_MODELS if set.
    if [ "${PHALANX_PULL_MODELS:-0}" = "1" ]; then
        export PHALANX_SKIP_PULL=0
    fi
fi

# ------------------------------------------------------------------
# Determine pip command (robust)
# ------------------------------------------------------------------
PIP_CMD=""
PIP_INSTALL_ARGS=""

# Prefer using python3 -m pip as the most reliable method
if python3 -m pip --version &>/dev/null; then
    PIP_CMD="python3 -m pip"
elif command_exists pip3; then
    PIP_CMD="pip3"
elif command_exists pip; then
    PIP_CMD="pip"
else
    echo "[!] No pip found. Please install python3-pip or ensure python3 is in PATH."
    exit 1
fi

# Determine installation flags
if [ "$PHALANX_USE_VENV" = "1" ]; then
    PIP_INSTALL_ARGS=""
else
    # Detect if we need --break-system-packages or --user
    if [ "$PLATFORM" = "kali" ]; then
        PIP_INSTALL_ARGS="--break-system-packages"
    else
        if pip3 --version 2>&1 | grep -qi "externally-managed"; then
            PIP_INSTALL_ARGS="--break-system-packages"
        else
            PIP_INSTALL_ARGS="--user"
        fi
    fi
fi

echo "[*] Using pip command: $PIP_CMD install $PIP_INSTALL_ARGS"

# ------------------------------------------------------------------
# Install system tools (unless skipped)
# ------------------------------------------------------------------
install_system_tools() {
    if [ "$PKG_MANAGER" = "unknown" ]; then
        echo "[!] Unknown package manager. Skipping system tool installation."
        echo "    Please install required tools manually (nmap, nikto, etc.)."
        return 1
    fi

    echo "[*] Installing system dependencies and pentest tools..."
    case "$PKG_MANAGER" in
        apt)
            run_sudo apt update -qq
            # Install docker-compose via legacy package (more reliable than plugin)
            run_sudo apt install -y -qq --no-install-recommends docker-compose || true
            # Rest of packages
            run_sudo apt install -y -qq --no-install-recommends nmap nikto whatweb gobuster ffuf wpscan sqlmap \
                theharvester enum4linux exploitdb metasploit-framework impacket-scripts \
                feroxbuster testssl.sh masscan git curl wget \
                libpcap-dev build-essential python3-pip \
                aircrack-ng wireless-tools || echo "[!] Some packages failed to install."
            if [ "$PHALANX_USE_DOCKER" = "1" ]; then
                run_sudo apt install -y -qq --no-install-recommends docker.io || true
            fi
            if [ "$PHALANX_INSTALL_VPN" = "1" ]; then
                run_sudo apt install -y -qq --no-install-recommends openvpn || true
            fi
            ;;
        dnf)
            run_sudo dnf install -y nmap nikto whatweb gobuster ffuf wpscan sqlmap \
                theharvester enum4linux exploitdb metasploit-framework impacket \
                feroxbuster testssl.sh masscan git curl wget \
                libpcap-devel gcc gcc-c++ make python3-pip \
                aircrack-ng wireless-tools || echo "[!] Some packages failed to install."
            if [ "$PHALANX_USE_DOCKER" = "1" ]; then
                run_sudo dnf install -y docker docker-compose || true
            fi
            if [ "$PHALANX_INSTALL_VPN" = "1" ]; then
                run_sudo dnf install -y openvpn || true
            fi
            ;;
        pacman)
            # On Arch, some tools are in AUR; we install what we can from official repos.
            run_sudo pacman -S --noconfirm --needed nmap nikto whatweb gobuster ffuf wpscan sqlmap \
                feroxbuster testssl.sh masscan git curl wget \
                libpcap base-devel python-pip \
                aircrack-ng wireless_tools || echo "[!] Some packages failed to install."
            # theharvester and enum4linux are not in official repos; try pip fallback later.
            # exploitdb and metasploit are in AUR; we skip for now.
            if [ "$PHALANX_USE_DOCKER" = "1" ]; then
                run_sudo pacman -S --noconfirm --needed docker docker-compose || true
            fi
            if [ "$PHALANX_INSTALL_VPN" = "1" ]; then
                run_sudo pacman -S --noconfirm --needed openvpn || true
            fi
            ;;
        brew)
            # Homebrew doesn't have all security tools; install what's available.
            brew install nmap nikto whatweb gobuster ffuf wpscan sqlmap \
                feroxbuster testssl.sh masscan git curl wget \
                libpcap python3 \
                aircrack-ng wireless-tools || echo "[!] Some packages failed to install."
            # theharvester and enum4linux are not available via brew; we'll install via pip later.
            # exploitdb and metasploit are not in brew; skip.
            if [ "$PHALANX_USE_DOCKER" = "1" ]; then
                brew install docker docker-compose || echo "[!] Docker install failed (may need Docker Desktop)."
            fi
            if [ "$PHALANX_INSTALL_VPN" = "1" ]; then
                brew install openvpn || true
            fi
            ;;
    esac

    # Install missing tools via pip fallback for theHarvester and enum4linux
    if ! command_exists theHarvester; then
        echo "[*] Installing theHarvester via pip..."
        pip_install theharvester || echo "[!] theHarvester install failed."
    fi
    if ! command_exists enum4linux; then
        echo "[*] Installing enum4linux via pip..."
        pip_install enum4linux || echo "[!] enum4linux install failed."
    fi

    # Install Go if missing
    if ! command_exists go; then
        echo "[*] Installing Go..."
        case "$PKG_MANAGER" in
            apt)   run_sudo apt install -y -qq --no-install-recommends golang-go || true ;;
            dnf)   run_sudo dnf install -y golang || true ;;
            pacman) run_sudo pacman -S --noconfirm --needed go || true ;;
            brew)  brew install go || true ;;
            *)     echo "[!] Cannot install Go automatically." ;;
        esac
    fi
}

if [ "$PHALANX_SKIP_TOOLS" != "1" ]; then
    install_system_tools
else
    echo "[*] Skipping system tools installation (PHALANX_SKIP_TOOLS=1)"
fi

# ------------------------------------------------------------------
# Install Go tools (unless skipped) – with fixed sliver handling
# ------------------------------------------------------------------
install_go_tools() {
    if ! command_exists go; then
        echo "[!] Go not found – skipping Go tools."
        return 1
    fi
    echo "[*] Installing Go tools..."
    export GOPATH=$(go env GOPATH)
    export PATH="$PATH:$GOPATH/bin"

    # Define tools as "name=url" entries for flexible handling
    GO_TOOLS=(
        "subfinder=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx=github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "nuclei=github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "naabu=github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "katana=github.com/projectdiscovery/katana/cmd/katana@latest"
        "dnsx=github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "gau=github.com/lc/gau/v2/cmd/gau@latest"
        "sliver=github.com/BishopFox/sliver/client@latest"
        "dalfox=github.com/hahwul/dalfox/v2@latest"
        "crlfuzz=github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
    )

    for entry in "${GO_TOOLS[@]}"; do
        tool="${entry%%=*}"
        url="${entry#*=}"
        echo "    Installing $tool..."
        # Special handling for sliver (known replace issues)
        if [ "$tool" = "sliver" ]; then
            echo "      Sliver special handling..."
            go install -v "$url" || {
                echo "      Sliver install failed (replace directives issue). Trying go get fallback..."
                go get -u github.com/BishopFox/sliver/client || true
            }
        else
            go install -v "$url" || {
                echo "      Warning: $tool install failed."
            }
        fi
    done

    echo "[*] Go tools installed. Ensure $GOPATH/bin is in your PATH."
    # Persist PATH for subsequent commands
    export PATH="$PATH:$GOPATH/bin"
}

if [ "$PHALANX_SKIP_GO_TOOLS" != "1" ]; then
    install_go_tools
else
    echo "[*] Skipping Go tools installation (PHALANX_SKIP_GO_TOOLS=1)"
fi

# ------------------------------------------------------------------
# Install reverse engineering tools (if requested)
# ------------------------------------------------------------------
install_reverse_tools() {
    if [ "$PKG_MANAGER" = "unknown" ]; then
        echo "[!] Unknown package manager. Skipping reverse tools installation."
        echo "    Please install jadx, apktool, radare2 manually."
        # Still try pip for frida-tools
        pip_install frida-tools || echo "  [WARNING] frida-tools installation failed."
        return 1
    fi

    echo "[*] Installing reverse engineering tools..."
    case "$PKG_MANAGER" in
        apt)
            run_sudo apt update -qq
            run_sudo apt install -y -qq --no-install-recommends jadx apktool radare2 || echo "[!] Some reverse tools failed to install."
            ;;
        brew)
            brew install jadx apktool radare2 || echo "[!] Some reverse tools failed to install."
            ;;
        pacman)
            run_sudo pacman -S --noconfirm --needed jadx apktool radare2 || echo "[!] Some reverse tools failed to install."
            ;;
        dnf)
            run_sudo dnf install -y jadx apktool radare2 || echo "[!] Some reverse tools failed to install."
            ;;
        *)
            echo "  [WARNING] Unknown package manager. Please install jadx, apktool, radare2 manually."
            ;;
    esac

    # Install frida-tools via pip using the determined pip command
    echo "[*] Installing frida-tools via pip..."
    pip_install frida-tools || echo "  [WARNING] frida-tools installation failed."

    # Install js-beautify via npm if available (use --force to bypass warnings)
    if command_exists npm; then
        echo "[*] Installing js-beautify via npm..."
        npm install -g --force js-beautify || echo "  [WARNING] js-beautify installation failed."
    else
        echo "  [WARNING] npm not found; js-beautify not installed."
    fi

    echo "[*] Reverse engineering tools installation complete."
}

if [ "$PHALANX_INSTALL_REVERSE" = "1" ]; then
    install_reverse_tools
else
    echo "[*] Skipping reverse tools installation (PHALANX_INSTALL_REVERSE=0)"
fi

# ------------------------------------------------------------------
# Python dependencies (system or venv)
# ------------------------------------------------------------------
install_python_deps() {
    echo "[*] Installing Python dependencies..."

    # Ensure pip is available
    if ! command_exists pip3 && ! command_exists pip && ! python3 -m pip &>/dev/null; then
        echo "[!] pip not found – installing..."
        if [ "$PKG_MANAGER" != "unknown" ]; then
            case "$PKG_MANAGER" in
                apt)   run_sudo apt install -y -qq --no-install-recommends python3-pip || true ;;
                dnf)   run_sudo dnf install -y python3-pip || true ;;
                pacman) run_sudo pacman -S --noconfirm --needed python-pip || true ;;
                brew)  brew install python3 || true ;;
                *)     echo "[!] Cannot install pip automatically."; return 1 ;;
            esac
        else
            echo "[!] Unknown package manager. Please install pip manually."
            return 1
        fi
        # Re‑detect pip command
        if python3 -m pip --version &>/dev/null; then
            PIP_CMD="python3 -m pip"
        elif command_exists pip3; then
            PIP_CMD="pip3"
        elif command_exists pip; then
            PIP_CMD="pip"
        else
            echo "[!] Still no pip found. Aborting."
            return 1
        fi
    fi

    # If using venv, create it now
    if [ "$PHALANX_USE_VENV" = "1" ]; then
        echo "[*] Creating Python virtual environment..."
        python3 -m venv .venv
        source .venv/bin/activate
        PIP_CMD="pip"
        PIP_INSTALL_ARGS=""
        echo "[*] Using venv pip: $PIP_CMD"
    fi

    # Upgrade pip and setuptools to a compatible version
    $PIP_CMD install $PIP_INSTALL_ARGS --upgrade pip || true
    $PIP_CMD install $PIP_INSTALL_ARGS "setuptools<82" --force-reinstall || true

    # Install from requirements.txt if present, otherwise install minimal
    if [ -f "requirements.txt" ]; then
        # Remove pywin32 on non-Windows
        if [[ "$PLATFORM" != "windows" && "$PLATFORM" != "wsl" ]]; then
            grep -v "pywin32" requirements.txt > requirements.temp.txt
            # Also filter out torch if platform doesn't support it? but we'll keep it.
            $PIP_CMD install $PIP_INSTALL_ARGS -r requirements.temp.txt || {
                echo "[!] Failed to install from requirements.temp.txt. Falling back to minimal."
                $PIP_CMD install $PIP_INSTALL_ARGS rich psutil sentence-transformers prompt-toolkit
            }
            rm -f requirements.temp.txt
        else
            $PIP_CMD install $PIP_INSTALL_ARGS -r requirements.txt || {
                echo "[!] Failed to install from requirements.txt. Falling back to minimal."
                $PIP_CMD install $PIP_INSTALL_ARGS rich psutil sentence-transformers prompt-toolkit
            }
        fi
    else
        $PIP_CMD install $PIP_INSTALL_ARGS rich psutil sentence-transformers prompt-toolkit
    fi

    # Install Playwright browsers if playwright is installed
    if python3 -c "import playwright" &>/dev/null; then
        echo "[*] Installing Playwright browsers..."
        python3 -m playwright install chromium
    fi

    # Pre‑load sentence-transformers model only if module is installed
    if python3 -c "import sentence_transformers" &>/dev/null; then
        echo "[*] Pre‑loading embedding model (all-MiniLM-L6-v2)..."
        python3 -c "
from sentence_transformers import SentenceTransformer
try:
    model = SentenceTransformer('all-MiniLM-L6-v2')
    model.encode('warmup')
    print('[+] Embedding model pre‑loaded.')
except Exception as e:
    print(f'[!] Failed to pre‑load embedding model: {e}')
" || true
    else
        echo "[*] sentence-transformers not installed; skipping embedding pre‑load."
    fi

    echo "[*] Python dependencies installed."
}

install_python_deps

# ------------------------------------------------------------------
# Ensure phalanx_defense.py stub exists (if missing)
# ------------------------------------------------------------------
ensure_defense_stub() {
    local defense_file="${PHALANX_DIR}/../phalanx_defense.py"
    if [ ! -f "$defense_file" ]; then
        echo "[*] Creating phalanx_defense.py stub..."
        cat > "$defense_file" <<'EOF'
#!/usr/bin/env python3
"""
PHALANX Defense Module – stub.
This file is created automatically by run.sh.
"""
import logging
logger = logging.getLogger("phalanx.defense")
logger.warning("phalanx_defense module is a stub. Install the full defense module for full functionality.")
EOF
        echo "[+] phalanx_defense.py stub created."
    fi
}
ensure_defense_stub

# ------------------------------------------------------------------
# Docker setup (if enabled)
# ------------------------------------------------------------------
if [ "$PHALANX_USE_DOCKER" = "1" ]; then
    echo "[*] Docker enabled – setting up containers..."

    # Check if Docker daemon is running
    if ! docker info &>/dev/null; then
        echo "[*] Starting Docker daemon..."
        case "$PLATFORM" in
            kali|linux|wsl)
                run_sudo systemctl start docker 2>/dev/null || run_sudo service docker start 2>/dev/null || true
                ;;
            macos)
                echo "[*] Please ensure Docker Desktop is running."
                echo "[*] If not installed, download from https://docker.com"
                ;;
        esac
        sleep 3
    fi

    if docker info &>/dev/null; then
        # Clean up any existing PHALANX containers to avoid name conflicts
        cleanup_containers

        if ! id -nG "$USER" 2>/dev/null | grep -qw docker; then
            echo "[*] Adding user to docker group..."
            run_sudo usermod -aG docker "$USER"
            echo "[!] Group membership changed. You may need to log out and back in for changes to take effect."
        fi

        if ! docker network inspect phalanx-net &>/dev/null; then
            docker network create phalanx-net
        fi

        # ------------------------------------------------------------------
        # Check if port 11434 is already in use (host has Ollama running)
        # ------------------------------------------------------------------
        OLLAMA_PORT_IN_USE=false
        if check_port_in_use 11434; then
            echo "[*] Port 11434 is already in use. Host Ollama is likely running."
            echo "[*] Will NOT start the ollama container. Using host Ollama instead."
            OLLAMA_PORT_IN_USE=true
        else
            echo "[*] Port 11434 is free. Starting ollama container."
        fi

        # ------------------------------------------------------------------
        # Generate docker-compose.yml dynamically (fixed: no duplicate depends_on)
        # ------------------------------------------------------------------
        cat > docker-compose.yml <<EOF
services:
  kali-sandbox:
    build:
      context: .
      dockerfile: Dockerfile.kali
    image: phalanx-kali:latest
    container_name: phalanx-kali
    command: tail -f /dev/null
    cap_add:
      - NET_ADMIN
    restart: unless-stopped
    networks:
      - phalanx-net
    healthcheck:
      test: ["CMD", "nmap", "--version"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    volumes:
      - ./phalanx/tools:/opt/phalanx/tools:ro
      - ./phalanx/wordlists:/opt/phalanx/wordlists:ro
      - ./phalanx/scripts:/opt/phalanx/scripts:ro
      - ./phalanx/sandbox-data:/root/.phalanx
    environment:
      - DEBIAN_FRONTEND=noninteractive
EOF

        if [ "$OLLAMA_PORT_IN_USE" = "true" ]; then
            # Use host's Ollama
            cat >> docker-compose.yml <<EOF
      - OLLAMA_HOST=http://host.docker.internal:11434
    extra_hosts:
      - "host.docker.internal:host-gateway"
EOF
        else
            # Use container's Ollama
            cat >> docker-compose.yml <<EOF
      - OLLAMA_HOST=http://ollama:11434
    depends_on:
      - ollama
EOF
        fi

        # Finish kali-sandbox definition
        cat >> docker-compose.yml <<EOF
    stdin_open: true
    tty: true
EOF

        # Add ollama service only if not using host
        if [ "$OLLAMA_PORT_IN_USE" = "false" ]; then
            cat >> docker-compose.yml <<EOF
  ollama:
    image: ollama/ollama:latest
    container_name: phalanx-ollama
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - phalanx-net
    restart: unless-stopped
EOF
        else
            echo "[*] Skipping ollama container (using host Ollama)."
        fi

        # Add metasploitable2 service
        cat >> docker-compose.yml <<EOF
  metasploitable2:
    image: tleemcjr/metasploitable2:latest
    container_name: phalanx-target
    restart: unless-stopped
    networks:
      - phalanx-net
    ports:
      - "22:22"
      - "80:80"
      - "443:443"
networks:
  phalanx-net:
    driver: bridge
volumes:
  ollama_data:
EOF

        # ------------------------------------------------------------------
        # Start containers
        # ------------------------------------------------------------------
        if command_exists docker && docker compose version &>/dev/null; then
            docker compose up -d --build --remove-orphans
        elif command_exists docker-compose; then
            docker-compose up -d --build --remove-orphans
        else
            echo "[!] Docker Compose not found – cannot start containers."
        fi
        echo "[+] Containers started (if compose is available)."

        # ------------------------------------------------------------------
        # AFTER compose up, ensure Metasploitable container is running
        # This is a safety net in case the container was not defined in compose
        # or if it was removed manually.
        # ------------------------------------------------------------------
        ensure_metasploitable_container
    else
        echo "[!] Docker not running – skipping containers."
    fi
else
    echo "[*] Docker disabled (PHALANX_USE_DOCKER=0)."
fi

# ------------------------------------------------------------------
# WinStealth build (Windows/WSL only, unless skipped)
# ------------------------------------------------------------------
if [[ "$PHALANX_SKIP_WINSTEALTH" != "1" ]]; then
    if [[ "$PLATFORM" == "windows" || "$PLATFORM" == "wsl" ]]; then
        echo "[*] Building WinStealth (Windows evasion library)..."
        # Install build dependencies if needed
        if [ "$PKG_MANAGER" != "unknown" ]; then
            case "$PKG_MANAGER" in
                apt)   run_sudo apt install -y -qq --no-install-recommends cmake gcc-mingw-w64 || echo "[!] Could not install build dependencies." ;;
                brew)  brew install cmake mingw-w64 || echo "[!] Could not install build dependencies." ;;
                pacman) run_sudo pacman -S --noconfirm --needed cmake mingw-w64 || echo "[!] Could not install build dependencies." ;;
                *)     echo "[!] Unknown package manager; cannot install build dependencies automatically." ;;
            esac
        else
            echo "[!] Unknown package manager. Please install cmake and mingw-w64 manually."
        fi
        # Check for required dependencies
        if ! command_exists cmake; then
            echo "[!] cmake not found. Please install cmake and mingw-w64."
            echo "    For Debian/Ubuntu: sudo apt install cmake gcc-mingw-w64"
            echo "    For macOS: brew install cmake mingw-w64"
            echo "    Skipping WinStealth build."
        else
            WINSTEALTH_DIR="${PHALANX_DIR}/lib/winstealth"
            if [ ! -d "$WINSTEALTH_DIR" ]; then
                echo "[*] Cloning WinStealth repository..."
                git clone https://github.com/youssefnoob003/SindriKit.git "$WINSTEALTH_DIR" || {
                    echo "[!] Failed to clone WinStealth. Skipping."
                    WINSTEALTH_SKIP=true
                }
            fi
            if [ -d "$WINSTEALTH_DIR" ] && [ "$WINSTEALTH_SKIP" != "true" ]; then
                mkdir -p "${WINSTEALTH_DIR}/build"
                cd "${WINSTEALTH_DIR}/build"
                echo "[*] Configuring WinStealth build..."
                cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release || {
                    echo "[!] CMake configuration failed. Skipping WinStealth build."
                    cd "$PROJECT_ROOT"
                    WINSTEALTH_SKIP=true
                }
                if [ "$WINSTEALTH_SKIP" != "true" ]; then
                    echo "[*] Building WinStealth..."
                    make -j$(nproc) || {
                        echo "[!] Make failed. Skipping WinStealth build."
                    }
                    cd "$PROJECT_ROOT"
                fi
                if [ -f "${WINSTEALTH_DIR}/build/libwinstealth.so" ] || [ -f "${WINSTEALTH_DIR}/build/winstealth.dll" ]; then
                    echo "[+] WinStealth built successfully."
                else
                    echo "[!] WinStealth build appears to have failed. Library not found."
                fi
            fi
        fi
    else
        echo "[*] Skipping WinStealth build (not on Windows/WSL)."
    fi
else
    echo "[*] Skipping WinStealth build (PHALANX_SKIP_WINSTEALTH=1)."
fi

# ------------------------------------------------------------------
# Bootstrap PHALANX components (creates directories, agent stubs, config)
# ------------------------------------------------------------------
echo "[*] Bootstrapping PHALANX components..."
python3 phalanx_extra.py --force --no-pull-models || {
    echo "[!] Bootstrap failed – some features may be missing. Continuing anyway..."
}

# ------------------------------------------------------------------
# Pull Ollama models if requested (or if not skipped)
# ------------------------------------------------------------------
pull_ollama_models() {
    if [ "${PHALANX_SKIP_PULL:-1}" = "1" ]; then
        echo "[*] Skipping Ollama model pull (PHALANX_SKIP_PULL=1)."
        return 0
    fi
    if ! command_exists ollama; then
        echo "[!] Ollama not installed. Cannot pull models. Install from https://ollama.com"
        echo "[*] You can later pull models manually with: ollama pull $PHALANX_DEFAULT_MODEL"
        return 1
    fi
    # Check if ollama is responding
    if ! ollama list &>/dev/null; then
        echo "[!] Ollama is not running. Please start Ollama first."
        echo "    Run: ollama serve"
        return 1
    fi
    local models_to_pull=("$PHALANX_DEFAULT_MODEL" "$PHALANX_FAST_MODEL")
    # Remove duplicates
    models_to_pull=($(printf "%s\n" "${models_to_pull[@]}" | sort -u))
    for model in "${models_to_pull[@]}"; do
        if ollama list | grep -q "$model"; then
            echo "[*] Model $model already present."
        else
            echo "[*] Pulling model $model (may take a while)..."
            # Use timeout to avoid hanging indefinitely (but allow long download)
            if ollama pull "$model"; then
                echo "[+] Model $model pulled successfully."
            else
                echo "[!] Failed to pull $model."
            fi
        fi
    done
}

if [ "${PHALANX_PULL_MODELS:-0}" = "1" ] || [ "${PHALANX_SKIP_PULL:-1}" = "0" ]; then
    pull_ollama_models
fi

# ------------------------------------------------------------------
# Set up optional OGhidra and verify-claims
# ------------------------------------------------------------------
if [ "$PHALANX_SETUP_OGHIDRA" = "1" ]; then
    echo "[*] Setting up OGhidra..."
    python3 phalanx_extra.py --setup-oghidra || echo "[!] OGhidra setup failed."
fi

if [ "$PHALANX_SETUP_VERIFY" = "1" ]; then
    echo "[*] Setting up verify-claims benchmark suite..."
    python3 phalanx_extra.py --setup-verify || echo "[!] verify-claims setup failed."
fi

# ------------------------------------------------------------------
# Launch PHALANX (default to TUI if no arguments)
# ------------------------------------------------------------------
if [ $# -eq 0 ]; then
    set -- --tui
fi
# Properly handle PHALANX_EXTRA_ARGS (split safely)
if [ -n "$PHALANX_EXTRA_ARGS" ]; then
    # Use eval to split arguments respecting quotes
    eval "set -- $@ $PHALANX_EXTRA_ARGS"
fi

echo "[*] Launching PHALANX with args: $*"
# Use exec to replace shell, but handle failure gracefully
if ! exec python3 phalanx.py "$@"; then
    echo "[!] PHALANX exited with an error. Check logs for details." >&2
    exit 1
fi