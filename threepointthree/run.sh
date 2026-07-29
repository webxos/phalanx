#!/usr/bin/env bash
set -euo pipefail   # Exit on error, undefined variable, and pipeline failures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Starting PHALANX v3.3"

# ------------------------------------------------------------------
# Detect package manager (apt, dnf, pacman, brew)
# ------------------------------------------------------------------
detect_package_manager() {
    if command -v apt &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v brew &> /dev/null; then
        echo "brew"
    else
        echo "unknown"
    fi
}

PKG_MANAGER=$(detect_package_manager)

# ------------------------------------------------------------------
# Directories
# ------------------------------------------------------------------
PHALANX_DIR="${SCRIPT_DIR}/phalanx"
mkdir -p "${PHALANX_DIR}"/{config,agents,skills,docs,reports,sandbox-data,tools,wordlists,scripts,swarm_logs,playbooks}
echo "[*] Local phalanx directory ready: ${PHALANX_DIR}"

# ------------------------------------------------------------------
# Ollama – use Docker container, NOT host process
# ------------------------------------------------------------------
echo "[*] Ollama will run inside Docker on host port 11435 -> container port 11434"

# ------------------------------------------------------------------
# Remove NVIDIA repository (only for apt)
# ------------------------------------------------------------------
if [ "$PKG_MANAGER" = "apt" ]; then
    echo "[*] Removing NVIDIA repository (not needed for PHALANX)..."
    sudo mkdir -p /etc/apt/sources.list.d/disabled
    sudo find /etc/apt/sources.list.d -type f \( -name "*nvidia*" -o -name "*cuda*" \) -exec mv {} /etc/apt/sources.list.d/disabled/ \; 2>/dev/null || true
    sudo sed -i '/developer.download.nvidia.com/d' /etc/apt/sources.list 2>/dev/null || true
    sudo rm -f /etc/apt/trusted.gpg.d/nvidia* /etc/apt/trusted.gpg.d/cuda* 2>/dev/null || true
fi

# ------------------------------------------------------------------
# Install system build dependencies (required for Go tools)
# ------------------------------------------------------------------
echo "[*] Ensuring system dependencies for Go tools..."
case "$PKG_MANAGER" in
    apt)
        sudo apt update
        sudo apt install -y libpcap-dev build-essential
        ;;
    dnf)
        sudo dnf install -y libpcap-devel gcc gcc-c++ make
        ;;
    pacman)
        sudo pacman -S --noconfirm libpcap base-devel
        ;;
    brew)
        brew install libpcap
        ;;
    *)
        echo "[!] Unknown package manager – skipping dependency installation (may cause issues)."
        ;;
esac

# ------------------------------------------------------------------
# Check and install missing tools (APT/Go) – with deduplication
# ------------------------------------------------------------------
declare -A TOOL_INFO=(
    ["nmap"]="apt"
    ["whois"]="apt"
    ["dig"]="apt"
    ["theHarvester"]="apt"
    ["enum4linux"]="apt"
    ["nikto"]="apt"
    ["whatweb"]="apt"
    ["gobuster"]="apt"
    ["ffuf"]="apt"
    ["wpscan"]="apt"
    ["sqlmap"]="apt"
    ["metasploit-framework"]="apt"
    ["searchsploit"]="apt"
    ["impacket-scripts"]="apt"
    ["ghidra"]="apt"
    ["docker"]="apt"
    ["docker-compose"]="apt"
    ["git"]="apt"
    ["golang-go"]="apt"
    ["subfinder"]="go"
    ["httpx"]="go"
    ["nuclei"]="go"
    ["naabu"]="go"
    ["katana"]="go"
    ["dnsx"]="go"
    ["gau"]="go"
    ["sliver"]="go"
)

declare -A MISSING_TOOLS
declare -A APT_TOOLS
declare -A GO_TOOLS

for tool in "${!TOOL_INFO[@]}"; do
    case "$tool" in
        metasploit-framework)
            if ! command -v msfconsole &> /dev/null; then
                MISSING_TOOLS["msfconsole"]=1
                APT_TOOLS["$tool"]=1
            fi
            ;;
        impacket-scripts)
            if ! command -v impacket-secretsdump &> /dev/null; then
                MISSING_TOOLS["impacket-secretsdump"]=1
                APT_TOOLS["$tool"]=1
            fi
            ;;
        sliver)
            if ! command -v sliver-client &> /dev/null; then
                MISSING_TOOLS["sliver-client"]=1
                GO_TOOLS["$tool"]=1
            fi
            ;;
        docker-compose)
            if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
                MISSING_TOOLS["docker-compose"]=1
                APT_TOOLS["$tool"]=1
            fi
            ;;
        *)
            if ! command -v "$tool" &> /dev/null; then
                MISSING_TOOLS["$tool"]=1
                if [[ "${TOOL_INFO[$tool]}" == "apt" ]]; then
                    APT_TOOLS["$tool"]=1
                else
                    GO_TOOLS["$tool"]=1
                fi
            fi
            ;;
    esac
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    echo "[!] Missing required tools: ${!MISSING_TOOLS[*]}"
    echo "    PHALANX will not function fully without these."
    echo "    You can install them now (requires sudo for apt packages, and Go for Go tools)."
    read -p "    Install all missing tools? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Install APT packages
        if [ ${#APT_TOOLS[@]} -gt 0 ]; then
            APT_LIST="${!APT_TOOLS[*]}"
            echo "[*] Installing apt packages: ${APT_LIST}"
            case "$PKG_MANAGER" in
                apt)
                    sudo apt update
                    sudo apt install -y ${APT_LIST}
                    ;;
                dnf)
                    sudo dnf install -y ${APT_LIST}
                    ;;
                pacman)
                    sudo pacman -S --noconfirm ${APT_LIST}
                    ;;
                brew)
                    brew install ${APT_LIST}
                    ;;
                *)
                    echo "[!] No supported package manager – cannot install APT packages."
                    ;;
            esac
        fi

        # Install Go tools
        if [ ${#GO_TOOLS[@]} -gt 0 ]; then
            if ! command -v go &> /dev/null; then
                echo "[*] Installing Go..."
                case "$PKG_MANAGER" in
                    apt)
                        sudo apt install -y golang-go
                        ;;
                    dnf)
                        sudo dnf install -y golang
                        ;;
                    pacman)
                        sudo pacman -S --noconfirm go
                        ;;
                    brew)
                        brew install go
                        ;;
                    *)
                        echo "[!] Please install Go manually."
                        ;;
                esac
            fi
            export GOPATH=$(go env GOPATH)
            export PATH=$PATH:$GOPATH/bin
            echo "[*] Installing Go tools: ${!GO_TOOLS[*]}"
            for tool in "${!GO_TOOLS[@]}"; do
                echo "    Installing $tool..."
                case "$tool" in
                    subfinder)
                        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "      Warning: $tool install failed"
                        ;;
                    httpx)
                        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || echo "      Warning: $tool install failed"
                        ;;
                    nuclei)
                        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "      Warning: $tool install failed"
                        ;;
                    naabu)
                        go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || echo "      Warning: $tool install failed"
                        ;;
                    katana)
                        go install -v github.com/projectdiscovery/katana/cmd/katana@latest || echo "      Warning: $tool install failed"
                        ;;
                    dnsx)
                        go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || echo "      Warning: $tool install failed"
                        ;;
                    gau)
                        go install -v github.com/lc/gau/v2/cmd/gau@latest || echo "      Warning: $tool install failed"
                        ;;
                    sliver)
                        go install -v github.com/BishopFox/sliver@latest || echo "      Warning: $tool install failed"
                        ;;
                esac
            done
            export PATH=$PATH:$(go env GOPATH)/bin
            echo "[*] Added $(go env GOPATH)/bin to PATH for this session."
        fi
        echo "[+] Tool installation completed (some warnings may be ignored)."
    else
        echo "[*] Skipping tool installation. Some features may be unavailable."
    fi
fi

# ------------------------------------------------------------------
# Docker network creation (without fixed subnet)
# ------------------------------------------------------------------
if command -v docker &> /dev/null; then
    if ! docker network inspect phalanx-net &>/dev/null; then
        echo "[*] Creating Docker network: phalanx-net (auto-assigned subnet)"
        docker network create phalanx-net
    else
        echo "[*] Docker network phalanx-net already exists"
    fi
fi

# ------------------------------------------------------------------
# Write docker-compose.yml (no explicit subnet)
# ------------------------------------------------------------------
DOCKER_COMPOSE_DIR="${PHALANX_DIR}/docker"
DOCKER_COMPOSE_FILE="${DOCKER_COMPOSE_DIR}/docker-compose.yml"
mkdir -p "$DOCKER_COMPOSE_DIR"

cat > "$DOCKER_COMPOSE_FILE" <<'EOF'
services:
  kali-sandbox:
    image: kalilinux/kali-rolling
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
      - OLLAMA_HOST=http://ollama:11434
    stdin_open: true
    tty: true
    depends_on:
      - ollama

  ollama:
    image: ollama/ollama:latest
    container_name: phalanx-ollama
    ports:
      - "11435:11434"
    volumes:
      - ollama_data:/root/.ollama
    networks:
      - phalanx-net
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "ollama", "list"]
      interval: 30s
      timeout: 10s
      retries: 3

  metasploitable2:
    image: tleemcjr/metasploitable2:latest
    container_name: phalanx-target
    restart: unless-stopped
    networks:
      - phalanx-net
    healthcheck:
      test: ["CMD", "netstat", "-tln", "|", "-q", "':22 '"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    ports:
      - "2222:22"
      - "8080:80"
      - "4443:443"

networks:
  phalanx-net:
    driver: bridge
    # No explicit subnet – Docker auto-assigns

volumes:
  ollama_data:
EOF

echo "[+] Docker Compose file written to $DOCKER_COMPOSE_FILE"

# ------------------------------------------------------------------
# Start Docker containers (Kali sandbox, Ollama, Metasploitable2)
# ------------------------------------------------------------------
if command -v docker &> /dev/null; then
    echo "[*] Starting Docker containers..."
    if command -v docker-compose &> /dev/null; then
        docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    elif docker compose version &>/dev/null 2>&1; then
        docker compose -f "$DOCKER_COMPOSE_FILE" up -d
    else
        echo "[!] Docker Compose not available – cannot start containers."
    fi
    echo "[+] Sandbox containers started (Kali: phalanx-kali, Target: phalanx-target, Ollama: phalanx-ollama on port 11435)"

    # Wait for Ollama to be ready
    echo "[*] Waiting for Ollama container to be healthy..."
    for i in {1..30}; do
        if docker inspect --format='{{.State.Health.Status}}' phalanx-ollama 2>/dev/null | grep -q healthy; then
            echo "[+] Ollama is ready."
            break
        fi
        sleep 2
    done

    # ------------------------------------------------------------------
    # Install Go tools inside the Kali sandbox container
    # ------------------------------------------------------------------
    echo "[*] Installing reconnaissance tools inside phalanx-kali container..."
    # Ensure Go and git are installed
    docker exec phalanx-kali bash -c "apt update && apt install -y golang-go git" 2>/dev/null || true
    # Set up GOPATH
    docker exec phalanx-kali bash -c "mkdir -p /root/go/bin && export GOPATH=/root/go && export PATH=\$PATH:\$GOPATH/bin" 2>/dev/null || true
    # Install tools
    tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
    )
    for repo in "${tools[@]}"; do
        tool_name=$(basename "$repo" | cut -d'@' -f1)
        echo "    Installing $tool_name..."
        docker exec phalanx-kali bash -c "export GOPATH=/root/go && go install -v $repo" 2>/dev/null || echo "      Warning: $tool_name install failed"
    done
    echo "[+] Sandbox container tools installed."
else
    echo "[!] Docker not found – sandbox mode disabled."
fi

# ------------------------------------------------------------------
# Virtual environment and Python dependencies
# ------------------------------------------------------------------
if [ "$PKG_MANAGER" = "apt" ] && ! dpkg -l python3-venv &>/dev/null 2>&1; then
    echo "[*] python3-venv not found. Installing..."
    sudo apt update
    sudo apt install -y python3-venv
fi

VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

echo "[*] Installing Python dependencies..."
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    if python -c "import playwright" &>/dev/null; then
        echo "[*] Installing Playwright browsers..."
        python -m playwright install chromium
    fi
else
    echo "[!] requirements.txt not found – skipping."
fi

# ------------------------------------------------------------------
# First run bootstrap (phalanx_extra.py)
# ------------------------------------------------------------------
CONFIG_FILE="${PHALANX_DIR}/config/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[*] First run detected – bootstrapping extra components..."
    if [ -f "phalanx_extra.py" ]; then
        python phalanx_extra.py --no-pull-models
    else
        echo "[!] phalanx_extra.py missing – cannot bootstrap."
    fi
fi

# ------------------------------------------------------------------
# Launch PHALANX (TUI / REPL / agentic)
# ------------------------------------------------------------------
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"
echo "[*] Launching PHALANX..."

python phalanx.py "$@"
PHALANX_EXIT_CODE=$?

deactivate 2>/dev/null || true
exit $PHALANX_EXIT_CODE
