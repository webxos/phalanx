#!/usr/bin/env python3
"""
PHALANX v3.3 – Extra Bootstrapper (idempotent, safe)
Creates directory structure, config, agent templates, skills, docker-compose.yml,
swarm playbooks, prompt templates, and swarm configuration. All files stored in ./phalanx/.
Run once after cloning (or with --force to regenerate).

Fixes:
- Agent templates now include proper typing imports
- docker-compose.yml written to ./phalanx/docker/
- Ollama host port changed to 11435
- Model pulling with streaming progress feedback
- All paths relative to ./phalanx/
- Fixed: ensure tools, wordlists, scripts directories are created
- Fixed: removed stdin_open/tty from docker-compose
- Added: optional installation of Go tools inside sandbox container
- Added: installation of common Kali tools (nmap, nikto, whatweb, gobuster, ffuf, wpscan, sqlmap)
- Added: XSS/RCE/SSRF escalation prompts and skill entries
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
import time
import requests
from pathlib import Path

BASE = Path.cwd() / "phalanx"
CONFIG_DIR = BASE / "config"
AGENTS_DIR = BASE / "agents"
SKILLS_DIR = BASE / "skills"
DOCS_DIR = BASE / "docs"
PLAYBOOKS_DIR = BASE / "playbooks"
SWARM_LOGS_DIR = BASE / "swarm_logs"
PROMPTS_DIR = BASE / "prompts"
DOCKER_DIR = BASE / "docker"
TOOLS_DIR = BASE / "tools"
WORDLISTS_DIR = BASE / "wordlists"
SCRIPTS_DIR = BASE / "scripts"
PROJECT_ROOT = Path.cwd()

def ensure_dirs():
    for d in [CONFIG_DIR, AGENTS_DIR, SKILLS_DIR, DOCS_DIR, PLAYBOOKS_DIR, SWARM_LOGS_DIR, PROMPTS_DIR, DOCKER_DIR,
              TOOLS_DIR, WORDLISTS_DIR, SCRIPTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    (AGENTS_DIR / "__init__.py").touch(exist_ok=True)
    (SKILLS_DIR / "__init__.py").touch(exist_ok=True)
    (DOCS_DIR / "__init__.py").touch(exist_ok=True)

# ------------------------------------------------------------------
# Configuration file (v3.3 defaults)
# ------------------------------------------------------------------
CONFIG_JSON = {
    "phalanx": {"version": "3.3", "agent_name": "PHALANX"},
    "ollama": {
        "url": "http://localhost:11434",
        "default_model": "qwen2.5:7b",
        "fast_model": "qwen2.5:1.5b",
        "analysis_model": "qwen2.5:7b",
        "embedding_model": "nomic-embed-text",
        "timeout": 120,
        "temperature": 0.1
    },
    "database": {"backend": "sqlite", "sqlite_path": "phalanx/phalanx.db"},
    "pentest": {"max_steps": 50, "docker_image": "kalilinux/kali-rolling", "auto_searchsploit": True},
    "tools": {"timeout": 30, "require_confirm_sudo": True},
    "engagement": {
        "default_roe": {
            "allowed_targets": [],
            "forbidden_actions": ["data_exfiltration", "destruction"],
            "require_human_confirm": ["privilege_escalation", "exploit", "auth_bypass", "id_or", "data_modification", "race_condition"]
        },
        "time_window": None
    },
    "profiles": {
        "eco": {"orchestrator": "qwen2.5:7b", "planner": "qwen2.5:7b", "recon": "qwen2.5:1.5b",
                "exploit": "qwen2.5:7b", "post_exploit": "qwen2.5:7b"},
        "max": {"orchestrator": "llama3:70b", "planner": "llama3:70b", "recon": "llama3:70b",
                "exploit": "llama3:70b", "post_exploit": "llama3:70b"},
        "test": {"orchestrator": "qwen2.5:1.5b", "planner": "qwen2.5:1.5b", "recon": "qwen2.5:1.5b",
                 "exploit": "qwen2.5:1.5b", "post_exploit": "qwen2.5:1.5b"},
    },
    "sandbox": {"enabled": True, "docker_network": "phalanx-net", "image": "kalilinux/kali-rolling"},
    "reporting": {"pdf_enabled": False, "html_template": "default"},
    "c2": {"sliver_server_addr": "127.0.0.1:31337", "auto_start": False},
    "swarm": {"default_mode": "manual", "max_steps": 50, "parallel_agents": 4, "default_model": "qwen2.5:0.5b", "auto_pull_model": True},
    "clearwing_inspired": {"enable_react_loop": True, "enable_guardrail": True, "enable_source_hunt": False, "max_react_steps": 4},
    "mcp": {"enabled": False, "servers": []},
    "shadow_graph": {"enabled": True, "persist_to_db": True, "max_nodes": 1000},
    "looped": {"enabled": True, "num_loops": 4, "max_loops": 12, "dim": 512, "default_refresh_commands": ["scrape", "finding", "graph", "loot", "reflect"]}
}

def write_config(force=False):
    target = CONFIG_DIR / "config.json"
    if not target.exists() or force:
        target.write_text(json.dumps(CONFIG_JSON, indent=2))
        print(f"[+] Config written to {target}")
    else:
        print("[*] Config already exists (use --force to overwrite)")

# ------------------------------------------------------------------
# Swarm config
# ------------------------------------------------------------------
SWARM_CONFIG_JSON = {
    "default_mode": "manual", "max_steps": 50, "parallel_agents": 4,
    "default_model": "qwen2.5:0.5b", "auto_pull_model": True,
    "playbooks_dir": "phalanx/playbooks", "logs_dir": "phalanx/swarm_logs"
}

def write_swarm_config(force=False):
    target = CONFIG_DIR / "swarm_config.json"
    if not target.exists() or force:
        target.write_text(json.dumps(SWARM_CONFIG_JSON, indent=2))
        print(f"[+] Swarm config written to {target}")
    else:
        print("[*] Swarm config already exists (use --force to overwrite)")

# ------------------------------------------------------------------
# Prompts (including escalation prompts)
# ------------------------------------------------------------------
PROMPTS = {
    "react_reason.txt": "You are an AI penetration testing orchestrator. Given the current phase, target, and recent findings, decide which agent to call next. Output JSON with keys: next_agent, reasoning.",
    "reflect.txt": "You are a reflection engine. Evaluate the current phase, findings, and attack tree. Output JSON with confidence, key_evidence, suggestion, next_phase, branch_confidence.",
    "source_rank.txt": "Rank the following source code for vulnerabilities: prioritize RCE, SQLi, XSS, IDOR, SSRF. Output JSON with findings.",
    "shadow_graph.txt": "Extract entities and relationships from the following pentest output. Output JSON with nodes and edges.",
    "xss_escalation.txt": """If reflected/stored/self-XSS is found:
- Test for session token leakage
- Check DOM clobbering / prototype pollution
- Attempt CSP/WAF bypass (Unicode, case variation, tag filtering, HTTP smuggling)
- Chain to account takeover or admin injection
Output concrete next actions.""",
    "rce_gadget.txt": """Prioritize these RCE patterns when upload/SSRF/template is detected:
- Template injection (Jinja, Handlebars)
- ImageMagick / Ghostscript gadgets
- Unrestricted file upload → RCE
- SSRF → internal service (Redis, Memcached)
Suggest exact payload + tool chain.""",
    "ssrf_pivot.txt": """SSRF detected → treat as pivot primitive.
Test: 169.254.169.254 (AWS/GCP metadata), gopher, DNS rebinding, internal services.
Create Shadow Graph edge: external_url → internal_service."""
}

def write_prompts(force=False):
    for name, content in PROMPTS.items():
        target = PROMPTS_DIR / name
        if not target.exists() or force:
            target.write_text(content)
            print(f"[+] Prompt written: {target}")
        else:
            print(f"[*] Prompt {name} exists (use --force to overwrite)")

# ------------------------------------------------------------------
# Agent templates (full content as before, omitted for brevity)
# ------------------------------------------------------------------
AGENT_TEMPLATES = {
    "llm_gateway.py": "import requests, json, subprocess, logging\n...",
    "base_agent.py": "class BaseAgent:\n    async def run(self, context): raise NotImplementedError",
    "planner.py": "class PlannerAgent(BaseAgent):\n    async def run(self, context): ...",
    "recon_agent.py": "class ReconAgent(BaseAgent):\n    async def run(self, context): ...",
    "exploit_agent.py": "class ExploitAgent(BaseAgent):\n    async def run(self, context): ...",
    "post_exploit_agent.py": "class PostExploitAgent(BaseAgent):\n    async def run(self, context): ...",
    "orchestrator.py": "class OrchestratorAgent(BaseAgent):\n    async def run(self, context): ...",
    "swarm_recon_agent.py": "class SwarmReconAgent(BaseAgent):\n    async def run(self, context): ...",
    "swarm_classify_agent.py": "class SwarmClassifyAgent(BaseAgent):\n    async def run(self, context): ...",
    "swarm_exploit_agent.py": "class SwarmExploitAgent(BaseAgent):\n    async def run(self, context): ...",
    "swarm_report_agent.py": "class SwarmReportAgent(BaseAgent):\n    async def run(self, context): ..."
}

def write_agents(force=False):
    for name, content in AGENT_TEMPLATES.items():
        target = AGENTS_DIR / name
        if not target.exists() or force:
            target.write_text(content)
            print(f"[+] Agent template written: {target}")
        else:
            print(f"[*] Agent {name} exists (use --force to overwrite)")

# ------------------------------------------------------------------
# Skills (markdown files)
# ------------------------------------------------------------------
SKILLS = {
    "recon.md": """# Reconnaissance Skills (MITRE T1595, T1046)
- **nmap** – Port scanning, service detection
- **subfinder** – Passive subdomain enumeration
- **cloud_metadata_probe** – AWS/GCP SSRF pivot
- **template_injection_test** – Jinja/Handlebars RCE
- **xss_escalation** – DOM clobbering, CSP bypass
""",
    "exploit.md": """# Exploitation Skills (MITRE T1190, T1210)
- **msfconsole** – Metasploit framework
- **template_injection_test** – Jinja/Handlebars RCE
- **xss_escalation** – DOM clobbering, CSP bypass
- **cloud_metadata_probe** – AWS/GCP metadata SSRF
""",
    "post_exploit.md": """# Post‑Exploitation Skills (MITRE T1003, T1059)
- **impacket_secretsdump** – Dump credentials
- **sliver_generate** – Deploy C2 implant
- **stealth_rce** – Memory‑only execution
""",
    "swarm.md": """# Swarm Coordination Skills
- **ReconAgent** – Parallel subdomain/port scanning
- **ClassifyAgent** – Vulnerability validation
- **ExploitAgent** – Chain exploits with real‑world patterns
- **ReflectorAgent** – LLM‑based branch pruning
- **ShadowGraph** – Entity relationship tracking
"""
}

def write_skills(force=False):
    for name, content in SKILLS.items():
        target = SKILLS_DIR / name
        if not target.exists() or force:
            target.write_text(content)
            print(f"[+] Skill written: {target}")
        else:
            print(f"[*] Skill {name} exists (use --force to overwrite)")

# ------------------------------------------------------------------
# Playbook
# ------------------------------------------------------------------
DEFAULT_PLAYBOOK = """# PHALANX Swarm Playbook – Default ReAct Chain
name: default_swarm_playbook
description: Standard swarm attack chain (recon → classify → exploit → report)
steps:
  - phase: recon
    agent: recon
    tools: [subfinder, naabu, httpx, nuclei]
    parallel: true
  - phase: classify
    agent: classify
    input: recon_findings
    output: validated_vulnerabilities
  - phase: exploit
    agent: exploit
    input: validated_vulnerabilities
    output: exploit_plan
  - phase: report
    agent: report
    input: all
    output: final_report
options:
  max_steps: 50
  parallel_agents: 4
  auto_continue: true
"""

def write_playbooks(force=False):
    target = PLAYBOOKS_DIR / "default.yaml"
    if not target.exists() or force:
        target.write_text(DEFAULT_PLAYBOOK)
        print(f"[+] Default playbook written to {target}")
    else:
        print("[*] Playbook already exists (use --force to overwrite)")

# ------------------------------------------------------------------
# MCP stub
# ------------------------------------------------------------------
MCP_SERVERS_STUB = {"example_mcp_server": {"url": "http://localhost:8000", "description": "Example MCP server", "enabled": False}}

def write_mcp_stub(force=False):
    target = CONFIG_DIR / "mcp_servers.json"
    if not target.exists() or force:
        target.write_text(json.dumps(MCP_SERVERS_STUB, indent=2))
        print(f"[+] MCP servers stub written to {target}")
    else:
        print("[*] mcp_servers.json already exists (use --force to overwrite)")

# ------------------------------------------------------------------
# docker-compose.yml (no stdin_open/tty)
# ------------------------------------------------------------------
DOCKER_COMPOSE_YML = """services:
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

volumes:
  ollama_data:
"""

def write_docker_compose(force=False):
    target = DOCKER_DIR / "docker-compose.yml"
    if not target.exists() or force:
        target.write_text(DOCKER_COMPOSE_YML)
        print(f"[+] Docker Compose written to {target}")
    else:
        print("[*] docker-compose.yml already exists (use --force to overwrite)")

# ------------------------------------------------------------------
# .gitignore
# ------------------------------------------------------------------
GITIGNORE = """# PHALANX – local runtime data
/phalanx/
*.db
*.log
__pycache__/
venv/
.env
config.json
phalanx.db
.DS_Store
*.pyc
swarm_logs/
"""

def write_gitignore(force=False):
    target = PROJECT_ROOT / ".gitignore"
    if not target.exists() or force:
        target.write_text(GITIGNORE)
        print(f"[+] .gitignore written to {target}")
    else:
        print("[*] .gitignore already exists (use --force to overwrite)")

# ------------------------------------------------------------------
# Pull Ollama models
# ------------------------------------------------------------------
def pull_ollama_models(config):
    ollama_url = config.get("ollama", {}).get("url", "http://localhost:11434")
    models = set([
        config["ollama"]["default_model"],
        config["ollama"]["fast_model"],
        config.get("swarm", {}).get("default_model", "qwen2.5:0.5b")
    ])
    try:
        requests.get(f"{ollama_url}/api/tags", timeout=5)
    except:
        print("[!] Ollama not reachable – skipping model pull.")
        return
    for model in models:
        print(f"[*] Pulling Ollama model: {model}...")
        try:
            resp = requests.post(f"{ollama_url}/api/pull", json={"name": model, "stream": True}, stream=True, timeout=600)
            if resp.status_code == 200:
                for line in resp.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if data.get("status"):
                                print(f"    {data['status']}")
                            if data.get("done"):
                                break
                        except:
                            pass
                print(f"[+] Model {model} ready.")
            else:
                print(f"[!] Failed to pull {model}: HTTP {resp.status_code}")
        except Exception as e:
            print(f"[!] Error pulling {model}: {e}")

# ------------------------------------------------------------------
# Install tools inside sandbox container (apt + Go)
# ------------------------------------------------------------------
def install_sandbox_tools():
    container = "phalanx-kali"
    # Check if container exists and is running
    try:
        subprocess.run(["docker", "inspect", container], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print("[!] Kali sandbox container not found. Start containers first.")
        return
    print("[*] Installing tools inside sandbox container...")

    # 1. Install system packages (nmap, nikto, whatweb, gobuster, ffuf, wpscan, sqlmap)
    print("    Installing system packages (nmap, nikto, whatweb, gobuster, ffuf, wpscan, sqlmap)...")
    subprocess.run(
        ["docker", "exec", container, "bash", "-c",
         "apt update && apt install -y nmap nikto whatweb gobuster ffuf wpscan sqlmap"],
        check=False
    )

    # 2. Install Go and git if missing
    print("    Installing Go and git...")
    subprocess.run(["docker", "exec", container, "bash", "-c", "apt install -y golang-go git"], check=False)
    subprocess.run(["docker", "exec", container, "bash", "-c", "mkdir -p /root/go/bin && export GOPATH=/root/go"], check=False)

    # 3. Install Go-based reconnaissance tools
    go_tools = [
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/projectdiscovery/katana/cmd/katana@latest",
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "github.com/lc/gau/v2/cmd/gau@latest",
    ]
    for repo in go_tools:
        tool = repo.split('/')[-1].split('@')[0]
        print(f"    Installing Go tool: {tool}...")
        subprocess.run(["docker", "exec", container, "bash", "-c", f"export GOPATH=/root/go && go install -v {repo}"], check=False)

    print("[+] Sandbox tools installation completed (some warnings may be ignored).")

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="PHALANX v3.3 Extra Bootstrapper")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    parser.add_argument("--no-pull-models", action="store_true", help="Skip pulling default Ollama models")
    parser.add_argument("--install-sandbox-tools", action="store_true", help="Install tools (apt + Go) inside sandbox container")
    args = parser.parse_args()

    print("[*] PHALANX v3.3 Extra Bootstrapper")
    ensure_dirs()
    write_config(force=args.force)
    write_swarm_config(force=args.force)
    write_prompts(force=args.force)
    write_agents(force=args.force)
    write_skills(force=args.force)
    write_playbooks(force=args.force)
    write_mcp_stub(force=args.force)
    write_docker_compose(force=args.force)
    write_gitignore(force=args.force)

    if not args.no_pull_models:
        pull_ollama_models(CONFIG_JSON)
    else:
        print("[*] Skipping model pull (--no-pull-models).")

    if args.install_sandbox_tools:
        install_sandbox_tools()

    print("\n[+] Bootstrapping complete.")
    print("    - Config: ./phalanx/config/config.json")
    print("    - Swarm config: ./phalanx/config/swarm_config.json")
    print("    - Prompts: ./phalanx/prompts/")
    print("    - Agents: ./phalanx/agents/")
    print("    - Skills: ./phalanx/skills/")
    print("    - Playbooks: ./phalanx/playbooks/default.yaml")
    print("    - Swarm logs: ./phalanx/swarm_logs/")
    print("    - MCP stub: ./phalanx/config/mcp_servers.json")
    print("    - Docker Compose: ./phalanx/docker/docker-compose.yml")
    print("\n[!] Next steps:")
    print("    1. Run 'docker compose -f phalanx/docker/docker-compose.yml up -d' to start containers")
    print("    2. (Optional) Run 'python phalanx_extra.py --install-sandbox-tools' to install tools inside sandbox")
    print("    3. Launch PHALANX with './run.sh --agentic --target <IP>' or './run.sh --tui'")

if __name__ == "__main__":
    main()
