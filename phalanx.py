#!/usr/bin/env python3
"""
PHALANX v3.6 – Main Entry: REPL, CLI, and Embedded TUI.
Includes /swarm command for local Ollama pentest swarm (4 agents + orchestrator).
All data stored in ./phalanx/ (local to project).

Enhanced with:
- /finding, /reflect, /resume, /sourcehunt commands
- --guardrail flag for exploit confirmation
- Live evidence table in agentic mode
- Session resume capability
- /loot, /graph, /spawn commands
- --graph / --shadow flags to enable Shadow Graph persistence
- /loop command to control Mythos-style Looped Transformer harness
- /xss command to show XSS escalation patterns
- Robust error handling and table rendering helpers
- Target validation to reject filesystem paths
- Fixed: agentic mode graceful fallback when agent files missing
- Fixed: /loop command handles "current" target correctly
- Fixed: /defense command for defense monitoring
- Fixed: confirmation callback in agentic mode
- Fixed: shadow graph loading in agentic mode
- Added /test command for system health check
- Added /wp command for WordPress scanning
- Added WinStealth integration for Windows low‑level evasion (renamed from SindriKit)
- Environment variables: PHALANX_DEFAULT_MODEL, PHALANX_FAST_MODEL, PHALANX_LOW_PROFILE
- Rich Confirm for guardrail callback
- NEW: --defense flag to start defense monitor at launch
- NEW: --graph flag to enable Shadow Graph by default for all agentic/swarm commands
- Improved error handling in _load_agent_components with detailed logging
- ensure_bootstrapped now runs phalanx_extra.py --force --no-pull-models for full setup
- NEW: Environment health checks (database writability, Docker network, containers) in /test and at startup
- FIX: Model selection in swarm is now fully automated via PHALANX_DEFAULT_MODEL env var
- FIX: No interactive prompts when running in TUI or headless mode
- FIX: TimeoutExpired in check_environment is now caught gracefully (increased timeout to 10s, handled exceptions)
- NEW: Automatic Docker container cleanup at startup to avoid name conflicts
- NEW: Interactive Ollama model selection at startup (lists available models, allows pull)

T3MP3ST + OGhidra Enhancements (v3.6):
- NEW: /warroom command to start/stop/open War Room UI (FastAPI server)
- NEW: /verify command to run verify-claims benchmark suite
- NEW: /reverse command for OGhidra‑powered reverse engineering (load, chat, malware, report)
- NEW: /status command to show T3MP3ST‑style feature status table
- NEW: --warroom CLI flag to launch War Room server at startup
- Updated version to 3.6 and integrated War Room API from phalanx_defense
- NEW: /defense dashboard – opens the War Room in the browser
- FIX: _load_agent_components now has proper fallback for missing planner/orchestrator modules
- FIX: _run_agentic_async handles generate_engagement_plan returning dict correctly
- FIX: Agentic loop no longer calls nmap repeatedly; state transitions improved

ADDITIONAL FIXES in this version:
- _load_agent_components now robustly falls back to Gateway and SwarmOrchestrator if agent modules are missing,
  ensuring that agentic mode never crashes even when stubs are incomplete.
- Defense monitor and War Room server startup order is now explicitly sequential to avoid any race conditions;
  the defense monitor is fully initialized before the War Room server thread is started.
- Added missing error handling in /warroom start to catch failures in starting the FastAPI server.
- The /reverse command now properly handles binary paths with spaces and verifies existence.
- /verify now displays the full benchmark results even if some tests fail.
- Improved the /status command to reflect the actual running state of the War Room and defense monitor.
- Fixed ensure_bootstrapped to use timeout and non-interactive mode.
- Added --no-bootstrap flag to skip automatic bootstrapping.
- Model selection now respects PHALANX_AUTO and uses environment variable without prompting in non-interactive mode.
- Docker container cleanup is now conditional and only runs when needed.
- Replaced broad except blocks with more specific exception handling where possible.
- In main(), added try/except around ensure_bootstrapped to catch exceptions and print clear message.
- War Room thread logging now includes thread ID and PID for debugging.
- Signal handler for clean shutdown logs shutdown actions.
- FIX: Added generic tool command routing in default() so that typing "nmap 192.168.1.1" runs the tool.
- FIX: /wp command now correctly passes config and handles errors.
- FIX: /swarm command no longer passes unexpected kwargs; use_t3mp3st is handled in library.
- ENHANCED: default() parser now intelligently handles flags and target, supports --help.
- ENHANCED: default() output now uses rich formatting for structured tool results when possible.
- FIX: default() now treats arguments starting with '-' as options, not as target.
- FIX: default() now uses inspect.signature to map the first positional argument to the correct parameter name (target, query, domain, etc.).
- FIX: Help handling now shows tool description when running --help for tools without a target parameter.

RAPTOR INSPIRED ENHANCEMENTS (v3.6):
- /loop command enhanced with --altitude flag to specify starting altitude.
- /status table now shows Reasoning Engine state and Disposition Ledger size.
- Signal handler now stops the looped harness gracefully.
- ensure_bootstrapped fallback added if phalanx_extra.py is missing.
- All run_tool calls now have explicit None guards (consistent pattern).

AUTONOMY INTEGRATION (v3.6 – FINAL):
- Removed explicit /raptor command; Raptor loop is now integrated into Swarm.
- Swarm now accepts --raptor and --no-raptor flags; Raptor is enabled by default for 'ctf' and 'manual' modes.
- Added /shell command to execute arbitrary shell commands (opt-in, dangerous).
- Background Reasoning Engine status shown in /status.

CRITICAL FIX (v3.6):
- Fixed _load_agent_components to not use SwarmOrchestrator as a fallback for OrchestratorAgent.
  SwarmOrchestrator has a completely different signature and would cause TypeError.
  Now uses a proper placeholder that matches the expected interface, with debug logging.
"""

import argparse
import asyncio
import cmd
import sys
import json
import signal
import subprocess
import shlex
import threading
import time
import shutil
import re
import os
import webbrowser
import inspect  # Added for signature inspection
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime

# ------------------------------------------------------------------
# Safe Docker import
# ------------------------------------------------------------------
DOCKER_AVAILABLE = False
docker = None
NotFound = Exception
try:
    import docker
    from docker.errors import NotFound
    DOCKER_AVAILABLE = True
except ImportError:
    # Docker not installed; set placeholders
    docker = None
    NotFound = Exception

# Rich for pretty output
from rich.console import Console
from rich.table import Table
from rich.box import ROUNDED, DOUBLE
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# Rich Confirm (optional)
RICH_CONFIRM_AVAILABLE = False
Confirm = None
try:
    from rich.prompt import Confirm
    RICH_CONFIRM_AVAILABLE = True
except ImportError:
    Confirm = None

# Prompt toolkit for TUI (embedded)
PROMPT_TOOLKIT_AVAILABLE = False
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style
    from prompt_toolkit.key_binding import KeyBindings
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    pass

# Local imports (v3.6 core)
from phalanx_core import (
    PhalanxDB, Soul, SkillManager, AutonomousPentest,
    CONFIG_FILE, Finding, RoEEnforcer, Benchmark
)
from phalanx_library import generate_engagement_plan, run_demo, get_logger, bootstrap_all, run_health_check
from phalanx_engine import ToolExecutor
from phalanx_tools import Gateway, list_tools, get_skill_metadata, TOOL_REGISTRY, run_tool

# WinStealth integration (renamed from SindriKit)
WINSTEALTH_AVAILABLE = False
WinStealthWrapper = None
WinStealthError = Exception
try:
    from phalanx_winstealth import WinStealthWrapper, WinStealthError
    WINSTEALTH_AVAILABLE = True
except ImportError:
    WinStealthWrapper = None
    WinStealthError = Exception

# Defense module (optional)
DEFENSE_AVAILABLE = False
NetWatchMonitor = None
run_defense_cli = None
start_warroom_server = None
WARROOM_AVAILABLE = False
try:
    from phalanx_defense import NetWatchMonitor, run_defense_cli, start_warroom_server
    DEFENSE_AVAILABLE = True
    WARROOM_AVAILABLE = True
except ImportError:
    NetWatchMonitor = None
    run_defense_cli = None
    start_warroom_server = None
    WARROOM_AVAILABLE = False

# RaptorLoopEngine – imported from phalanx_library (class defined there)
try:
    from phalanx_library import RaptorLoopEngine
    RAPTOR_AVAILABLE = True
except ImportError:
    RaptorLoopEngine = None
    RAPTOR_AVAILABLE = False

console = Console()
logger = get_logger("phalanx.cli")

# ------------------------------------------------------------------
# Enhanced ASCII Logo (v3.6)
# ------------------------------------------------------------------
LOGO = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗                 ║
║   ██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝                 ║
║   ██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝                  ║
║   ██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗                  ║
║   ██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗                 ║
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝                 ║
║                                                                              ║
║                    Autonomous Pentesting Framework  v3.6                     ║
║              T3MP3ST + OGhidra Enhanced • War Room • verify-claims           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

def print_logo():
    console.print(Panel(
        Text(LOGO, style="bold bright_blue"),
        border_style="bright_blue",
        padding=(0, 2),
        title="PHALANX v3.6",
        subtitle="Only use on authorized systems",
        title_align="center",
        subtitle_align="center"
    ))

# ------------------------------------------------------------------
# Optional Components Status Display
# ------------------------------------------------------------------
def print_optional_status(config: dict):
    """Display availability of optional components at startup."""
    status = []
    # PyTorch
    try:
        import torch
        status.append(("PyTorch", "available (looped harness enabled)"))
    except ImportError:
        status.append(("PyTorch", "not installed (looped harness disabled)"))

    # WinStealth
    try:
        from phalanx_winstealth import WinStealthWrapper
        if config.get("winstealth", {}).get("enabled", False):
            status.append(("WinStealth", "available"))
        else:
            status.append(("WinStealth", "available but disabled in config"))
    except ImportError:
        status.append(("WinStealth", "not built (Windows evasion disabled)"))

    # tmux / pexpect
    tmux = shutil.which("tmux") is not None
    pexpect = False
    try:
        import pexpect
        pexpect = True
    except ImportError:
        pass
    if tmux or pexpect:
        status.append(("Interactive sessions", "available (tmux/pexpect)"))
    else:
        status.append(("Interactive sessions", "limited (subprocess fallback; install tmux or pexpect)"))

    # Sliver
    if shutil.which("sliver-client") or shutil.which("sliver"):
        status.append(("Sliver C2", "available"))
    else:
        status.append(("Sliver C2", "not installed (some C2 features limited)"))

    # FTS5 (SQLite)
    try:
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE VIRTUAL TABLE test USING fts5(content)")
        conn.close()
        status.append(("FTS5 (full-text search)", "available"))
    except Exception:
        status.append(("FTS5 (full-text search)", "not available (fallback to LIKE queries)"))

    # War Room
    if WARROOM_AVAILABLE:
        status.append(("War Room", "available (FastAPI + uvicorn)"))
    else:
        status.append(("War Room", "not installed (pip install fastapi uvicorn)"))

    # OGhidra
    try:
        from phalanx_tools import _check_oghidra_plugin
        if _check_oghidra_plugin():
            status.append(("OGhidra", "plugin installed"))
        else:
            status.append(("OGhidra", "plugin not found"))
    except ImportError:
        status.append(("OGhidra", "not available"))

    # Raptor engine
    if RAPTOR_AVAILABLE:
        status.append(("Raptor Engine", "available"))
    else:
        status.append(("Raptor Engine", "not installed (install phalanx_raptor)"))

    console.print("[dim]Optional Components:[/dim]")
    for name, msg in status:
        console.print(f"  {name}: {msg}")

# ------------------------------------------------------------------
# Target validation – prevent filesystem paths (allow single-label)
# ------------------------------------------------------------------
def is_valid_network_target(target: str) -> bool:
    """
    Reject filesystem paths and require a hostname/IP address.
    Returns True for valid network targets, False otherwise.
    Now allows single-label hostnames like 'localhost', 'metasploitable2'.
    """
    if '/' in target or '\\' in target:
        return False
    if Path(target).exists():
        return False
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(pattern, target))

# ------------------------------------------------------------------
# Environment health checks
# ------------------------------------------------------------------
def check_environment(config: dict) -> Dict[str, Any]:
    """
    Perform comprehensive environment checks:
    - Database directory writability
    - Docker network presence
    - Ollama availability (local or container)
    - Metasploitable2 container status
    Returns dict with 'warnings', 'errors', 'score' and details.
    """
    warnings = []
    errors = []
    score = 100

    # 1. Database directory writability
    db_path = Path(config.get("database", {}).get("sqlite_path", "phalanx/phalanx.db"))
    db_dir = db_path.parent
    try:
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
        test_file = db_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
        logger.debug("Database directory writable.")
    except Exception as e:
        errors.append(f"Database directory '{db_dir}' is not writable: {e}")
        score -= 30

    # 2. Docker network existence (if Docker is available)
    if DOCKER_AVAILABLE:
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", "phalanx-net"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if result.returncode == 0:
                logger.debug("Docker network phalanx-net exists.")
            else:
                warnings.append("Docker network 'phalanx-net' does not exist. Create it with: docker network create phalanx-net")
                score -= 15
        except subprocess.TimeoutExpired:
            warnings.append("Docker network inspect timed out. Docker may be slow or not responding.")
            score -= 15
        except FileNotFoundError:
            warnings.append("Docker command not found. Sandbox features will be disabled.")
            score -= 20
        except Exception as e:
            warnings.append(f"Docker network check failed: {e}")
            score -= 15
    else:
        warnings.append("Docker not installed – sandbox features disabled.")
        score -= 20

    # 3. Ollama availability
    ollama_url = config.get("ollama", {}).get("url", "http://localhost:11434")
    try:
        import requests
        r = requests.get(f"{ollama_url}/api/tags", timeout=3)
        if r.status_code == 200:
            logger.debug("Ollama is reachable.")
        else:
            warnings.append(f"Ollama at {ollama_url} returned status {r.status_code}.")
            score -= 15
    except Exception:
        warnings.append(f"Ollama is not reachable at {ollama_url}. Ensure Ollama is running.")
        score -= 20

    # 4. Metasploitable2 container status (if Docker is available)
    if DOCKER_AVAILABLE:
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", "name=phalanx-target",
                 "--format", "{{.Status}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                if "Up" in result.stdout:
                    logger.debug("phalanx-target container is running.")
                else:
                    warnings.append("phalanx-target container exists but is not running. Start with: docker start phalanx-target")
                    score -= 10
            else:
                # Check if container exists but stopped
                result_all = subprocess.run(
                    ["docker", "ps", "-a", "--filter", "name=phalanx-target",
                     "--format", "{{.Status}}"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False
                )
                if result_all.returncode == 0 and result_all.stdout.strip():
                    warnings.append("phalanx-target container exists but is not running. Start with: docker start phalanx-target")
                    score -= 10
                else:
                    warnings.append("phalanx-target container not found. Create with: docker run -d --name phalanx-target --network phalanx-net tleemcjr/metasploitable2:latest")
                    score -= 15
        except subprocess.TimeoutExpired:
            warnings.append("Docker container check timed out. Docker may be slow or not responding.")
            score -= 10
        except FileNotFoundError:
            # Docker not installed, already warned
            pass
        except Exception as e:
            warnings.append(f"Docker container check failed: {e}")
            score -= 10

    return {
        "warnings": warnings,
        "errors": errors,
        "score": max(0, score),
        "passed": len(errors) == 0 and score >= 80
    }

# ------------------------------------------------------------------
# Helper: render findings as table
# ------------------------------------------------------------------
def render_findings_table(findings: List[Dict], title: str = "Findings") -> Table:
    table = Table(title=title, box=ROUNDED)
    table.add_column("Time", style="dim")
    table.add_column("Target", style="cyan")
    table.add_column("Tool", style="green")
    table.add_column("Severity", style="bold")
    table.add_column("Description", style="white")
    for f in findings[:30]:
        severity_color = "red" if f.get("severity") in ("critical","high") else "yellow" if f.get("severity") == "medium" else "green"
        table.add_row(
            f.get("timestamp", "")[:19],
            f.get("target", "")[:20],
            f.get("tool", ""),
            f"[{severity_color}]{f.get('severity', 'info')}[/]",
            f.get("description", "")[:60]
        )
    return table

def render_loot_table(loot_items: List[Dict], category: str = None) -> Table:
    table = Table(title=f"Loot Items ({category or 'all'})", box=ROUNDED)
    table.add_column("ID", style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("Data (summary)", style="white")
    table.add_column("Ingested", style="dim")
    for item in loot_items[:30]:
        data = json.loads(item["data"])
        summary = data.get("description", data.get("name", data.get("address", str(data)[:50])))
        table.add_row(
            item["loot_id"][:8],
            item["category"],
            summary[:60],
            item["ingested_at"][:16]
        )
    return table

# ------------------------------------------------------------------
# Swarm helpers (import from library, with fallback)
# ------------------------------------------------------------------
SWARM_AVAILABLE = False
try:
    from phalanx_library import (
        run_swarm,
        list_ollama_models,
        pull_ollama_model,
        stop_swarm_campaign,
        get_swarm_campaign_status
    )
    SWARM_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Swarm imports failed: {e}")
    def run_swarm(*args, **kwargs):
        raise NotImplementedError("Swarm not available – run 'python phalanx_extra.py' to install agents.")
    def list_ollama_models():
        return []
    def pull_ollama_model(model):
        return False
    def stop_swarm_campaign(cid):
        return False
    def get_swarm_campaign_status(cid):
        return None

# ------------------------------------------------------------------
# Guardrails: Docker cleanup with locking
# ------------------------------------------------------------------
_CONTAINER_CLEANUP_LOCK = threading.Lock()

def cleanup_phalanx_containers():
    """Stop and remove existing PHALANX containers to avoid name conflicts."""
    if not DOCKER_AVAILABLE:
        logger.debug("Docker module not available; skipping container cleanup.")
        return
    with _CONTAINER_CLEANUP_LOCK:
        try:
            client = docker.from_env()
            for name in ["phalanx-ollama", "phalanx-target", "phalanx-kali"]:
                try:
                    container = client.containers.get(name)
                    if container.status == "running":
                        container.stop()
                    container.remove()
                    console.print(f"[dim]Removed existing container: {name}[/dim]")
                except NotFound:
                    pass
                except Exception as e:
                    logger.warning(f"Could not remove container {name}: {e}")
        except Exception as e:
            logger.warning(f"Could not initialize Docker client: {e}")

# ------------------------------------------------------------------
# Ollama model selection (with fallback)
# ------------------------------------------------------------------
def select_ollama_model(gateway, interactive: bool = True):
    """
    Show available Ollama models and let user choose or pull a new one.
    If interactive is False, skip prompting and return the default from env or fallback.
    """
    if not interactive:
        model = os.environ.get("PHALANX_DEFAULT_MODEL", "qwen2.5:0.5b")
        logger.info(f"Non-interactive mode: using model {model} from environment.")
        return model

    if not SWARM_AVAILABLE:
        console.print("[yellow]Swarm not available; cannot list models.[/yellow]")
        console.print("[yellow]Using default model from environment or fallback.[/yellow]")
        return os.environ.get("PHALANX_DEFAULT_MODEL", "qwen2.5:0.5b")

    models = list_ollama_models()
    if not models:
        console.print("[yellow]No Ollama models found locally.[/yellow]")
        console.print("You can pull one manually later with 'ollama pull <model>'.")
        return None

    console.print("[bold cyan]Available Ollama models:[/bold cyan]")
    for i, m in enumerate(models, 1):
        console.print(f"  {i}. {m}")
    console.print("  Enter a number to select, or type a new model name to pull it.")
    console.print("  (Press Enter to skip, or type 'q' to quit without changing)")

    choice = input("Select model: ").strip()
    if choice.lower() in ('q', ''):
        return None
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(models):
            return models[idx]
    # Otherwise treat as a new model name
    console.print(f"[*] Attempting to pull model: {choice}")
    if pull_ollama_model(choice):
        console.print(f"[green]Model {choice} pulled successfully.[/green]")
        return choice
    else:
        console.print(f"[red]Failed to pull {choice}. Using current default.[/red]")
        return None

# ------------------------------------------------------------------
# Agentic mode with safe dynamic imports (FIXED for v3.6)
# ------------------------------------------------------------------
def _load_agent_components(config: dict):
    """
    Dynamically import agent components using importlib, with graceful failure.
    Returns (OrchestratorAgent, OllamaGateway) or (None, None) on failure.
    Logs detailed errors for debugging.
    FIXED: removed incorrect fallback to SwarmOrchestrator; now uses a proper placeholder.
    """
    try:
        import importlib
        agents_path = Path.cwd() / "phalanx" / "agents"
        if agents_path.exists() and str(agents_path) not in sys.path:
            sys.path.insert(0, str(agents_path))

        # Try importing orchestrator module
        try:
            orchestrator_module = importlib.import_module("orchestrator")
            OrchestratorAgent = getattr(orchestrator_module, "OrchestratorAgent")
        except (ImportError, AttributeError) as e:
            logger.warning(f"OrchestratorAgent not found ({e}), using placeholder.")
            logger.debug("Using placeholder orchestrator – missing agent stubs")
            # Use a placeholder that matches the expected interface
            class PlaceholderOrchestrator:
                def __init__(self, name, gateway, db, soul, skill_mgr, config=None):
                    self.name = name
                    self.gateway = gateway
                    self.db = db
                    self.soul = soul
                    self.skill_mgr = skill_mgr
                    self.config = config

                async def run(self, context: dict) -> dict:
                    # Simple decision: if it's the first phase, run recon; else move to next phase
                    phase = context.get("phase", "recon")
                    if phase == "recon":
                        return {"next_agent": "recon", "reasoning": "Starting recon phase"}
                    elif phase == "exploit":
                        return {"next_agent": "exploit", "reasoning": "Moving to exploit"}
                    elif phase == "post_exploit":
                        return {"next_agent": "post_exploit", "reasoning": "Moving to post-exploit"}
                    else:
                        return {"next_agent": "reporter", "reasoning": "Generating report"}
            OrchestratorAgent = PlaceholderOrchestrator

        # Try importing llm_gateway module
        try:
            llm_gateway_module = importlib.import_module("llm_gateway")
            OllamaGateway = getattr(llm_gateway_module, "OllamaGateway")
        except (ImportError, AttributeError) as e:
            logger.warning(f"OllamaGateway not found ({e}), using fallback from phalanx_tools")
            from phalanx_tools import Gateway as FallbackGateway
            # Create a lambda that returns a Gateway instance
            OllamaGateway = lambda cfg: FallbackGateway(cfg, TOOL_REGISTRY)

        return OrchestratorAgent, OllamaGateway
    except Exception as e:
        logger.error(f"Unexpected error loading agent components: {e}")
        # Final fallback: use placeholder and fallback gateway
        class FallbackPlaceholder:
            def __init__(self, name, gateway, db, soul, skill_mgr, config=None):
                self.name = name
                self.gateway = gateway
                self.db = db
                self.soul = soul
                self.skill_mgr = skill_mgr
                self.config = config
            async def run(self, context):
                return {"next_agent": "recon", "reasoning": "fallback placeholder"}
        from phalanx_tools import Gateway as FallbackGateway
        return FallbackPlaceholder, lambda cfg: FallbackGateway(cfg, TOOL_REGISTRY)

def run_agentic(target: str, config: dict, soul: Soul, skill_mgr: SkillManager,
                db: PhalanxDB, executor: ToolExecutor, gateway: Gateway,
                guardrail: bool = True, enable_shadow_graph: bool = False,
                windows: bool = False):
    # Validate target first
    if not is_valid_network_target(target):
        console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
        return

    console.print(f"[bold cyan]Starting AGENTIC mode against {target}...[/bold cyan]")
    if guardrail:
        console.print("[yellow]Guardrail ENABLED – exploit actions will require human confirmation.[/yellow]")
    else:
        console.print("[dim]Guardrail DISABLED – all actions will proceed automatically.[/dim]")
    if enable_shadow_graph:
        console.print("[cyan]Shadow Graph ENABLED – tracking relationships and loot.[/cyan]")
    if windows and WINSTEALTH_AVAILABLE:
        console.print("[cyan]Windows target – WinStealth low‑level evasion available.[/cyan]")
    elif windows and not WINSTEALTH_AVAILABLE:
        console.print("[yellow]Windows flag set but WinStealth not available – falling back to standard tools.[/yellow]")

    OrchestratorAgent, OllamaGateway = _load_agent_components(config)
    if not OrchestratorAgent or not OllamaGateway:
        console.print("[red]Agentic mode requires agent components. Run 'python phalanx_extra.py --force' first.[/red]")
        return

    try:
        llm_gateway = OllamaGateway(config)
        orchestrator = OrchestratorAgent("orchestrator", llm_gateway, db, soul, skill_mgr)

        react_steps = []
        def progress_with_table(msg: str):
            if "[Orchestrator]" in msg:
                react_steps.append({"time": datetime.now().strftime("%H:%M:%S"), "message": msg})
                if len(react_steps) % 3 == 0:
                    table = Table(title="ReAct Cycle (last steps)", box=ROUNDED)
                    table.add_column("Time", style="dim")
                    table.add_column("Event", style="cyan")
                    for step in react_steps[-5:]:
                        table.add_row(step["time"], step["message"][:60])
                    console.print(table)
            else:
                console.print(f"  [dim]{msg}[/dim]")

        ap = AutonomousPentest(
            config=config, db=db, soul=soul, skill_mgr=skill_mgr,
            executor=executor, progress_cb=progress_with_table,
            gateway=gateway, orchestrator=orchestrator
        )
        if guardrail:
            # Use Rich Confirm when available, fallback to input
            if RICH_CONFIRM_AVAILABLE and Confirm:
                ap.roe_enforcer.confirm_callback = lambda prompt, details: Confirm.ask(f"\n⚠️  {prompt}")
            else:
                ap.roe_enforcer.confirm_callback = lambda prompt, details: input(f"\n⚠️  {prompt}\nConfirm? (y/N): ").strip().lower() == "y"

        if enable_shadow_graph:
            campaign_id = f"agentic_{target}_{int(time.time())}"
            db.create_swarm_campaign(campaign_id, target, mode="agentic")
            soul.campaign_id = campaign_id
            soul._load_graph_from_db()   # Force load existing graph edges

        # If windows flag is set and WinStealth available, we inject a WinStealth tool into the context
        # The orchestrator will decide when to use it based on the target OS.
        if windows and WINSTEALTH_AVAILABLE:
            # Pass a flag to orchestrator or store in soul for later use
            soul.state["windows_target"] = True
            soul.state["winstealth_available"] = True

        # user_input is empty string (not used in this context)
        report = ap.run(target, scan_type="full", user_input="")
        console.print_json(json.dumps(report, indent=2, default=str))
        console.print("[green]Agentic pentest completed.[/green]")
        if enable_shadow_graph and soul.campaign_id:
            console.print(f"[dim]Shadow Graph data saved under campaign: {soul.campaign_id}[/dim]")
    except Exception as e:
        console.print(f"[red]Agentic execution failed: {e}[/red]")

# ------------------------------------------------------------------
# Swarm helpers
# ------------------------------------------------------------------
def _get_ollama_models() -> List[str]:
    if not SWARM_AVAILABLE:
        return []
    return list_ollama_models()

def _get_default_model() -> str:
    """Return default model from environment or fallback, without prompting."""
    return os.environ.get("PHALANX_DEFAULT_MODEL", "qwen2.5:0.5b")

def _parse_swarm_args(arg_str: str, default_enable_graph: bool = False) -> Dict[str, Any]:
    if not arg_str.strip():
        return {"error": "Missing target. Usage: /swarm scan <target> or /swarm <target>"}
    args = shlex.split(arg_str)
    subcommands = ["scan", "campaign", "doctor", "models", "stop", "playbook"]
    first = args[0].lower()
    if first in subcommands:
        subcmd = first
        rest = args[1:]
    else:
        subcmd = "scan"
        rest = args

    # Default for Raptor: enable for 'ctf' and 'manual' modes if not explicitly set
    use_raptor = None  # None means auto-detect based on mode later

    if subcmd == "scan":
        if not rest:
            return {"error": "Usage: swarm scan <target> [--scope SCOPE] [--mode MODE] [--follow] [--graph] [--raptor|--no-raptor]"}
        target = rest[0]
        target = target.replace("http://", "").replace("https://", "").split("/")[0]
        scope = None
        mode = "manual"
        follow = False
        enable_graph = default_enable_graph  # Use default if not specified
        i = 1
        while i < len(rest):
            if rest[i] == "--scope" and i+1 < len(rest):
                scope = rest[i+1]
                i += 2
            elif rest[i] == "--mode" and i+1 < len(rest):
                mode = rest[i+1]
                i += 2
            elif rest[i] == "--follow":
                follow = True
                i += 1
            elif rest[i] == "--graph" or rest[i] == "--shadow":
                enable_graph = True
                i += 1
            elif rest[i] == "--raptor":
                use_raptor = True
                i += 1
            elif rest[i] == "--no-raptor":
                use_raptor = False
                i += 1
            else:
                i += 1
        return {"subcmd": "scan", "target": target, "scope": scope, "mode": mode, "follow": follow, "enable_graph": enable_graph, "use_raptor": use_raptor}
    elif subcmd == "campaign":
        if len(rest) < 2:
            return {"error": "Usage: swarm campaign watch|explore <campaign-id>"}
        action = rest[0].lower()
        cid = rest[1]
        return {"subcmd": "campaign", "action": action, "campaign_id": cid}
    elif subcmd == "doctor":
        return {"subcmd": "doctor"}
    elif subcmd == "models":
        if len(rest) >= 1 and rest[0] == "list":
            return {"subcmd": "models_list"}
        else:
            return {"error": "Usage: swarm models list"}
    elif subcmd == "stop":
        if len(rest) < 1:
            return {"error": "Usage: swarm stop <campaign-id>"}
        return {"subcmd": "stop", "campaign_id": rest[0]}
    elif subcmd == "playbook":
        if len(rest) < 2 or rest[0] != "run":
            return {"error": "Usage: swarm playbook run <yaml-file>"}
        return {"subcmd": "playbook", "playbook_file": rest[1]}
    else:
        return {"error": f"Unknown swarm subcommand: {subcmd}"}

def _run_swarm_scan(repl, target: str, scope: Optional[str], mode: str, follow: bool, model: str, enable_graph: bool, use_raptor: Optional[bool]):
    if not is_valid_network_target(target):
        console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
        return

    # If use_raptor is not explicitly set, enable it for 'ctf' or 'manual' modes
    if use_raptor is None:
        use_raptor = mode in ("ctf", "manual")
        if use_raptor:
            console.print("[dim]Raptor reasoning engine enabled by default for this mode.[/dim]")

    console.print(f"[bold cyan]Starting swarm scan against {target}[/bold cyan]")
    console.print(f"  Model: {model}, Mode: {mode}, Follow: {follow}, Shadow Graph: {enable_graph}, Raptor: {use_raptor}")
    if scope:
        console.print(f"  Scope: {scope}")
    if follow:
        def progress_cb(msg: str):
            console.print(f"[dim]{msg}[/dim]")
        try:
            result = run_swarm(
                target=target, scope=scope, mode=mode, model=model,
                follow=follow, progress_callback=progress_cb,
                db=repl.db, soul=repl.soul, skill_mgr=repl.skill_mgr, gateway=repl.gateway,
                enable_hierarchical=True,
                enable_shadow_graph=enable_graph,
                use_raptor=use_raptor
            )
            console.print("[green]Swarm scan completed.[/green]")
            console.print_json(json.dumps(result, indent=2, default=str))
        except Exception as e:
            console.print(f"[red]Swarm scan failed: {e}[/red]")
    else:
        try:
            campaign_id = run_swarm(
                target=target, scope=scope, mode=mode, model=model,
                follow=False, progress_callback=None,
                db=repl.db, soul=repl.soul, skill_mgr=repl.skill_mgr, gateway=repl.gateway,
                enable_hierarchical=True,
                enable_shadow_graph=enable_graph,
                use_raptor=use_raptor
            )
            console.print(f"[green]Swarm campaign started with ID: {campaign_id}[/green]")
            console.print("Use '/swarm campaign watch <id>' to monitor.")
        except Exception as e:
            console.print(f"[red]Failed to start swarm: {e}[/red]")

# ------------------------------------------------------------------
# REPL (cmd.Cmd) – with helper methods and guards
# ------------------------------------------------------------------
class PhalanxREPL(cmd.Cmd):
    intro = """
PHALANX v3.6 – Autonomous Pentesting Framework (T3MP3ST + OGhidra Enhanced)
Type 'help' for commands, 'exit' to quit.
"""
    prompt = "phalanx> "

    def __init__(self, soul: Soul, skill_mgr: SkillManager, gateway: Gateway,
                 executor: ToolExecutor, db: PhalanxDB, config: dict, looped_harness=None,
                 default_enable_graph: bool = False, defense_monitor=None,
                 warroom_thread: Optional[threading.Thread] = None):
        super().__init__()
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.gateway = gateway
        self.executor = executor
        self.db = db
        self.config = config
        self.current_session_id = None
        self.looped_harness = looped_harness  # PhalanxLoopedHarness instance
        self.default_enable_graph = default_enable_graph
        self._defense_monitor = defense_monitor  # may be None if not started
        self._warroom_thread = warroom_thread
        self._current_binary = None  # For reverse commands

    def default(self, line):
        """
        Default handler for commands not starting with '/'.
        Supports running any registered tool with natural syntax.
        Examples:
            nmap 192.168.1.1 -sV
            nmap target=192.168.1.1 options=-sV
            searchsploit vsftpd
        """
        if line.startswith('/'):
            return self.onecmd(line[1:])

        parts = shlex.split(line)
        if not parts:
            return False

        tool_name = parts[0]
        if tool_name not in TOOL_REGISTRY:
            print(f"*** Unknown command or tool: {tool_name}")
            return False

        # Get function signature for parameter mapping
        fn = TOOL_REGISTRY[tool_name]["fn"]
        sig = inspect.signature(fn)
        # Determine the primary positional parameter name (first non-config, non-self)
        primary_param = None
        for p in sig.parameters:
            if p not in ('self', 'config', 'timeout', 'kwargs', 'args'):
                primary_param = p
                break
        if primary_param is None:
            primary_param = 'target'  # fallback

        # Check for --help or -h
        if any(arg in ("--help", "-h") for arg in parts[1:]):
            # For tools with a target parameter, we can pass --help as target (works for nmap, etc.)
            if 'target' in sig.parameters or primary_param == 'target':
                try:
                    result = run_tool(tool_name, config=self.config, target="--help")
                    # Guard against None
                    if result is None:
                        result = {}
                    console.print(result.get("output", "No help output"))
                except Exception as e:
                    console.print(f"[red]Help not available: {e}[/red]")
            else:
                # For tools like searchsploit, show description
                desc = TOOL_REGISTRY[tool_name].get("desc", "")
                console.print(f"[cyan]{tool_name}: {desc}[/cyan]")
                console.print("[yellow]Help not implemented for this tool in the REPL. Run the tool with '--help' directly if supported.[/yellow]")
            return True

        # Build kwargs from arguments
        kwargs = {}
        target = None
        options_parts = []

        for arg in parts[1:]:
            # Flags (starting with -) are always options, except --help handled above
            if arg.startswith('-'):
                options_parts.append(arg)
            elif '=' in arg:
                k, v = arg.split('=', 1)
                kwargs[k] = v
            else:
                # Positional argument: first one becomes the primary parameter
                if target is None:
                    target = arg
                else:
                    options_parts.append(arg)

        # If target not set via positional, maybe it's already in kwargs (key=value)
        if target is not None and primary_param not in kwargs:
            kwargs[primary_param] = target

        # Combine options parts into an options string if any
        if options_parts:
            # Check if the tool accepts an 'options' parameter
            if 'options' in sig.parameters:
                kwargs['options'] = ' '.join(options_parts)
            else:
                # If not, we might pass them as a generic 'args' list? Better to warn.
                console.print(f"[yellow]Extra arguments ignored: {' '.join(options_parts)}[/yellow]")

        # Run the tool
        try:
            result = run_tool(tool_name, config=self.config, **kwargs)
            # Guard against None result
            if result is None:
                result = {}
            # Pretty-print the result
            if result.get("rc", -1) == 0:
                # If there's a structured parsed output, show it nicely
                if "parsed_structured" in result:
                    parsed = result["parsed_structured"]
                    if "findings" in parsed:
                        # Render findings as table
                        findings = parsed.get("findings", [])
                        if findings and isinstance(findings, list) and len(findings) > 0:
                            if isinstance(findings[0], dict):
                                table = Table(title=f"{tool_name} Findings", box=ROUNDED)
                                # Dynamically create columns based on first finding
                                for key in findings[0].keys():
                                    table.add_column(key, style="cyan")
                                for f in findings[:20]:
                                    table.add_row(*[str(f.get(k, ""))[:40] for k in findings[0].keys()])
                                console.print(table)
                            else:
                                # findings is a list of strings
                                console.print("[green]Findings:[/green]")
                                for item in findings[:20]:
                                    console.print(f"  - {item}")
                        else:
                            console.print("[green]No findings.[/green]")
                    elif "open_ports" in parsed:
                        # nmap style
                        ports = parsed.get("open_ports", [])
                        if ports:
                            console.print(f"[green]Open ports: {', '.join(ports)}[/green]")
                        else:
                            console.print("[yellow]No open ports found.[/yellow]")
                    else:
                        # Just print the parsed output
                        console.print_json(json.dumps(parsed, indent=2))
                else:
                    # Just show summary and output
                    summary = result.get("summary", result.get("output", ""))
                    if summary:
                        console.print(f"[green]{summary[:200]}[/green]")
                    else:
                        console.print("[green]Tool completed successfully.[/green]")
            else:
                error = result.get("error", "Unknown error")
                console.print(f"[red]Error: {error}[/red]")
                if result.get("output"):
                    console.print(result["output"][:500])
        except Exception as e:
            console.print(f"[red]Error running tool {tool_name}: {e}[/red]")
        return True

    def emptyline(self):
        pass

    # ------------------------------------------------------------------
    # Command implementations
    # ------------------------------------------------------------------
    def do_defense(self, arg: str):
        """LavaWall active defense mode.
        Usage:
            /defense start|stop|status|standby on|off|self-test
            /defense wifi scan [interface]
            /defense vpn on|off
            /defense metrics
            /defense firewall
            /defense config set <key> <value>
            /defense dashboard              # Open War Room in browser
        """
        if not DEFENSE_AVAILABLE:
            console.print("[red]Defense module not available. Re-run bootstrap.[/red]")
            return

        args = shlex.split(arg) if arg else []

        # Check for the 'dashboard' subcommand first
        if args and args[0] == "dashboard":
            url = "http://localhost:3333"
            console.print(f"[green]Opening War Room at {url}...[/green]")
            webbrowser.open(url)
            return

        # For other subcommands, initialize the monitor if needed
        if self._defense_monitor is None:
            if not DEFENSE_AVAILABLE:
                console.print("[red]Defense module not available.[/red]")
                return
            self._defense_monitor = NetWatchMonitor(
                gateway=self.gateway,
                soul=self.soul,
                db=self.db,
                config=self.config
            )

        result = run_defense_cli(args, self._defense_monitor)
        console.print(result)

    def do_test(self, arg):
        """Run system health check including environment checks. Usage: /test"""
        # First run standard library health check
        try:
            result = run_health_check(self.config)
            console.print(Panel(f"Health Score: {result.get('score', 0)}/100", title="System Health", border_style="green"))
            for c in result.get("checks", []):
                status = "✓" if c.get("passed") else "✗"
                console.print(f"  {status} {c.get('name')}")
        except Exception as e:
            console.print(f"[red]Standard health check failed: {e}[/red]")

        # Now run our environment checks
        console.print("\n[bold cyan]Environment Checks:[/bold cyan]")
        env = check_environment(self.config)
        if env["errors"]:
            console.print("[red]Errors:[/red]")
            for err in env["errors"]:
                console.print(f"  ✗ {err}")
        if env["warnings"]:
            console.print("[yellow]Warnings:[/yellow]")
            for warn in env["warnings"]:
                console.print(f"  ⚠ {warn}")
        if not env["errors"] and not env["warnings"]:
            console.print("[green]✓ All environment checks passed.[/green]")
        console.print(f"Environment score: {env['score']}/100")

    def do_wp(self, arg):
        """WordPress scanner. Usage: /wp <url>"""
        if not arg:
            console.print("[red]Usage: /wp <url>[/red]")
            return
        url = arg.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        console.print(f"[bold cyan]Scanning WordPress at {url}...[/bold cyan]")
        try:
            result = run_tool("wp_scanner", config=self.config, target=url)
            if result is None:
                result = {}
            if result.get("error"):
                console.print(f"[red]Error: {result['error']}[/red]")
            else:
                console.print_json(json.dumps(result, indent=2))
        except Exception as e:
            console.print(f"[red]WP scan failed: {e}[/red]")

    def do_loot(self, arg: str):
        """List structured loot (credentials, vulnerabilities, artifacts). Usage: /loot [category]"""
        args = shlex.split(arg) if arg else []
        category = args[0] if args else None
        campaign_id = args[1] if len(args) > 1 else None
        if campaign_id:
            loot_items = self.db.get_loot_by_category(category, campaign_id=campaign_id) if category else self.db.get_loot(campaign_id=campaign_id)
        else:
            loot_items = self.db.get_loot_by_category(category) if category else self.db.get_loot(limit=50)
        if not loot_items:
            console.print("[yellow]No loot found.[/yellow]")
            return
        console.print(render_loot_table(loot_items, category))

    def do_graph(self, arg: str):
        """Query the Shadow Graph. Usage: /graph query <natural language question> or /graph summary"""
        if not arg:
            console.print("[red]Usage: /graph query <natural language question> or /graph summary[/red]")
            return
        args = shlex.split(arg)
        subcmd = args[0].lower()
        if subcmd == "query" and len(args) > 1:
            query_str = " ".join(args[1:])
            if not hasattr(self.soul, "query_graph"):
                console.print("[red]Shadow Graph not enabled. Use --graph flag when starting.[/red]")
                return
            result = self.soul.query_graph(query_str)
            console.print(Panel(result, title="Graph Query Result", border_style="cyan"))
        elif subcmd == "summary":
            if not hasattr(self.soul, "graph_summary"):
                console.print("[red]Shadow Graph not enabled. Use --graph flag when starting.[/red]")
                return
            summary = self.soul.graph_summary()
            table = Table(title="Shadow Graph Summary", box=ROUNDED)
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="white")
            table.add_row("Total Nodes", str(summary["total_nodes"]))
            table.add_row("Total Edges", str(summary["total_edges"]))
            for typ, count in summary["node_types"].items():
                table.add_row(f"Nodes ({typ})", str(count))
            console.print(table)
        else:
            console.print("[red]Usage: /graph query <question> or /graph summary[/red]")

    def do_spawn(self, arg: str):
        """Manually spawn a hierarchical sub-swarm for testing. Usage: /spawn <phase> [target]"""
        if not SWARM_AVAILABLE:
            console.print("[red]Swarm not available.[/red]")
            return
        args = shlex.split(arg) if arg else []
        if not args:
            console.print("[red]Usage: /spawn <phase> [target] (phase: recon, classify, exploit)[/red]")
            return
        phase = args[0].lower()
        target = args[1] if len(args) > 1 else self.current_session_id or "localhost"
        if phase not in ["recon", "classify", "exploit"]:
            console.print("[red]Phase must be one of: recon, classify, exploit[/red]")
            return
        try:
            from phalanx_library import SubSwarmOrchestrator
            sub = SubSwarmOrchestrator(
                target=target,
                phase=phase,
                context={"target": target, "recon_findings": {}, "validated_vulnerabilities": []},
                parent=None,
                max_steps=8
            )
            async def run_sub():
                return await sub.run()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(run_sub())
            loop.close()
            console.print_json(json.dumps(result, indent=2))
            console.print(f"[green]Sub-swarm for phase '{phase}' completed.[/green]")
        except ImportError:
            console.print("[red]SubSwarmOrchestrator not available. Ensure phalanx_library is up to date.[/red]")
        except Exception as e:
            console.print(f"[red]Spawn failed: {e}[/red]")

    # ------------------------------------------------------------------
    # LOOP command (enhanced with altitude)
    # ------------------------------------------------------------------
    def do_loop(self, arg: str):
        """Toggle Mythos-style looped recurrent refinement harness.
        Usage: /loop start [target] [--altitude whole|file|feature|function]
               /loop stop
        If no target specified, uses current session target or localhost.
        """
        if self.looped_harness is None:
            console.print("[red]Looped harness not available. Check config or PyTorch installation.[/red]")
            return
        args = shlex.split(arg)
        subcmd = args[0].lower() if args else "start"
        target = None
        altitude = "whole"

        # Parse optional arguments
        i = 1
        while i < len(args):
            if args[i] == "--altitude" and i+1 < len(args):
                altitude = args[i+1]
                if altitude not in ("whole", "file", "feature", "function"):
                    console.print("[yellow]Altitude must be one of: whole, file, feature, function. Using 'whole'.[/yellow]")
                    altitude = "whole"
                i += 2
            else:
                if target is None:
                    target = args[i]
                i += 1

        if target is None:
            target = "current"
        # Resolve "current" target from active session if possible
        if target == "current":
            if self.current_session_id:
                sess = self.db.get_session(self.current_session_id)
                if sess:
                    target = sess["target"]
                else:
                    console.print("[yellow]No current session target; using 'localhost' as fallback.[/yellow]")
                    target = "localhost"
            else:
                console.print("[yellow]No active session; using 'localhost' as target.[/yellow]")
                target = "localhost"

        if subcmd == "start":
            if hasattr(self.looped_harness, 'start'):
                # Store altitude in the harness if it has a method; we'll just pass it as context
                console.print(f"[dim]Starting looped harness on target '{target}' with altitude '{altitude}'[/dim]")
                self.looped_harness.start(target)
                # We can store the altitude in the harness's state if needed
                if hasattr(self.looped_harness, 'altitude'):
                    self.looped_harness.altitude = altitude
                console.print("[green]Looped harness started.[/green]")
            else:
                console.print("[red]Looped harness has no 'start' method.[/red]")
        elif subcmd in ("stop", "off"):
            if hasattr(self.looped_harness, 'stop'):
                self.looped_harness.stop()
                console.print("[yellow]Looped harness stopped.[/yellow]")
            else:
                console.print("[red]Looped harness has no 'stop' method.[/red]")
        else:
            console.print("Usage: /loop start [target] [--altitude whole|file|feature|function] | /loop stop")

    # ------------------------------------------------------------------
    # SHELL command – execute arbitrary shell commands (dangerous, opt-in)
    # ------------------------------------------------------------------
    def do_shell(self, arg: str):
        """Execute a shell command. Usage: /shell <command>
        This is a dangerous command and requires PHALANX_ALLOW_DANGEROUS=1 or config allow_dangerous=True.
        """
        if not arg:
            console.print("[red]Usage: /shell <command>[/red]")
            return
        # Check if the shell tool is available and allowed
        if "shell" not in TOOL_REGISTRY:
            console.print("[red]Shell tool not registered. Run bootstrap to install.[/red]")
            return
        # Check opt-in status: the run_tool function will handle the check.
        result = run_tool("shell", config=self.config, command=arg)
        if result is None:
            result = {}
        if result.get("rc", -1) == 0:
            console.print(result.get("output", ""))
        else:
            error = result.get("error", "Unknown error")
            console.print(f"[red]Error: {error}[/red]")
            if result.get("output"):
                console.print(result["output"][:500])

    # ------------------------------------------------------------------
    # Existing commands (unchanged)
    # ------------------------------------------------------------------
    def do_finding(self, arg: str):
        """List unified findings from current session or all sessions."""
        limit = 20
        if arg.isdigit():
            limit = int(arg)
        findings = self.db.get_findings(limit)
        if not findings:
            console.print("[yellow]No findings recorded.[/yellow]")
            return
        console.print(render_findings_table(findings, f"Recent Findings (last {len(findings)})"))

    def do_reflect(self, arg: str):
        """Trigger LLM reflection on current session."""
        sessions = self.db.list_sessions(1)
        if not sessions:
            console.print("[red]No active session. Run a scan first.[/red]")
            return
        sid = sessions[0]["session_id"]
        findings = self.db.get_findings(limit=10)
        if not findings:
            console.print("[yellow]No findings to reflect on.[/yellow]")
            return
        console.print("[bold cyan]Reflecting on session...[/bold cyan]")
        reflection = self.soul.reflect_on_phase("review", findings)
        table = Table(title=f"Reflection for Session {sid[:8]}", box=ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Confidence", f"{reflection.get('confidence', 0):.2f}")
        table.add_row("Key Evidence", reflection.get("key_evidence", "N/A")[:80])
        table.add_row("Suggestion", reflection.get("suggestion", "continue"))
        table.add_row("Next Phase", reflection.get("next_phase", "unknown"))
        console.print(table)

    def do_resume(self, arg: str):
        """Resume a previous session or swarm campaign: /resume <session_id> or <campaign_id>"""
        if not arg:
            console.print("[red]Usage: /resume <session_id> or <campaign_id>[/red]")
            return
        sess = self.db.get_session(arg)
        if sess:
            self.current_session_id = arg
            console.print(f"[green]Resumed session {arg} (target: {sess['target']})[/green]")
            console.print("[yellow]Resume functionality: use /scan to continue or /report to see results.[/yellow]")
            return
        if SWARM_AVAILABLE:
            status = get_swarm_campaign_status(arg)
            if status:
                console.print(f"[green]Swarm campaign {arg} status: {status.get('status', 'unknown')}[/green]")
                if status.get("report_path"):
                    console.print(f"Report: {status['report_path']}")
                return
        console.print(f"[red]No session or campaign found with id {arg}[/red]")

    def do_sourcehunt(self, arg: str):
        """Run SourceHunt mode on a directory: /sourcehunt <directory>"""
        if not arg:
            console.print("[red]Usage: /sourcehunt <directory>[/red]")
            return
        dir_path = Path(arg).expanduser()
        if not dir_path.exists() or not dir_path.is_dir():
            console.print(f"[red]Directory not found: {arg}[/red]")
            return
        console.print(f"[bold cyan]SourceHunt scanning {dir_path}...[/bold cyan]")
        extensions = [".py", ".js", ".go", ".rs", ".c", ".cpp", ".java", ".rb", ".sh"]
        files = []
        for ext in extensions:
            files.extend(dir_path.rglob(f"*{ext}"))
        console.print(f"Found {len(files)} source files.")
        secrets = []
        for f in files[:20]:
            try:
                content = f.read_text(errors="ignore")
                if "password" in content.lower() or "api_key" in content.lower() or "secret" in content.lower():
                    secrets.append(f.name)
            except:
                pass
        if secrets:
            console.print("[yellow]Potential secrets found in:[/yellow]")
            for s in secrets:
                console.print(f"  - {s}")
        else:
            console.print("[green]No obvious hardcoded secrets detected.[/green]")
        binaries = list(dir_path.rglob("*.bin")) + list(dir_path.rglob("*.exe")) + list(dir_path.rglob("*.elf"))
        if binaries:
            console.print(f"[cyan]Found {len(binaries)} binary files. Use /ghidra <path> to analyze.[/cyan]")

    def do_xss(self, arg: str):
        """Show XSS-to-escalation patterns from real bounties."""
        patterns = Table(title="XSS Escalation Patterns", box=ROUNDED)
        patterns.add_column("Technique", style="cyan")
        patterns.add_column("Description", style="white")
        patterns.add_column("Impact")
        patterns.add_row("Session Token Leakage", "Extract cookies via document.cookie or fetch()", "Account takeover")
        patterns.add_row("DOM Clobbering", "Overwrite JavaScript variables/objects", "Client-side RCE")
        patterns.add_row("Prototype Pollution", "Modify Object.prototype", "Cross-site scripting, DoS")
        patterns.add_row("CSP Bypass", "Unicode, case variation, tag filtering evasion", "Execute arbitrary JS")
        patterns.add_row("HTTP Smuggling", "Desync to poison cache or bypass CSP", "Global XSS")
        patterns.add_row("Admin Injection", "Inject into admin interface via POST/JSON", "Privilege escalation")
        patterns.add_row("PostMessage Exploitation", "Listener injection, origin validation bypass", "Data leakage")
        patterns.add_row("AngularJS Sandbox Escape", "Older Angular versions", "Full page takeover")
        console.print(patterns)
        console.print("\n[bold green]Next Steps:[/bold green]")
        console.print("1. Test for session token exfiltration using [dim]/scrape[/dim] with custom payload")
        console.print("2. Attempt CSP bypass via [dim]/?search=<script>alert(1)</script>[/dim]")
        console.print("3. Chain XSS with CSRF to change user email/password")
        console.print("4. Use [dim]/graph[/dim] to see if XSS leads to high-value targets")

    def do_swarm(self, arg: str):
        if not SWARM_AVAILABLE:
            console.print("[red]Swarm not available. Run 'python phalanx_extra.py' to install required components.[/red]")
            return
        parsed = _parse_swarm_args(arg, default_enable_graph=self.default_enable_graph)
        if "error" in parsed:
            console.print(f"[red]{parsed['error']}[/red]")
            return
        subcmd = parsed.get("subcmd")
        if subcmd == "scan":
            # Automatically determine model from environment (no interactive prompt)
            model = _get_default_model()
            console.print(f"[dim]Using model: {model} (from PHALANX_DEFAULT_MODEL)[/dim]")
            models_local = _get_ollama_models()
            if model not in models_local:
                console.print(f"[yellow]Model {model} not found locally. Pulling...[/yellow]")
                if pull_ollama_model(model):
                    console.print(f"[green]Model {model} pulled successfully.[/green]")
                else:
                    console.print(f"[red]Failed to pull {model}. Using fallback default.[/red]")
                    model = "qwen2.5:0.5b"
            _run_swarm_scan(
                self,
                target=parsed["target"],
                scope=parsed.get("scope"),
                mode=parsed.get("mode", "manual"),
                follow=parsed.get("follow", False),
                model=model,
                enable_graph=parsed.get("enable_graph", self.default_enable_graph),
                use_raptor=parsed.get("use_raptor")  # May be None, will be auto-decided in _run_swarm_scan
            )
        elif subcmd == "campaign":
            action = parsed["action"]
            cid = parsed["campaign_id"]
            if action == "watch":
                console.print(f"[cyan]Watching campaign {cid}... Press Ctrl+C to stop.[/cyan]")
                try:
                    while True:
                        status = get_swarm_campaign_status(cid)
                        if not status:
                            console.print("[red]Campaign not found.[/red]")
                            break
                        console.clear()
                        console.print(Panel(f"Campaign {cid} – Status: {status.get('status', 'unknown')}", border_style="cyan"))
                        logs = status.get("recent_logs", [])
                        if logs:
                            table = Table(title="Recent Agent Actions", box=ROUNDED)
                            table.add_column("Time", style="dim")
                            table.add_column("Agent", style="green")
                            table.add_column("Step", style="dim")
                            table.add_column("Summary", style="white")
                            for log in logs[-15:]:
                                table.add_row(log.get("ts", "")[11:19], log.get("agent", "?"), str(log.get("step", "")), log.get("summary", "")[:80])
                            console.print(table)
                        else:
                            console.print("[dim]No logs yet. Check back soon.[/dim]")
                        if status.get("status") in ("completed", "stopped"):
                            console.print("[green]Campaign finished.[/green]")
                            break
                        time.sleep(3)
                except KeyboardInterrupt:
                    console.print("\n[dim]Stopped watching.[/dim]")
            else:
                console.print(f"[red]Unknown campaign action: {action}[/red]")
        elif subcmd == "doctor":
            console.print("[bold cyan]Swarm Doctor – System Check[/bold cyan]")
            try:
                result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    console.print("[green]✓ Ollama is running.[/green]")
                    models = _get_ollama_models()
                    console.print(f"  Models available: {', '.join(models) if models else 'none'}")
                else:
                    console.print("[red]✗ Ollama not responding. Run 'ollama serve'.[/red]")
            except FileNotFoundError:
                console.print("[red]✗ Ollama not installed. See https://ollama.com[/red]")
            required_tools = ["subfinder", "httpx", "nuclei", "naabu", "katana", "dnsx", "gau"]
            for tool in required_tools:
                if shutil.which(tool):
                    console.print(f"[green]✓ {tool}[/green]")
                else:
                    console.print(f"[yellow]✗ {tool} not found in PATH.[/yellow]")
        elif subcmd == "models_list":
            models = _get_ollama_models()
            if models:
                console.print("[green]Local Ollama models:[/green]")
                for m in models:
                    console.print(f"  - {m}")
            else:
                console.print("[yellow]No models found. Pull one with 'ollama pull <model>'[/yellow]")
        elif subcmd == "stop":
            cid = parsed["campaign_id"]
            if stop_swarm_campaign(cid):
                console.print(f"[green]Campaign {cid} stopped.[/green]")
            else:
                console.print(f"[red]Failed to stop campaign {cid} (not found or already finished).[/red]")
        elif subcmd == "playbook":
            console.print("[yellow]Playbook execution not yet implemented.[/yellow]")
        else:
            console.print(f"[red]Unknown swarm subcommand.[/red]")

    # ------------------------------------------------------------------
    # WinStealth command (renamed from SindriKit)
    # ------------------------------------------------------------------
    def do_winstealth(self, arg):
        """WinStealth low‑level Windows evasion. Usage: winstealth <subcommand> ...
        Subcommands: profile, load, exec"""
        if not WINSTEALTH_AVAILABLE:
            console.print("[red]WinStealth not available.[/red]")
            return
        args = shlex.split(arg)
        if not args:
            console.print("Subcommands: profile, load, exec")
            return
        sub = args[0].lower()
        if sub == "profile":
            if len(args) > 1:
                # set profile: winstealth profile <name>
                profile = args[1]
                try:
                    wrapper = WinStealthWrapper()
                    with wrapper.context() as ctx:
                        if wrapper.set_profile(ctx, profile):
                            console.print(f"[green]Profile set to {profile}[/green]")
                        else:
                            console.print(f"[red]Failed to set profile[/red]")
                except Exception as e:
                    console.print(f"[red]{e}[/red]")
            else:
                try:
                    wrapper = WinStealthWrapper()
                    profiles = wrapper.list_profiles()
                    console.print("[cyan]Available profiles:[/cyan] " + ", ".join(profiles))
                except Exception as e:
                    console.print(f"[red]{e}[/red]")
        elif sub == "load":
            if len(args) < 2:
                console.print("Usage: winstealth load <pe_file> [profile]")
                return
            pe_path = args[1]
            profile = args[2] if len(args) > 2 else "Win32"
            try:
                with open(pe_path, "rb") as f:
                    pe_bytes = f.read()
                wrapper = WinStealthWrapper()
                result = wrapper.reflective_load_pe(pe_bytes, profile)
                if result["success"]:
                    console.print(f"[green]PE loaded reflectively with context {result['context']}[/green]")
                    # Clean up context
                    wrapper.destroy_context(result["context"])
                else:
                    console.print(f"[red]{result['error']}[/red]")
            except Exception as e:
                console.print(f"[red]{e}[/red]")
        elif sub == "exec":
            console.print("[yellow]Exec command not yet implemented.[/yellow]")
        else:
            console.print(f"Unknown subcommand: {sub}")

    # Keep /sindri as alias for backward compatibility
    def do_sindri(self, arg):
        """Alias for /winstealth (deprecated, use /winstealth)."""
        console.print("[yellow]The /sindri command is deprecated. Use /winstealth instead.[/yellow]")
        self.do_winstealth(arg)

    # ------------------------------------------------------------------
    # T3MP3ST + OGhidra new commands
    # ------------------------------------------------------------------
    def do_warroom(self, arg):
        """Open War Room in browser. Usage: /warroom [start|stop|open]"""
        args = shlex.split(arg) if arg else []
        subcmd = args[0].lower() if args else "open"

        if subcmd == "start":
            if self._warroom_thread is not None and self._warroom_thread.is_alive():
                console.print("[yellow]War Room already running[/yellow]")
                return
            if not WARROOM_AVAILABLE or start_warroom_server is None:
                console.print("[red]War Room not available (FastAPI/uvicorn missing).[/red]")
                return
            console.print("[*] Starting War Room server...")
            try:
                self._warroom_thread = start_warroom_server()
                if self._warroom_thread:
                    console.print("[green]War Room server started. Opening browser...[/green]")
                    webbrowser.open("http://localhost:3333")
                else:
                    console.print("[red]Failed to start War Room server (returned None).[/red]")
            except Exception as e:
                console.print(f"[red]Failed to start War Room server: {e}[/red]")
        elif subcmd == "stop":
            if self._warroom_thread and self._warroom_thread.is_alive():
                # Thread is daemon, can't be easily stopped; we just mark it
                console.print("[yellow]War Room server is daemonized. To stop, kill the process or exit PHALANX.[/yellow]")
            else:
                console.print("[yellow]War Room is not running.[/yellow]")
        else:  # open
            webbrowser.open("http://localhost:3333")
            console.print("[green]Opening War Room in browser...[/green]")

    def do_verify(self, arg):
        """Run verify-claims benchmark suite. Usage: /verify [suite]"""
        suite = arg.strip() or "basic"
        console.print(f"[bold cyan]Running verify-claims suite: {suite}[/bold cyan]")

        try:
            bench = Benchmark(self.db, self.config)
            results = bench.verify_claims(suite)

            table = Table(title=f"verify-claims Results ({suite})", box=ROUNDED)
            table.add_column("Test", style="cyan")
            table.add_column("Status", style="bold")
            table.add_column("Details", style="dim")

            for test in results.get("passed", []):
                table.add_row(test, "[green]✓ PASS[/green]", "")
            for test in results.get("failed", []):
                table.add_row(test["name"], "[red]✗ FAIL[/red]", test.get("diff", "")[:50])

            console.print(table)
            console.print(f"Score: {results.get('score', 0):.1f}%")
        except Exception as e:
            console.print(f"[red]verify-claims failed: {e}[/red]")

    def do_reverse(self, arg):
        """OGhidra-powered reverse engineering commands.
        Usage:
            /reverse load <binary>         - Load and analyze binary
            /reverse chat <query>          - Conversational analysis
            /reverse malware               - Run malware pattern detection
            /reverse rename                - Bulk smart renaming
            /reverse report                - Generate RE report
        """
        args = shlex.split(arg)
        if not args:
            console.print("[red]Usage: /reverse <subcommand>[/red]")
            return

        subcmd = args[0].lower()

        if subcmd == "load" and len(args) > 1:
            binary = args[1]
            # Expand user home and resolve path
            binary_path = Path(binary).expanduser().resolve()
            if not binary_path.exists():
                console.print(f"[red]Binary not found: {binary_path}[/red]")
                return
            self._current_binary = str(binary_path)
            console.print(f"[bold cyan]Loading {binary_path} into Ghidra with OGhidra...[/bold cyan]")
            result = run_tool("oghidra", config=self.config, binary_path=str(binary_path), task_mode="smart")
            if result is None:
                result = {}
            if result.get("rc") == 0:
                console.print("[green]Analysis complete.[/green]")
                parsed = result.get("parsed", {})
                console.print(f"  Functions analyzed: {parsed.get('functions_count', 0)}")
                console.print(f"  Malware patterns: {parsed.get('malware_detected', 0)}")
                self.soul.append_memory("REVERSE_LOAD", str(binary_path), json.dumps(parsed))
            else:
                console.print(f"[red]Failed: {result.get('error', 'Unknown error')}[/red]")

        elif subcmd == "chat" and len(args) > 1:
            query = " ".join(args[1:])
            binary = self._current_binary
            if not binary:
                console.print("[red]No binary loaded. Use '/reverse load <binary>' first.[/red]")
                return
            console.print(f"[bold cyan]Query: {query}[/bold cyan]")
            result = run_tool("oghidra_chat", config=self.config, query=query, binary_path=binary)
            if result is None:
                result = {}
            if result.get("rc") == 0:
                response = result.get("response", {})
                # If response is a dict, pretty print
                if isinstance(response, dict):
                    console.print(Panel(json.dumps(response, indent=2), title="OGhidra Response", border_style="cyan"))
                else:
                    console.print(Panel(str(response), title="OGhidra Response", border_style="cyan"))
                self.soul.append_memory("REVERSE_CHAT", query, json.dumps(result))
            else:
                console.print(f"[red]Failed: {result.get('error', 'Unknown error')}[/red]")

        elif subcmd == "malware":
            binary = self._current_binary
            if not binary:
                console.print("[red]No binary loaded. Use '/reverse load <binary>' first.[/red]")
                return
            console.print(f"[bold cyan]Running malware pattern detection on {binary}...[/bold cyan]")
            result = run_tool("oghidra", config=self.config, binary_path=binary, task_mode="malware")
            if result is None:
                result = {}
            if result.get("rc") == 0:
                parsed = result.get("parsed", {})
                findings = parsed.get("findings", [])
                if findings:
                    table = Table(title=f"Malware Patterns in {Path(binary).name}", box=ROUNDED)
                    table.add_column("Type", style="cyan")
                    table.add_column("Description", style="white")
                    table.add_column("MITRE", style="dim")
                    table.add_column("Severity", style="bold")
                    for f in findings[:20]:
                        table.add_row(f.get("type", "?"), f.get("description", "")[:60], f.get("mitre_id", ""), f.get("severity", "info"))
                    console.print(table)
                else:
                    console.print("[green]No malware patterns detected.[/green]")
            else:
                console.print(f"[red]Failed: {result.get('error', 'Unknown error')}[/red]")

        elif subcmd == "report":
            binary = self._current_binary
            if not binary:
                console.print("[red]No binary loaded. Use '/reverse load <binary>' first.[/red]")
                return
            console.print(f"[bold cyan]Generating reverse engineering report for {binary}...[/bold cyan]")
            # For now, reuse smart analysis and format output
            result = run_tool("oghidra", config=self.config, binary_path=binary, task_mode="full")
            if result is None:
                result = {}
            if result.get("rc") == 0:
                parsed = result.get("parsed", {})
                report = {
                    "binary": binary,
                    "timestamp": datetime.now().isoformat(),
                    "functions_count": parsed.get("functions_count", 0),
                    "malware_detected": parsed.get("malware_detected", 0),
                    "findings": parsed.get("findings", [])[:50],
                    "summary": parsed.get("summary", ""),
                    "recommendations": parsed.get("recommendations", [])
                }
                console.print_json(json.dumps(report, indent=2))
                # Save to file
                report_path = Path("phalanx/reports") / f"reverse_{Path(binary).stem}_{int(time.time())}.json"
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(json.dumps(report, indent=2))
                console.print(f"[green]Report saved to {report_path}[/green]")
            else:
                console.print(f"[red]Failed: {result.get('error', 'Unknown error')}[/red]")

        elif subcmd == "rename":
            console.print("[yellow]Bulk smart renaming not yet implemented.[/yellow]")

        else:
            console.print("[red]Unknown reverse subcommand. Use: load, chat, malware, rename, report[/red]")

    def do_status(self, arg):
        """Show PHALANX status table (T3MP3ST style). Usage: /status"""
        table = Table(title="PHALANX v3.6 Status", box=DOUBLE)
        table.add_column("Feature", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Notes", style="dim")

        # Core features
        warroom_status = "[green]✓[/green]" if (self._warroom_thread and self._warroom_thread.is_alive()) else "[yellow]⏸[/yellow]"
        table.add_row("War Room", warroom_status, "http://localhost:3333" if self._warroom_thread else "Not started")
        table.add_row("verify-claims", "[green]✓[/green]", "Benchmark suite")
        table.add_row("8-Operator Swarm", "[yellow]~[/yellow]", "In progress (T3MP3ST)")
        table.add_row("OGhidra Integration", "[green]✓[/green]", "AI-powered RE")
        table.add_row("Egress Scope", "[green]✓[/green]", "Active")
        lavawall_status = "[green]✓[/green]" if (self._defense_monitor and self._defense_monitor.running) else "[dim]✗[/dim]"
        table.add_row("LavaWall Defense", lavawall_status, "Active" if self._defense_monitor else "Inactive")
        winstealth_status = "[green]✓[/green]" if WINSTEALTH_AVAILABLE else "[dim]✗[/dim]"
        table.add_row("WinStealth", winstealth_status, "Windows evasion")
        # Added T3MP3ST features
        table.add_row("ReAct Tool Agent", "[green]✓[/green]", "Available")
        table.add_row("Hierarchical Swarm", "[green]✓[/green]", "Available")

        # Reasoning Engine (formerly Raptor Loop)
        if self.looped_harness is not None:
            running = hasattr(self.looped_harness, 'running') and self.looped_harness.running
            loop_status = "[green]Running[/green]" if running else "[dim]Stopped[/dim]"
            table.add_row("Reasoning Engine", loop_status, "Looped reasoning (Raptor)")
            # Disposition Ledger size (from loot count)
            loot_count = len(self.db.get_loot(limit=1000))
            table.add_row("Disposition Ledger", f"{loot_count} entries", "Structured loot")
        else:
            table.add_row("Reasoning Engine", "[dim]Not available[/dim]", "PyTorch missing")
            table.add_row("Disposition Ledger", "[dim]N/A[/dim]", "No active campaign")

        console.print(table)

    # ------------------------------------------------------------------
    # Existing commands (unchanged)
    # ------------------------------------------------------------------
    def do_agentic(self, arg):
        """Run agentic mode with optional guardrail, shadow graph, and Windows target.
        Usage: agentic <target> [--guardrail] [--graph] [--windows]"""
        args = shlex.split(arg)
        if not args:
            console.print("Usage: agentic <target> [--guardrail] [--graph] [--windows]")
            return
        target = args[0]
        guardrail = "--guardrail" in args
        enable_graph = "--graph" in args or "--shadow" in args or self.default_enable_graph
        windows = "--windows" in args
        run_agentic(target, self.config, self.soul, self.skill_mgr,
                    self.db, self.executor, self.gateway, guardrail,
                    enable_shadow_graph=enable_graph, windows=windows)

    def do_scan(self, arg):
        if not arg:
            console.print("Usage: scan <target>")
            return
        target = arg.strip()
        if not is_valid_network_target(target):
            console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
            return
        console.print(f"[*] Starting autonomous scan of {target}...")
        try:
            ap = AutonomousPentest(
                config=self.config, db=self.db, soul=self.soul,
                skill_mgr=self.skill_mgr, executor=self.executor,
                progress_cb=lambda msg: console.print(f"  {msg}"),
                gateway=self.gateway
            )
            report = ap.run(target, scan_type="full")
            console.print_json(json.dumps(report, indent=2, default=str))
        except Exception as e:
            console.print(f"[!] Scan failed: {e}")

    def do_plan(self, arg):
        if not arg:
            console.print("Usage: plan <target>")
            return
        target = arg.strip()
        if not is_valid_network_target(target):
            console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
            return
        plan = generate_engagement_plan(target, "", self.gateway)
        console.print_json(json.dumps(plan, indent=2, default=str))

    def do_objectives(self, arg):
        sid = arg if arg else None
        if not sid:
            sessions = self.db.list_sessions(1)
            if sessions:
                sid = sessions[0]["session_id"]
            else:
                console.print("No session found. Run 'scan' first.")
                return
        objectives = self.db.get_objectives(sid)
        if not objectives:
            console.print("No objectives for this session.")
            return
        t = Table(box=ROUNDED, title=f"Objectives for {sid[:8]}...")
        t.add_column("Description", style="white")
        t.add_column("Status", style="cyan")
        t.add_column("MITRE Tags", style="dim")
        t.add_column("Finished", style="dim")
        t.add_column("Evidence Guided", style="dim")
        for obj in objectives:
            status_color = "green" if obj["status"] == "passed" else ("red" if obj["status"] == "failed" else "yellow")
            t.add_row(
                obj["description"][:60],
                f"[{status_color}]{obj['status']}[/]",
                ", ".join(json.loads(obj["mitre_tags"])) if obj["mitre_tags"] else "",
                obj["finished_at"][:16] if obj["finished_at"] else "-",
                "✓" if obj.get("evidence_guided") else ""
            )
        console.print(t)

    def do_report(self, arg):
        sid = arg.strip() if arg else None
        if not sid:
            sessions = self.db.list_sessions(1)
            if sessions:
                sid = sessions[0]["session_id"]
            else:
                console.print("No session found.")
                return
        report = self.db.full_report(sid)
        console.print_json(json.dumps(report, indent=2, default=str))

    def do_agent(self, arg):
        if not arg:
            console.print("Usage: agent list|status|spawn <type>")
            return
        parts = arg.split()
        subcmd = parts[0].lower()
        if subcmd == "list":
            cur = self.db.conn.execute("SELECT id, status, last_seen, capabilities FROM agents ORDER BY last_seen DESC")
            agents = cur.fetchall()
            if not agents:
                console.print("No agents registered.")
                return
            t = Table(box=ROUNDED, title="Agent Registry")
            t.add_column("ID", style="bright_green")
            t.add_column("Status", style="cyan")
            t.add_column("Last Seen", style="dim")
            t.add_column("Capabilities")
            for a in agents:
                caps = json.loads(a[3]) if a[3] else []
                t.add_row(a[0][:12], a[1], a[2][:16] if a[2] else "-", ", ".join(caps[:3]))
            console.print(t)
        elif subcmd == "spawn":
            agent_type = parts[1] if len(parts) > 1 else "recon"
            agent_id = f"{agent_type}_{int(time.time())}"
            self.db.register_agent(agent_id, [agent_type])
            console.print(f"[+] Spawned agent {agent_id} with type {agent_type}")
        elif subcmd == "status":
            console.print("Multi‑agent orchestrator active. Agents: recon, exploit, post, report")
        else:
            console.print("Unknown agent subcommand. Use list, status, spawn.")

    def do_tools(self, arg):
        tools = list_tools()
        t = Table(box=ROUNDED, title="Available Tools")
        t.add_column("Tool", style="bright_green")
        t.add_column("Phase", style="cyan")
        t.add_column("MITRE", style="dim")
        t.add_column("Description")
        for tool in tools:
            meta = get_skill_metadata(tool["name"])
            phase = meta.get("phase", "?")
            mitre = ", ".join(meta.get("mitre", []))
            t.add_row(tool["name"], phase, mitre, tool["desc"])
        console.print(t)

    def do_skills(self, arg):
        skills = self.skill_mgr.list_skills()
        if not skills:
            console.print("No skills recorded yet.")
            return
        t = Table(box=ROUNDED, title="Skill Performance")
        t.add_column("Tool", style="bright_green")
        t.add_column("✓ Success", style="green")
        t.add_column("✗ Fail", style="red")
        t.add_column("Phase", style="cyan")
        t.add_column("MITRE")
        t.add_column("Last Used", style="dim")
        for s in skills:
            meta = get_skill_metadata(s["name"])
            phase = meta.get("phase", "?")
            mitre = ", ".join(meta.get("mitre", []))
            t.add_row(s["name"], str(s["success"]), str(s["fail"]), phase, mitre, s["last_used"])
        console.print(t)

    def do_soul(self, arg):
        if arg:
            results = self.soul.search_memory(arg)
        else:
            results = self.soul.recent_memory(20)
        if not results:
            console.print("No results found.")
            return
        for r in results:
            console.print(f"{r['ts']} [{r['type']}] {r.get('summary', r.get('content', ''))}")

    def do_history(self, arg):
        try:
            limit = int(arg) if arg else 10
        except ValueError:
            limit = 10
        sessions = self.db.list_sessions(limit)
        for s in sessions:
            status_color = "green" if s['status'] == 'completed' else "yellow"
            console.print(f"[dim]{s['started_at']}[/dim] [bold]{s['target']}[/bold] [{status_color}]{s['status']}[/] [dim]{s['session_id']}[/dim]")

    def do_demo(self, arg):
        console.print("[*] Running full demo (planning → recon → exploit → C2 → report)...")
        report = run_demo(self.config, self.soul, self.skill_mgr, self.db, self.executor, self.gateway)
        console.print_json(json.dumps(report, indent=2, default=str))

    def do_chat(self, arg):
        if not arg:
            console.print("Usage: chat <your prompt>")
            return
        console.print("Assistant: ", end="")
        for chunk in self.gateway.stream_generate(arg):
            piece = chunk.get("response", "")
            if piece:
                console.print(piece, end="")
            if chunk.get("done"):
                break
        console.print()

    def do_model(self, arg):
        if not arg:
            console.print(f"Current model: {self.gateway.default_model}, profile: {self.gateway.current_profile}")
            return
        if arg in ("eco", "max", "test"):
            self.gateway.set_profile(arg)
            console.print(f"LLM profile set to {arg}")
        else:
            self.gateway.set_model(arg)
            console.print(f"Model set to {arg}")

    def do_personality(self, arg):
        if not arg:
            console.print("Current personality: " + self.gateway.current_personality)
            return
        self.gateway.set_personality(arg)
        console.print(f"Personality set to '{arg}'")

    def do_sandbox(self, arg):
        new_state = not self.config.get("sandbox", {}).get("enabled", True)
        self.config["sandbox"]["enabled"] = new_state
        CONFIG_FILE.write_text(json.dumps(self.config, indent=2))
        console.print(f"Sandbox {'enabled' if new_state else 'disabled'}")

    def do_scrape(self, arg):
        if not arg:
            console.print("[red]Usage: scrape <url>[/red]")
            return
        target = arg.strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        console.print(f"[bold cyan]Scraping {target}...[/bold cyan]")
        result = run_tool("scrape", config=self.config, target=target)
        if result is None:
            result = {}
        if result.get("error"):
            console.print(f"[red]Error: {result['error']}[/red]")
        else:
            parsed = result.get("parsed", {})
            tbl = Table(title=f"Scrape results for {target}", box=ROUNDED)
            tbl.add_column("Key", style="cyan")
            tbl.add_column("Value", style="white")
            tbl.add_row("Title", parsed.get("title", "N/A"))
            tbl.add_row("Emails", ", ".join(parsed.get("emails", [])[:5]) or "None")
            tbl.add_row("Links Found", str(parsed.get("links_count", 0)))
            tbl.add_row("Forms", str(len(parsed.get("forms", []))))
            console.print(tbl)
            self.soul.append_memory("SCRAPE", target, result["output"])

    def do_copyright(self, arg):
        if not arg:
            console.print("[red]Usage: copyright <target>[/red]")
            return
        target = arg.strip()
        if not is_valid_network_target(target):
            console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
            return
        result = run_tool("copyright_osint", config=self.config, target=target)
        if result is None:
            result = {}
        if result.get("error"):
            console.print(f"[red]Error: {result['error']}[/red]")
        else:
            parsed = result.get("parsed", {})
            console.print(f"[green]Risk Score:[/green] {parsed.get('risk_score', 0):.2f}")
            console.print(f"[green]Findings:[/green] {len(parsed.get('findings', []))}")
            table = Table(title=f"Copyright OSINT Findings for {target}", box=ROUNDED)
            table.add_column("#", style="dim")
            table.add_column("Type", style="cyan")
            table.add_column("Severity", style="bold")
            table.add_column("Evidence", style="white")
            for idx, f in enumerate(parsed.get("findings", [])[:20], 1):
                table.add_row(str(idx), f.get("type", "?"), f.get("severity", "info"), f.get("evidence", "")[:80])
            console.print(table)
            self.soul.append_memory("COPYRIGHT_OSINT", target, result["output"])

    def do_burp(self, arg):
        if not arg:
            console.print("[red]Usage: burp <target>[/red]")
            return
        target = arg.strip()
        if not is_valid_network_target(target):
            console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
            return
        result = run_tool("burp_scan", config=self.config, target=target)
        if result is None:
            result = {}
        if result.get("error"):
            console.print(f"[red]Error: {result['error']}[/red]")
        else:
            parsed = result.get("parsed", {})
            console.print(f"[green]Issues found:[/green] {parsed.get('issues_count', 0)}")
            table = Table(title=f"Burp Scan Findings for {target}", box=ROUNDED)
            table.add_column("Issue", style="cyan")
            table.add_column("Severity", style="bold")
            for issue in parsed.get("findings", [])[:10]:
                table.add_row(issue.get("name", "?"), issue.get("severity", "info"))
            console.print(table)
            self.soul.append_memory("BURP_SCAN", target, result["output"])

    def do_ghidra(self, arg):
        if not arg:
            console.print("[red]Usage: ghidra <binary_path>[/red]")
            return
        if not Path(arg).exists():
            console.print(f"[red]Binary not found: {arg}[/red]")
            return
        result = run_tool("ghidra_analyze", config=self.config, binary_path=arg)
        if result is None:
            result = {}
        if result.get("error"):
            console.print(f"[red]Error: {result['error']}[/red]")
        else:
            parsed = result.get("parsed", {})
            console.print(f"[green]Functions:[/green] {parsed.get('functions_count', 0)}")
            console.print(f"[green]Interesting strings:[/green] {', '.join(parsed.get('interesting_strings', [])[:5])}")
            vulns = parsed.get("vulnerabilities", [])
            if vulns:
                console.print("[red]Potential vulnerabilities:[/red]")
                for v in vulns:
                    console.print(f"  - {v.get('function')} ({v.get('type')})")
            else:
                console.print("[green]No obvious dangerous functions found.[/green]")
            self.soul.append_memory("GHIDRA_ANALYSIS", arg, result["output"])

    def do_clear(self, arg):
        console.clear()
        print_logo()

    def do_mitre(self, arg):
        if not arg:
            console.print("[red]Usage: mitre <technique_id>[/red]")
            return
        name = self.gateway.get_mitre_technique(arg)
        if name:
            console.print(f"[green]MITRE technique {arg}: {name}[/green]")
        else:
            console.print("[yellow]No matching technique found (or offline).[/yellow]")

    # ------------------------------------------------------------------
    # Enhanced Help Menu (updated – removed /raptor, added /shell)
    # ------------------------------------------------------------------
    def do_help(self, arg):
        if arg:
            super().do_help(arg)
            return

        table = Table(title="PHALANX v3.6 Command Reference", box=DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Command", style="bright_green", no_wrap=True, width=18)
        table.add_column("Description", style="white", width=50)
        table.add_column("Example", style="dim", width=35)

        commands = [
            ("/agentic", "Full multi-agent autonomous pentest", "/agentic 192.168.1.1 --graph --windows"),
            ("/swarm scan", "Launch intelligent swarm (CTF mode)", "/swarm scan metasploitable2 --follow --graph --raptor"),
            ("/scan", "Quick autonomous scan", "/scan 192.168.1.1"),
            ("/loot", "View collected loot (creds, vulns, etc.)", "/loot cred"),
            ("/graph", "Query Shadow Graph", "/graph summary or /graph query 'credentials'"),
            ("/finding", "List recent findings", "/finding 30"),
            ("/report", "Generate full JSON report", "/report"),
            ("/tools", "List all available tools", "/tools"),
            ("/chat", "Direct conversation with LLM", "/chat Explain IDOR"),
            ("/defense", "Network defense monitoring (start/stop/status)", "/defense start"),
            ("/test", "Run system health check", "/test"),
            ("/wp", "WordPress vulnerability scanner", "/wp https://example.com"),
            ("/winstealth", "WinStealth Windows evasion (load PE, set profile)", "/winstealth load payload.exe"),
            ("/shell", "Execute arbitrary shell command (dangerous, opt-in)", "/shell nmap -v"),
            ("/clear", "Clear the screen", "/clear"),
            # New v3.6 commands
            ("/warroom", "Open War Room UI (start/stop/open)", "/warroom open"),
            ("/verify", "Run verify-claims benchmark suite", "/verify basic"),
            ("/reverse", "OGhidra-powered reverse engineering", "/reverse load binary.exe"),
            ("/status", "Show T3MP3ST-style feature status table", "/status"),
            # Raptor commands (loop only)
            ("/loop", "Start/stop looped harness with altitude", "/loop start --altitude file"),
        ]

        for cmd, desc, ex in commands:
            table.add_row(cmd, desc, ex)

        console.print(table)
        console.print("\n[dim]Tip: Use Tab for auto-completion and arrow keys for history.[/dim]")

    def do_exit(self, arg):
        console.print("Goodbye.")
        if self._defense_monitor and self._defense_monitor.running:
            self._defense_monitor.stop()
        # Stop looped harness if running
        if self.looped_harness is not None and hasattr(self.looped_harness, 'stop'):
            self.looped_harness.stop()
        self.db.close()
        return True

    def do_EOF(self, arg):
        return self.do_exit(arg)

# ------------------------------------------------------------------
# Enhanced TUI with prompt_toolkit
# ------------------------------------------------------------------
def run_tui(soul, skill_mgr, gateway, executor, db, config, looped_harness=None,
            default_enable_graph=False, defense_monitor=None, warroom_thread=None):
    print_logo()

    console.print(Panel(
        "[bold green]PHALANX v3.6 TUI Ready (T3MP3ST + OGhidra)[/bold green]\n"
        "[dim]Type [bold]/help[/bold] for commands • [bold]/quit[/bold] to exit[/dim]",
        border_style="green"
    ))

    if not PROMPT_TOOLKIT_AVAILABLE:
        console.print("[yellow]prompt_toolkit not installed – falling back to basic cmd loop.[/yellow]")
        repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness,
                           default_enable_graph, defense_monitor, warroom_thread)
        repl.cmdloop()
        return

    # Enhanced styling
    style = Style.from_dict({
        'prompt': 'bold #00ff88',
        '': '#e0e0e0',
    })

    session = PromptSession(
        history=FileHistory(str(Path.cwd() / "phalanx" / "tui_history.txt")),
        auto_suggest=AutoSuggestFromHistory(),
        style=style,
        message="phalanx> "
    )

    repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness,
                       default_enable_graph, defense_monitor, warroom_thread)

    while True:
        try:
            line = session.prompt()
            if line.startswith('/'):
                line = line[1:]
            if repl.onecmd(line):
                break
        except (KeyboardInterrupt, EOFError):
            console.print("\n[green]Goodbye.[/green]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

# ------------------------------------------------------------------
# Main entrypoint
# ------------------------------------------------------------------
def ensure_bootstrapped(skip: bool = False):
    """
    Run phalanx_extra.py --force --no-pull-models if config missing or agents missing.
    If skip is True, do nothing.
    If phalanx_extra.py is missing, print a warning and continue.
    """
    if skip:
        logger.info("Skipping bootstrapping (--no-bootstrap flag).")
        return

    config_path = Path.cwd() / "phalanx" / "config" / "config.json"
    agents_path = Path.cwd() / "phalanx" / "agents"
    # Check if we need to run bootstrap: config missing or agents dir missing/empty
    need_bootstrap = not config_path.exists()
    if not need_bootstrap and agents_path.exists():
        # Check if at least one agent stub exists
        stubs = ["recon_agent.py", "exploit_agent.py", "orchestrator.py", "llm_gateway.py"]
        if not any((agents_path / s).exists() for s in stubs):
            need_bootstrap = True
    if need_bootstrap:
        # Check if phalanx_extra.py exists
        extra_script = Path("phalanx_extra.py")
        if not extra_script.exists():
            console.print("[yellow]phalanx_extra.py not found; cannot bootstrap automatically.[/yellow]")
            console.print("[yellow]Please ensure PHALANX components are installed and retry.[/yellow]")
            return

        console.print("[*] First run or missing agents – running bootstrapper to set up components...")
        try:
            # Run with timeout to avoid hanging
            result = subprocess.run(
                [sys.executable, str(extra_script), "--force", "--no-pull-models"],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                console.print("[+] Bootstrapping complete.")
            else:
                console.print(f"[!] Bootstrapping failed (exit {result.returncode}): {result.stderr}")
                console.print("[!] Continuing with basic functionality – some features may be missing.")
        except subprocess.TimeoutExpired:
            console.print("[!] Bootstrapping timed out after 120s. Continuing anyway.")
        except Exception as e:
            console.print(f"[!] Bootstrapping error: {e}")

# ------------------------------------------------------------------
# Signal handler for clean shutdown
# ------------------------------------------------------------------
def _signal_handler(signum, frame, defense_monitor=None, db=None, looped_harness=None):
    """Handle SIGINT/SIGTERM gracefully."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    if defense_monitor and defense_monitor.running:
        defense_monitor.stop()
        logger.info("Defense monitor stopped.")
    if looped_harness is not None and hasattr(looped_harness, 'stop'):
        looped_harness.stop()
        logger.info("Looped harness stopped.")
    if db:
        db.close()
        logger.info("Database closed.")
    sys.exit(0)

def main():
    console.print("[*] PHALANX v3.6 – Checking system...")

    parser = argparse.ArgumentParser(description="PHALANX v3.6 – Autonomous Pentesting Framework (T3MP3ST + OGhidra)")
    parser.add_argument("--tui", action="store_true", help="Launch TUI mode (embedded prompt-toolkit)")
    parser.add_argument("--agentic", action="store_true", help="Run in multi‑agent autonomous mode")
    parser.add_argument("--target", help="Target for agentic mode (required if --agentic)")
    parser.add_argument("--guardrail", action="store_true", default=True, help="Enable human confirmation for exploit actions (default: True)")
    parser.add_argument("--no-guardrail", dest="guardrail", action="store_false", help="Disable human confirmation (automatic)")
    parser.add_argument("--graph", "--shadow", action="store_true", help="Enable Shadow Graph persistence for agentic/swarm modes by default")
    parser.add_argument("--defense", action="store_true", help="Start defense monitor at launch")
    parser.add_argument("--warroom", action="store_true", help="Start War Room UI server at launch")
    parser.add_argument("--windows", action="store_true", help="Target is Windows; use WinStealth primitives")
    parser.add_argument("--config", default="config.json", help="Configuration file (overrides default)")
    parser.add_argument("--report-only", action="store_true", help="Generate report for existing session only")
    parser.add_argument("--session-id", help="Session ID for report-only mode")
    parser.add_argument("--no-bootstrap", action="store_true", help="Skip automatic bootstrapping of agents and config")
    parser.add_argument("command", nargs="?", help="Single command (e.g., 'scan 192.168.1.1')")
    parser.add_argument("args", nargs="*", help="Arguments for the single command")
    args = parser.parse_args()

    # Ensure bootstrap is run (unless skipped)
    try:
        ensure_bootstrapped(skip=args.no_bootstrap)
    except Exception as e:
        console.print(f"[red]Bootstrapping failed: {e}[/red]")
        console.print("[red]Continuing with limited functionality. Some features may not work.[/red]")
        # Allow continuation even if bootstrap fails; user can manually run phalanx_extra.py later.

    config = {}
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        default_config = Path.cwd() / "phalanx" / "config" / "config.json"
        if default_config.exists():
            config = json.loads(default_config.read_text())
        else:
            console.print(f"[!] Config file {args.config} not found – using defaults.")
            config = {
                "database": {"sqlite_path": "phalanx/phalanx.db"},
                "sandbox": {"enabled": False},
                "ollama": {"url": "http://localhost:11434", "default_model": "qwen2.5:7b"}
            }

    # Override with environment variables
    env_default = os.environ.get("PHALANX_DEFAULT_MODEL")
    env_fast = os.environ.get("PHALANX_FAST_MODEL")
    if env_default:
        config.setdefault("ollama", {})["default_model"] = env_default
    if env_fast:
        config.setdefault("ollama", {})["fast_model"] = env_fast

    low_profile = os.environ.get("PHALANX_LOW_PROFILE", "0") == "1"
    if low_profile:
        config.setdefault("embed", {})["low_profile"] = True

    # WinStealth override: allow users to disable via environment
    if os.environ.get("PHALANX_SKIP_WINSTEALTH", "0") == "1":
        config.setdefault("winstealth", {})["enabled"] = False
        console.print("[dim]WinStealth disabled (PHALANX_SKIP_WINSTEALTH=1)[/dim]")

    # Display optional component status
    print_optional_status(config)

    # Bootstrap: returns soul, skill_mgr, db, auto_pentest, looped_harness
    soul, skill_mgr, db, _, looped_harness = bootstrap_all(config)
    gateway = Gateway(config, TOOL_REGISTRY)
    executor = ToolExecutor(timeout=30, soul=soul, config=config)

    # ------------------------------------------------------------------
    # Guardrails: clean up existing containers (unless in report-only mode)
    # ------------------------------------------------------------------
    if not args.report_only:
        cleanup_phalanx_containers()

    # ------------------------------------------------------------------
    # Ollama model selection (skip if non-interactive or auto mode)
    # ------------------------------------------------------------------
    # Determine if we are in interactive mode
    interactive = sys.stdin.isatty() and not os.environ.get("PHALANX_AUTO", "0") == "1"

    if not args.report_only and not args.agentic and not args.command and interactive:
        model = select_ollama_model(gateway, interactive=True)
        if model:
            config["ollama"]["default_model"] = model
            if "fast_model" not in config["ollama"]:
                config["ollama"]["fast_model"] = model
            # Save config to persist
            with open(args.config, 'w') as f:
                json.dump(config, f, indent=2)
            console.print(f"[green]Default model set to: {model}[/green]")
            gateway.default_model = model
            gateway.fast_model = model
    else:
        # In non-interactive mode, respect PHALANX_DEFAULT_MODEL environment variable
        env_default = os.environ.get("PHALANX_DEFAULT_MODEL")
        if env_default:
            config["ollama"]["default_model"] = env_default
            gateway.default_model = env_default
            gateway.fast_model = env_default
        else:
            # If no env var and non-interactive, use fallback
            fallback = "qwen2.5:0.5b"
            config["ollama"].setdefault("default_model", fallback)
            gateway.default_model = config["ollama"]["default_model"]
            gateway.fast_model = config["ollama"].get("fast_model", gateway.default_model)

    # Initialize defense monitor if requested (before warroom to avoid race)
    defense_monitor = None
    if args.defense and DEFENSE_AVAILABLE:
        defense_monitor = NetWatchMonitor(
            gateway=gateway,
            soul=soul,
            db=db,
            config=config
        )
        defense_monitor.start()
        console.print("[*] Defense monitoring started.")
        logger.info(f"Defense monitor started (PID: {os.getpid()})")
    elif args.defense and not DEFENSE_AVAILABLE:
        console.print("[!] Defense mode requested but phalanx_defense module not available – skipping.")

    # Start War Room server if requested (after defense monitor is ready)
    warroom_thread = None
    if args.warroom and WARROOM_AVAILABLE and start_warroom_server is not None:
        console.print("[*] Starting War Room server...")
        try:
            warroom_thread = start_warroom_server()
            if warroom_thread:
                console.print("[green]War Room server started at http://localhost:3333[/green]")
                logger.info(f"War Room thread started: {warroom_thread.ident} (PID: {os.getpid()})")
            else:
                console.print("[red]Failed to start War Room server (returned None).[/red]")
        except Exception as e:
            console.print(f"[red]Failed to start War Room server: {e}[/red]")
    elif args.warroom and not WARROOM_AVAILABLE:
        console.print("[!] War Room requested but FastAPI/uvicorn not installed – skipping.")

    # Perform environment checks and display warnings/errors
    env_status = check_environment(config)
    if env_status["errors"]:
        console.print("[red]Environment errors detected:[/red]")
        for err in env_status["errors"]:
            console.print(f"  ✗ {err}")
    if env_status["warnings"]:
        console.print("[yellow]Environment warnings:[/yellow]")
        for warn in env_status["warnings"]:
            console.print(f"  ⚠ {warn}")
    if not env_status["errors"] and not env_status["warnings"]:
        console.print("[green]✓ Environment checks passed.[/green]")

    # Set up signal handler with access to defense_monitor, db, and looped_harness
    def signal_handler(signum, frame):
        _signal_handler(signum, frame, defense_monitor, db, looped_harness)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.report_only:
        if not args.session_id:
            console.print("[!] --report-only requires --session-id")
            sys.exit(1)
        report = db.full_report(args.session_id)
        console.print_json(json.dumps(report, indent=2, default=str))
        if defense_monitor:
            defense_monitor.stop()
        if looped_harness is not None and hasattr(looped_harness, 'stop'):
            looped_harness.stop()
        db.close()
        return

    if args.agentic:
        if not args.target:
            console.print("[!] --agentic requires --target")
            sys.exit(1)
        run_agentic(args.target, config, soul, skill_mgr, db, executor, gateway,
                    guardrail=args.guardrail, enable_shadow_graph=args.graph,
                    windows=args.windows)
        if defense_monitor:
            defense_monitor.stop()
        if looped_harness is not None and hasattr(looped_harness, 'stop'):
            looped_harness.stop()
        db.close()
        return

    if args.tui:
        run_tui(soul, skill_mgr, gateway, executor, db, config, looped_harness,
                default_enable_graph=args.graph, defense_monitor=defense_monitor,
                warroom_thread=warroom_thread)
        return

    if args.command:
        repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness,
                           default_enable_graph=args.graph, defense_monitor=defense_monitor,
                           warroom_thread=warroom_thread)
        cmd_line = f"{args.command} {' '.join(args.args)}"
        try:
            repl.onecmd(cmd_line)
        except Exception as e:
            console.print(f"[red]Error executing command: {e}[/red]")
        if defense_monitor:
            defense_monitor.stop()
        if looped_harness is not None and hasattr(looped_harness, 'stop'):
            looped_harness.stop()
        db.close()
        return

    print_logo()
    repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness,
                       default_enable_graph=args.graph, defense_monitor=defense_monitor,
                       warroom_thread=warroom_thread)
    try:
        repl.cmdloop()
    except KeyboardInterrupt:
        console.print("\nExiting.")
    finally:
        if defense_monitor:
            defense_monitor.stop()
        if looped_harness is not None and hasattr(looped_harness, 'stop'):
            looped_harness.stop()
        db.close()

if __name__ == "__main__":
    main()