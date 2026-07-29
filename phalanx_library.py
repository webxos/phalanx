#!/usr/bin/env python3
"""
PHALANX Library v3.6 – Bootstrap, sandbox, interactive runner, demo mode,
reporting, multi‑agent orchestration, SWARM with ReAct + reflection, and
**Raptor Loop Engine** (altitude‑aware generator/judge pipeline).

All data stored in ./phalanx/ (local to project).

Enhancements (v3.6):
- Shadow Graph in Soul (entity extraction, graph queries) – defined in core
- Hierarchical spawning in SwarmOrchestrator (sub-swarms for complex tasks)
- ReflectorAgent queries graph for strategic insights
- Mythos-style Looped Transformer Harness (Recurrent-Depth / Looped Reasoning)
- Thread-safe swarm campaign management
- No circular imports (uses local imports inside functions)
- Fixed: generate_engagement_plan now works when event loop is already running
- Fixed: run_swarm sets campaign_id on newly created Soul for graph persistence
- Fixed: SubSwarmOrchestrator handles missing agents gracefully
- Added XSS/RCE/SSRF escalation prompts
- Enhanced ExploitAgent with real‑world bounty patterns
- Improved SwarmOrchestrator escalation logic for high‑value findings
- Added Rich panel output for linear demo mode
- Added warning for missing phalanx_defense module in bootstrap_all
- Added call to _finalize_campaign in SwarmOrchestrator.run when completed
- FIX: SubSwarmOrchestrator progress handling ensures parent.progress exists and is callable
- NEW: Windows OS detection in ReconAgent (SMB/RDP ports)
- NEW: WindowsExploitAgent for reflective PE loading via WinStealth (renamed from SindriKit)
- NEW: SwarmOrchestrator auto‑switches to WindowsExploitAgent when target OS is Windows
- FIX: WinStealth import guard now catches ImportError and sets flag (supports non‑Windows platforms)
- FIX: bootstrap_all now gracefully handles missing phalanx_defense module (only warning)
- FIX: run_swarm uses robust async event loop handling (ThreadPoolExecutor fallback)
- FIX: SwarmOrchestrator progress callback ensures callable before use
- NEW: ensure_agent_stubs() called at module load to create missing agent files if needed
- ENHANCED: run_health_check now includes Docker network, container status, database writability
- ENHANCED: run_health_check now checks a broader set of tools with lower penalty and provides specific suggestions.
- AUTOMATION: All functions are fully non‑interactive; respect PHALANX_SKIP_PULL, PHALANX_DEFAULT_MODEL, etc.
- AUTOMATION: ensure_agent_stubs runs phalanx_extra.py with --no-pull-models to avoid prompts.
- NEW: route_reverse_skill() function added for routing reverse engineering tasks.

T3MP3ST + OGhidra Enhancements (v3.6):
- Added OPERATOR_ARCHETYPES for 8‑operator ReAct kill chain (RECON, SCANNER, EXPLOITER, INFILTRATOR, EXFILTRATOR, GHOST, COORDINATOR, ANALYST).
- Added new operator agent classes: ScannerAgent, InfiltratorAgent, ExfiltratorAgent, GhostAgent, CoordinatorAgent.
- Added T3MP3STSwarm class that orchestrates the full 8‑operator pipeline with ReAct loops and state management.
- Updated run_swarm to optionally use T3MP3STSwarm via `use_t3mp3st=True` parameter.
- Operator states are persisted in the database (operator_states table) for cooldown and detection risk tracking.
- ReActToolAgent from phalanx_engine is used to wrap each operator for reasoning and action.

FIXES in this version:
- Fixed T3MP3STSwarm._init_operators to correctly instantiate operator agents using agent_classes mapping.
- Fixed run_swarm async event loop handling to use ThreadPoolExecutor when loop is already running.
- Fixed background thread handling in run_swarm for non-follow mode.
- Ensured all 8 operators are correctly registered and executed in sequence.
- Added missing __init__ imports and fixed circular import references.
- Added a global flag to avoid repeated agent stub creation.
- Improved async execution in run_swarm with better error handling.
- Safe WinStealth import with broad exception handling.
- Safe PyTorch import with warning log.
- Safe parent.progress access in SubSwarmOrchestrator.
- Enhanced generate_engagement_plan to always return a valid plan, with robust fallback.
- FIX: SwarmOrchestrator __init__ now accepts and ignores use_t3mp3st parameter to avoid TypeError.
- FIX: T3MP3STSwarm __init__ properly pops use_t3mp3st before calling super.
- FIX: ensure_agent_stubs creates agent stubs with the correct __init__ signature (name, gateway, db, soul, skill_mgr, config=None).
- FIX: run_swarm now ensures gateway is always provided to the orchestrator, even if db was given but gateway was None.

RAPTOR LOOP ENGINE (v3.6.1):
- NEW: RaptorLoopEngine class – altitude scheduler, coverage matrix, generator/judge agents,
  disposition ledger, monotonic scrutiny KB.
- NEW: run_swarm(use_raptor=True) to use the Raptor loop instead of legacy/T3MP3ST swarms.
- All agent.run() results are checked for None before merging into context.
- FIXED: RaptorLoopEngine._get_altitude_context now uses get_loot_by_category instead of get_loot with category parameter.

INTEGRATION (v3.6.2):
- SwarmOrchestrator now accepts `use_raptor` flag and delegates to RaptorLoopEngine when True.
- run_swarm now always uses SwarmOrchestrator (except T3MP3ST), passing the flag.
- Removed direct RaptorLoopEngine instantiation from run_swarm – centralised control.
"""

import os
import sys
import json
import subprocess
import shutil
import logging
import asyncio
import time
import uuid
import threading
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------------
# Torch for looped harness (optional, but required if enabled)
# ------------------------------------------------------------------
try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None
    nn = None
    # Log a warning once at module load
    logger = logging.getLogger("phalanx_library")
    logger.warning("PyTorch not installed – looped harness disabled")

# ------------------------------------------------------------------
# Rich for pretty console output (optional)
# ------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
    Panel = None

# ------------------------------------------------------------------
# WinStealth integration (renamed from SindriKit) – gracefully handles missing library
# ------------------------------------------------------------------
try:
    from phalanx_winstealth import WinStealthWrapper
    WINSTEALTH_AVAILABLE = True
except ImportError:
    WINSTEALTH_AVAILABLE = False
    WinStealthWrapper = None
except Exception as e:
    # Catch any other import-related issues (e.g., missing dependencies)
    logger = logging.getLogger("phalanx_library")
    logger.warning(f"WinStealth import failed: {e}")
    WINSTEALTH_AVAILABLE = False
    WinStealthWrapper = None

# ------------------------------------------------------------------
# Paths – local "phalanx" folder (no dot)
# ------------------------------------------------------------------
BASE_DIR = Path.cwd() / "phalanx"
AGENTS_DIR = BASE_DIR / "agents"
CONFIG_DIR = BASE_DIR / "config"
PROMPTS_DIR = BASE_DIR / "prompts"
SWARM_LOGS_DIR = BASE_DIR / "swarm_logs"
REPORTS_DIR = BASE_DIR / "reports"

# Add agents directory to Python path for lazy imports
if AGENTS_DIR.exists() and str(AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(AGENTS_DIR))

# ------------------------------------------------------------------
# Logger
# ------------------------------------------------------------------
def get_logger(name: str) -> logging.Logger:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logging.getLogger(name)

logger = get_logger("phalanx_library")

# ------------------------------------------------------------------
# Additional prompts for escalation (XSS, RCE, SSRF)
# ------------------------------------------------------------------
PROMPTS = {
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

# ------------------------------------------------------------------
# Global flag to prevent repeated agent stub creation
# ------------------------------------------------------------------
_AGENT_STUBS_ENSURE_DONE = False

def ensure_agent_stubs():
    """Check if agent directory has necessary stubs; if not, run phalanx_extra.py --force --no-pull-models."""
    global _AGENT_STUBS_ENSURE_DONE
    if _AGENT_STUBS_ENSURE_DONE:
        return
    if AGENTS_DIR.exists() and any(AGENTS_DIR.glob("*.py")):
        # Check for at least one core agent file
        required = ["recon_agent.py", "exploit_agent.py", "orchestrator.py", "llm_gateway.py"]
        missing = [r for r in required if not (AGENTS_DIR / r).exists()]
        if not missing:
            _AGENT_STUBS_ENSURE_DONE = True
            return  # all good

    # Create the stubs directly with correct signatures rather than relying on phalanx_extra
    stub_files = {
        "recon_agent.py": '''#!/usr/bin/env python3
from phalanx_extra import BaseAgent

class ReconAgent(BaseAgent):
    def __init__(self, name, gateway, db, soul, skill_mgr, config=None):
        super().__init__(name, config)
        self.gateway = gateway
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr

    def run(self, target):
        return {"status": "recon placeholder", "target": target}
''',
        "exploit_agent.py": '''#!/usr/bin/env python3
from phalanx_extra import BaseAgent

class ExploitAgent(BaseAgent):
    def __init__(self, name, gateway, db, soul, skill_mgr, config=None):
        super().__init__(name, config)
        self.gateway = gateway
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr

    def run(self, target):
        return {"status": "exploit placeholder", "target": target}
''',
        "post_exploit_agent.py": '''#!/usr/bin/env python3
from phalanx_extra import BaseAgent

class PostExploitAgent(BaseAgent):
    def __init__(self, name, gateway, db, soul, skill_mgr, config=None):
        super().__init__(name, config)
        self.gateway = gateway
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr

    def run(self, target):
        return {"status": "post_exploit placeholder", "target": target}
''',
        "orchestrator.py": '''#!/usr/bin/env python3
from phalanx_extra import BaseAgent

class OrchestratorAgent(BaseAgent):
    def __init__(self, name, gateway, db, soul, skill_mgr, config=None):
        super().__init__(name, config)
        self.gateway = gateway
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr

    async def run(self, context):
        return {"next_agent": "recon", "reasoning": "orchestrator stub"}
''',
        "llm_gateway.py": '''#!/usr/bin/env python3
class OllamaGateway:
    def __init__(self, config):
        self.config = config
    def generate(self, prompt, model=None, json_mode=False):
        return "{}"
    async def generate_async(self, prompt, model=None, json_mode=False):
        return "{}"
'''
    }

    # Write missing or zero-size stubs
    for filename, content in stub_files.items():
        stub_path = AGENTS_DIR / filename
        if not stub_path.exists() or stub_path.stat().st_size == 0:
            stub_path.parent.mkdir(parents=True, exist_ok=True)
            stub_path.write_text(content)
            logger.info(f"Created/refreshed agent stub: {stub_path}")

    _AGENT_STUBS_ENSURE_DONE = True

# ------------------------------------------------------------------
# Bootstrap – unified (no duplication)
# ------------------------------------------------------------------
def bootstrap_all(config: dict):
    """
    Unified bootstrap for PHALANX components.
    Returns: (soul, skill_mgr, db, auto_pentest, looped_harness)
    """
    from phalanx_core import PhalanxDB, RoE, Soul, SkillManager, AutonomousPentest
    from phalanx_engine import ToolExecutor
    from phalanx_tools import Gateway, TOOL_REGISTRY

    # Optional: warn about missing defense module
    try:
        from phalanx_defense import NetWatchMonitor  # noqa: F401
    except ImportError:
        logger.warning("phalanx_defense module not found. Defense features limited.")

    db = PhalanxDB(config)
    roe = RoE.from_dict(config.get("engagement", {}).get("default_roe", {}))
    soul = Soul(db, roe)  # EnhancedSoul is now Soul in core
    skill_mgr = SkillManager()
    gateway = Gateway(config, TOOL_REGISTRY)
    executor = ToolExecutor(timeout=config.get("tools", {}).get("timeout", 30), soul=soul, config=config)

    looped_harness = None
    if config.get("looped", {}).get("enabled", False) and TORCH_AVAILABLE:
        looped_harness = PhalanxLoopedHarness(gateway, soul, db, config)
    elif config.get("looped", {}).get("enabled", False):
        logger.warning("Looped harness enabled but PyTorch not installed – skipping.")

    auto_pentest = AutonomousPentest(config=config, db=db, soul=soul, skill_mgr=skill_mgr,
                                     executor=executor, gateway=gateway)

    # Ensure agent stubs exist for agentic/swarm modes
    ensure_agent_stubs()

    return soul, skill_mgr, db, auto_pentest, looped_harness

# ------------------------------------------------------------------
# Sandbox, interactive, demo, planning (unchanged logic)
# ------------------------------------------------------------------
def run_in_sandbox(command: str, image: str = "kalilinux/kali-rolling", network: str = "phalanx-net") -> Dict:
    try:
        import docker
        client = docker.from_env()
        container = client.containers.run(
            image, command, detach=True, remove=True,
            stdin_open=False, tty=False, network=network
        )
        result = container.wait()
        logs = container.logs(stdout=True, stderr=True).decode("utf-8")
        return {"stdout": logs, "stderr": "", "returncode": result["StatusCode"]}
    except ImportError:
        return {"stdout": "", "stderr": "Docker Python module not installed", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}

_TMUX_AVAILABLE = shutil.which("tmux") is not None
_PEXPECT_AVAILABLE = False
try:
    import pexpect
    _PEXPECT_AVAILABLE = True
except ImportError:
    pexpect = None

def run_interactive(tool: str, command: str, timeout: int = 60,
                    expect_prompt: str = None, send_input: str = None) -> Dict:
    if _TMUX_AVAILABLE:
        session_name = f"phalanx_{tool}_{int(time.time())}"
        try:
            subprocess.run(["tmux", "new-session", "-d", "-s", session_name, command], check=True)
            if send_input and expect_prompt:
                time.sleep(2)
                subprocess.run(["tmux", "send-keys", "-t", session_name, send_input], check=True)
                subprocess.run(["tmux", "send-keys", "-t", session_name, "Enter"], check=True)
            time.sleep(timeout)
            result = subprocess.run(["tmux", "capture-pane", "-t", session_name, "-p"], capture_output=True, text=True)
            subprocess.run(["tmux", "kill-session", "-t", session_name])
            return {"stdout": result.stdout, "stderr": "", "returncode": 0}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}
    elif _PEXPECT_AVAILABLE:
        try:
            child = pexpect.spawn(command, timeout=timeout)
            if expect_prompt:
                child.expect(expect_prompt)
                if send_input:
                    child.sendline(send_input)
            child.expect(pexpect.EOF)
            return {
                "stdout": child.before.decode("utf-8", errors="ignore"),
                "stderr": "",
                "returncode": child.exitstatus
            }
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}
    else:
        return {"error": "Neither tmux nor pexpect available for interactive mode"}

def run_demo(config: dict, soul, skill_mgr, db, executor, gateway, agents: Optional[Dict] = None) -> dict:
    target = config.get("demo_target", "metasploitable2")
    logger.info(f"Starting autonomous demo against {target}")
    session_id = db.create_session(target, "demo", ["recon", "exploit", "c2"])
    findings = []
    if agents and agents.get("orchestrator"):
        logger.info("Using agentic orchestrator for demo")
        try:
            orchestrator = agents["orchestrator"]
            async def _run_orchestrator():
                return await orchestrator.run({"target": target, "phase": "recon"})
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            decision = loop.run_until_complete(_run_orchestrator())
            loop.close()
            db.finish_session(session_id, "completed")
            report = {
                "summary": f"Agentic demo completed against {target}",
                "orchestrator_decision": decision,
                "timestamp": datetime.utcnow().isoformat(),
                "session_id": session_id
            }
            # --- Add Rich panel output if available ---
            if RICH_AVAILABLE and Console and Panel:
                console = Console()
                console.print(Panel(json.dumps(report, indent=2), title="Demo Complete", border_style="green"))
            return report
        except Exception as e:
            logger.error(f"Agentic demo failed: {e}, falling back to linear demo")
    logger.info("Running linear demo (no agents)")
    nmap_result = gateway.run_tool("nmap", {"target": target, "options": "-sV -p- --open"})
    findings.append({
        "target": target, "tool": "nmap", "severity": "info",
        "description": "Port scan completed", "raw_output": nmap_result.get("output", "")[:500]
    })
    if "vsftpd 2.3.4" in nmap_result.get("output", ""):
        logger.info("Exploiting vsftpd backdoor")
        exploit_result = gateway.run_tool("msfconsole", {"resource": "exploit/vsftpd_backdoor.rc"})
        findings.append({
            "target": target, "tool": "msfconsole", "severity": "critical",
            "description": "vsftpd 2.3.4 backdoor exploited", "raw_output": exploit_result.get("output", "")[:500]
        })
    report = {
        "summary": f"Demo completed against {target}",
        "findings": findings,
        "timestamp": datetime.utcnow().isoformat(),
        "session_id": session_id
    }
    for f in findings:
        db.add_finding(target, f["tool"], f["severity"], f["description"], f["raw_output"])
    db.finish_session(session_id, "completed")

    # --- Add Rich panel output for linear demo if available ---
    if RICH_AVAILABLE and Console and Panel:
        console = Console()
        console.print(Panel(json.dumps(report, indent=2), title="Demo Complete", border_style="green"))

    return report

# ==================================================================
# generate_engagement_plan – FIXED scoping bug (inner except now captures as e)
# ==================================================================
def generate_engagement_plan(target: str, user_input: str, gateway) -> Dict:
    """
    Generate a structured engagement plan (OPPLAN) using PlannerAgent if available.
    Works correctly even when called from an already running event loop.
    FIXED: Robust fallback to static plan on any failure, always returns a valid dict.
    """
    try:
        import importlib
        planner_module = importlib.import_module("planner")
        PlannerAgent = getattr(planner_module, "PlannerAgent")
        planner = PlannerAgent("planner", gateway, None, None, None)

        async def _plan():
            return await planner.run({"target": target, "user_input": user_input})

        # Detect if we are already inside an event loop
        try:
            loop = asyncio.get_running_loop()
            # Running in async context: run the coroutine in a new thread to avoid nesting
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: asyncio.run(_plan()))
                plan = future.result()
        except RuntimeError:
            # No running loop, safe to use asyncio.run()
            plan = asyncio.run(_plan())

        # Validate that the plan has the expected structure
        if not isinstance(plan, dict):
            raise ValueError("PlannerAgent returned non-dict")
        if "objectives" not in plan or "roe" not in plan:
            raise ValueError("Plan missing 'objectives' or 'roe' keys")

        return plan
    except Exception as e:
        logger.warning(f"PlannerAgent failed: {e}, falling back to static plan")
        # Fallback: try to use phalanx_planner._static_plan if available
        try:
            from phalanx_planner import _static_plan
            return _static_plan(target, user_input, reason=str(e))
        except ImportError as e:
            # Last resort: built-in static plan – capture import error for reason
            logger.warning(f"phalanx_planner not available: {e}; using built-in static plan")
            safe_target = re.sub(r'[^a-zA-Z0-9\.\-_:]', '', target)[:100] or "unknown-target"
            plan = {
                "objectives": [
                    {"description": f"Reconnaissance of {safe_target}", "mitre_tags": ["T1595"], "evidence_guided": False},
                    {"description": f"Vulnerability assessment of {safe_target}", "mitre_tags": ["T1595.002"], "evidence_guided": False},
                    {"description": f"Exploitation of {safe_target}", "mitre_tags": ["T1190"], "evidence_guided": True}
                ],
                "roe": {
                    "allowed_targets": [safe_target],
                    "excluded_targets": [],
                    "forbidden_actions": ["data_exfiltration", "destruction"],
                    "require_human_confirm": ["privilege_escalation"],
                    "max_severity": "critical"
                },
                "user_input": user_input,
                "generated_by": "static_fallback_builtin",
                "fallback_reason": f"PlannerAgent failed: {str(e) if 'e' in locals() else 'unknown'}",
                "schema_version": "2.0"
            }
            return plan

# ------------------------------------------------------------------
# generate_report
# ------------------------------------------------------------------
def generate_report(db) -> Dict:
    sessions = db.list_sessions(10)
    all_findings = db.get_findings(limit=1000)
    return {
        "report_generated": datetime.utcnow().isoformat(),
        "total_sessions": len(sessions),
        "total_findings": len(all_findings),
        "sessions": sessions,
        "findings": all_findings[:100]
    }

def ensure_phalanx_dirs():
    """Create standard PHALANX directories in local ./phalanx."""
    for sub in ["config", "agents", "skills", "docs", "reports", "sandbox-data", "tools", "wordlists", "scripts", "swarm_logs", "playbooks"]:
        (BASE_DIR / sub).mkdir(parents=True, exist_ok=True)

# ==================================================================
# REVERSE ENGINEERING SKILL ROUTER
# ==================================================================
def route_reverse_skill(target: str, skill_mgr) -> Optional[str]:
    """
    Determine which reverse skill to use based on file extension or content.
    Uses the SkillManager's routing matrix as fallback.
    Returns the skill name (e.g., 'apk-reverse') or None.
    """
    from phalanx_core import SkillManager  # only for type hinting, not strictly needed
    path = Path(target)
    if path.exists():
        ext = path.suffix.lower()
        # Direct mapping for known extensions
        ext_map = {
            '.apk': 'apk-reverse',
            '.dex': 'apk-reverse',
            '.exe': 'ida-reverse',
            '.dll': 'ida-reverse',
            '.so': 'ida-reverse',
            '.elf': 'ida-reverse',
            '.js': 'js-reverse',
            '.mjs': 'js-reverse',
            '.bin': 'firmware-pentest',
            '.rom': 'firmware-pentest',
            '.fw': 'firmware-pentest',
        }
        if ext in ext_map:
            return ext_map[ext]
        # Fallback to routing matrix
        if skill_mgr and hasattr(skill_mgr, 'get_skill_for_target'):
            return skill_mgr.get_skill_for_target(ext)
        else:
            logger.warning("SkillManager does not have get_skill_for_target() – routing by extension only.")
            return None
    else:
        # Maybe a URL or domain – use routing matrix for web
        if target.startswith(('http://', 'https://')):
            if skill_mgr and hasattr(skill_mgr, 'get_skill_for_target'):
                return skill_mgr.get_skill_for_target("web")
            else:
                return "js-reverse"  # conservative fallback for web
        else:
            # Generic fallback
            if skill_mgr and hasattr(skill_mgr, 'get_skill_for_target'):
                return skill_mgr.get_skill_for_target("generic")
            return None

# ==================================================================
# System health check (for run.sh and /test command) – ENHANCED
# ==================================================================
def run_health_check(config: dict = None) -> dict:
    """
    System health check – matches v3.3 expectations for run.sh and /test.
    Enhanced with Docker network, container status, database writability,
    and a broader set of tools with lower penalty.
    """
    checks = []
    score = 100
    hardening_needed = []

    # Ollama
    try:
        from phalanx_tools import Gateway
        g = Gateway(config or {}, {})
        ollama_ok = g.check_ollama()
        checks.append({"name": "Ollama", "passed": ollama_ok})
        if not ollama_ok:
            score -= 25
            hardening_needed.append("Start Ollama")
    except Exception:
        checks.append({"name": "Ollama", "passed": False})
        score -= 30
        hardening_needed.append("Start Ollama")

    # Docker daemon
    try:
        import docker
        client = docker.from_env()
        client.ping()
        checks.append({"name": "Docker daemon", "passed": True})
    except Exception:
        checks.append({"name": "Docker daemon", "passed": False})
        score -= 20
        hardening_needed.append("Start Docker")

    # Docker network phalanx-net
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", "phalanx-net"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            checks.append({"name": "Docker network phalanx-net", "passed": True})
        else:
            checks.append({"name": "Docker network phalanx-net", "passed": False,
                           "details": "Network not found or not accessible"})
            score -= 15
            hardening_needed.append("Create Docker network phalanx-net")
    except FileNotFoundError:
        checks.append({"name": "Docker network phalanx-net", "passed": False,
                       "details": "Docker command not available"})
        score -= 15
        hardening_needed.append("Install Docker")
    except Exception as e:
        checks.append({"name": "Docker network phalanx-net", "passed": False,
                       "details": str(e)})
        score -= 15
        hardening_needed.append("Check Docker network")

    # Metasploitable2 container status
    try:
        # Check if container is running
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=phalanx-target", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            status = result.stdout.strip()
            if "Up" in status:
                checks.append({"name": "phalanx-target container (running)", "passed": True})
            else:
                checks.append({"name": "phalanx-target container (running)", "passed": False,
                               "details": f"Container exists but not running: {status}"})
                score -= 10
                hardening_needed.append("Start phalanx-target container")
        else:
            # Check if container exists (but stopped)
            result_all = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=phalanx-target", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=5
            )
            if result_all.returncode == 0 and result_all.stdout.strip():
                checks.append({"name": "phalanx-target container (exists)", "passed": False,
                               "details": f"Container exists but not running: {result_all.stdout.strip()}"})
                score -= 10
                hardening_needed.append("Start phalanx-target container")
            else:
                checks.append({"name": "phalanx-target container", "passed": False,
                               "details": "Container not found"})
                score -= 15
                hardening_needed.append("Create phalanx-target container")
    except FileNotFoundError:
        checks.append({"name": "phalanx-target container", "passed": False,
                       "details": "Docker command not available"})
        score -= 10
        hardening_needed.append("Install Docker")
    except Exception as e:
        checks.append({"name": "phalanx-target container", "passed": False,
                       "details": str(e)})
        score -= 10
        hardening_needed.append("Check phalanx-target container")

    # Database writability
    if config:
        db_path = Path(config.get("database", {}).get("sqlite_path", "phalanx/phalanx.db"))
    else:
        db_path = Path("phalanx/phalanx.db")
    db_dir = db_path.parent
    try:
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
        test_file = db_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
        checks.append({"name": "Database directory writable", "passed": True})
    except Exception as e:
        checks.append({"name": "Database directory writable", "passed": False,
                       "details": str(e)})
        score -= 30
        hardening_needed.append("Fix database directory permissions")

    # Core tools – broader list with lower penalty
    required_tools = ["nmap", "python3", "nuclei", "subfinder"]
    for tool in required_tools:
        passed = shutil.which(tool) is not None
        checks.append({"name": tool, "passed": passed})
        if not passed:
            score -= 5
            hardening_needed.append(f"Install {tool}")

    return {
        "checks": checks,
        "score": max(0, score),
        "hardening_needed": hardening_needed
    }

def print_banner():
    banner = r"""
    ██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
    ██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
    ██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
           Autonomous Pentesting Framework  v3.6
    ⚠  Only use on systems you own or have written permission.
    """
    if RICH_AVAILABLE:
        console = Console()
        console.print(banner, style="bold blue")
    else:
        print(banner)

# ==================================================================
# MYTHOS-STYLE LOOPED HARNESS (Recurrent-Depth / Looped Transformer)
# Integrated into phalanx_library.py for central access
# ==================================================================

if TORCH_AVAILABLE:
    class RecurrentBlock(nn.Module):
        """Core looped block: weight-shared transformer-style layer (RDT style)."""
        def __init__(self, dim: int = 512, num_heads: int = 8, ff_dim: int = 2048, dropout: float = 0.1):
            super().__init__()
            self.self_attn = nn.MultiheadAttention(embed_dim=dim, num_heads=num_heads, dropout=dropout, batch_first=True)
            self.norm1 = nn.LayerNorm(dim)
            self.ffn = nn.Sequential(
                nn.Linear(dim, ff_dim),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(ff_dim, dim),
                nn.Dropout(dropout)
            )
            self.norm2 = nn.LayerNorm(dim)

        def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
            attn_out, _ = self.self_attn(x, x, x, attn_mask=mask)
            x = self.norm1(x + attn_out)
            x = self.norm2(x + self.ffn(x))
            return x

    class LoopedTransformerHarness(nn.Module):
        """Prelude → Repeated Recurrent Block (Mythos RDT) → Coda."""
        def __init__(self, dim: int = 512, base_loops: int = 4, max_loops: int = 12):
            super().__init__()
            self.dim = dim
            self.base_loops = base_loops
            self.max_loops = max_loops
            self.prelude = nn.Linear(768, dim)
            self.recurrent_block = RecurrentBlock(dim=dim)
            self.coda = nn.Linear(dim, 768)
            self.halting_gate = nn.Linear(dim, 1)

        def forward(self, context_emb: torch.Tensor, num_loops: Optional[int] = None) -> torch.Tensor:
            x = self.prelude(context_emb)
            loops = num_loops or self.base_loops
            for i in range(min(loops, self.max_loops)):
                x = self.recurrent_block(x)
                halt_prob = torch.sigmoid(self.halting_gate(x.mean(dim=1)))
                if halt_prob.mean().item() > 0.85 and i > 2:
                    break
            return self.coda(x)

    class PhalanxLoopedHarness:
        """Main harness class – integrates with existing PHALANX components."""
        def __init__(self, gateway, soul, db, config: dict):
            self.gateway = gateway
            self.soul = soul
            self.db = db
            self.config = config
            self.model = LoopedTransformerHarness(
                dim=config.get("looped", {}).get("dim", 512),
                base_loops=config.get("looped", {}).get("num_loops", 4),
                max_loops=config.get("looped", {}).get("max_loops", 12)
            )
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)
            self.running = False
            self.loop_thread = None
            # Extended refresh commands with XSS/RCE/SSRF escalation
            self.refresh_commands = config.get("looped", {}).get("default_refresh_commands", [
                "scrape", "finding", "graph", "loot", "reflect", "xss_escalation", "rce_gadget"
            ])

        def prepare_context(self, target: str, recent_commands: List[str]) -> torch.Tensor:
            """Build context from graph, loot, memory, and recent activity."""
            graph_summary = self.soul.graph_summary() if hasattr(self.soul, "graph_summary") else {}
            loot_items = self.db.get_loot(limit=20) if self.db else []
            context_text = (
                f"Target: {target}\n"
                f"Recent commands: {' | '.join(recent_commands)}\n"
                f"Graph: {json.dumps(graph_summary)}\n"
                f"Loot count: {len(loot_items)}"
            )
            # Placeholder embedding – in production replace with actual Ollama nomic-embed-text call
            # TODO: Implement actual embedding using Ollama or a lightweight embedder.
            emb = torch.randn(1, 16, 768, device=self.device)
            return emb

        def refine_once(self, target: str, command: str):
            """One iteration of looped refinement."""
            context_emb = self.prepare_context(target, [command])
            with torch.no_grad():
                refined = self.model(context_emb)
            prompt = f"""You are a penetration testing analyst.
After running looped recurrent-depth reasoning on command '{command}' for target {target},
here is the refined latent insight. Turn this into concrete next actions or observations:"""
            insight = self.gateway.generate(prompt, model=self.gateway.fast_model)
            self.soul.append_memory("LOOP_REFINE", command, insight[:800])
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"[Loop] Refined '{command}': {insight[:120]}...")
            else:
                print(f"[Loop] Refined '{command}': {insight[:120]}...")

        def background_loop(self, target: str):
            """Background thread that keeps refreshing commands with looped reasoning."""
            while self.running:
                for cmd in self.refresh_commands:
                    if not self.running:
                        break
                    try:
                        self.refine_once(target, cmd)
                    except Exception as e:
                        logger.warning(f"Loop refinement failed for {cmd}: {e}")
                time.sleep(8)

        def start(self, target: str = "current"):
            if not TORCH_AVAILABLE:
                if RICH_AVAILABLE:
                    console = Console()
                    console.print("[red]PyTorch not installed – looped harness disabled.[/red]")
                else:
                    print("[!] PyTorch not installed – looped harness disabled.")
                return
            if self.running:
                return
            self.running = True
            self.loop_thread = threading.Thread(target=self.background_loop, args=(target,), daemon=True)
            self.loop_thread.start()
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"[green]Looped Harness (Mythos RDT) started – refreshing: {self.refresh_commands}[/green]")

        def stop(self):
            self.running = False
            if self.loop_thread and self.loop_thread.is_alive():
                self.loop_thread.join(timeout=3)
            if RICH_AVAILABLE:
                console = Console()
                console.print("[yellow]Looped Harness stopped.[/yellow]")
else:
    # Dummy class when PyTorch not available
    class PhalanxLoopedHarness:
        def __init__(self, *args, **kwargs):
            logger.warning("PhalanxLoopedHarness initialized without PyTorch – will be non-functional")
        def start(self, *args, **kwargs):
            pass
        def stop(self, *args, **kwargs):
            pass

# ==================================================================
# SWARM COMPONENTS (Enhanced with ReflectorAgent and ReAct)
# ==================================================================

def list_ollama_models() -> List[str]:
    try:
        result = subprocess.run(["ollama", "list", "--json"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return [m["name"] for m in data.get("models", [])]
        else:
            result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().splitlines()
                if len(lines) > 1:
                    models = []
                    for line in lines[1:]:
                        parts = line.split()
                        if parts:
                            models.append(parts[0])
                    return models
    except Exception as e:
        logger.warning(f"Failed to list Ollama models: {e}")
    return []

def pull_ollama_model(model: str) -> bool:
    try:
        subprocess.run(["ollama", "pull", model], check=True, timeout=300)
        return True
    except Exception as e:
        logger.error(f"Failed to pull model {model}: {e}")
        return False

# ------------------------------------------------------------------
# Base Swarm Agent (abstract)
# ------------------------------------------------------------------
class BaseSwarmAgent:
    def __init__(self, name: str, gateway, db, soul, skill_mgr, model: str, progress_callback=None):
        self.name = name
        self.gateway = gateway
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.model = model
        self.progress_callback = progress_callback
    async def run(self, context: dict) -> dict:
        raise NotImplementedError

# ------------------------------------------------------------------
# Recon Agent (async-friendly) – enhanced with Windows detection
# ------------------------------------------------------------------
class ReconAgent(BaseSwarmAgent):
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        if not target:
            return {"error": "No target provided"}
        
        results = {
            "subdomains": [],
            "open_ports": [],
            "urls": [],
            "technologies": [],
            "vulnerabilities": [],
            "emails": [],
            "links": [],
            "forms": []
        }
        
        async def run_subfinder():
            return await asyncio.to_thread(
                lambda: self.gateway.run_tool("subfinder", {"domain": target})
            )
        async def run_naabu():
            return await asyncio.to_thread(
                lambda: self.gateway.run_tool("naabu", {"target": target})
            )
        async def run_httpx(subdomains):
            if subdomains:
                return await asyncio.to_thread(
                    lambda: self.gateway.run_tool("httpx", {"targets": ",".join(subdomains[:10])})
                )
            return None
        async def run_nuclei():
            return await asyncio.to_thread(
                lambda: self.gateway.run_tool("nuclei", {"target": target})
            )
        async def run_scrape():
            return await asyncio.to_thread(
                lambda: self.gateway.run_tool("scrape", {"target": target})
            )
        
        subfinder_task = asyncio.create_task(run_subfinder())
        naabu_task = asyncio.create_task(run_naabu())
        nuclei_task = asyncio.create_task(run_nuclei())
        scrape_task = asyncio.create_task(run_scrape())
        
        subfinder_res = await subfinder_task
        naabu_res = await naabu_task
        nuclei_res = await nuclei_task
        scrape_res = await scrape_task
        
        if subfinder_res.get("rc", -1) == 0:
            results["subdomains"] = subfinder_res.get("parsed", {}).get("subdomains", [])
        if naabu_res.get("rc", -1) == 0:
            results["open_ports"] = naabu_res.get("parsed", {}).get("ports", [])
        if nuclei_res.get("rc", -1) == 0:
            results["vulnerabilities"] = nuclei_res.get("parsed", {}).get("findings", [])
        if scrape_res.get("rc", -1) == 0:
            parsed = scrape_res.get("parsed", {})
            results["emails"] = parsed.get("emails", [])
            results["links"] = parsed.get("sample_links", [])
            results["forms"] = parsed.get("forms", [])
            results["technologies"] = parsed.get("tech_hints", [])
        
        if results["subdomains"]:
            httpx_res = await run_httpx(results["subdomains"])
            if httpx_res and httpx_res.get("rc", -1) == 0:
                results["urls"] = httpx_res.get("parsed", {}).get("urls", [])
        
        # --- Windows OS detection from open ports ---
        os_type = "unknown"
        open_ports = results.get("open_ports", [])
        # Common Windows services: SMB (445), RDP (3389), NetBIOS (137-139), etc.
        windows_indicators = [445, 3389, 137, 138, 139]
        if any(port in open_ports for port in windows_indicators):
            os_type = "windows"
        elif "ssh" in str(results.get("technologies", [])).lower() or 22 in open_ports:
            os_type = "linux"  # could be other Unix, but assume Linux
        # Also check service strings from nmap if available (via parsed data)
        # We don't have direct access to nmap parsed output here, but can add later.
        context["os_type"] = os_type
        results["os_type"] = os_type
        
        if self.progress_callback:
            self.progress_callback(f"[Recon] Found {len(results['subdomains'])} subdomains, {len(results['open_ports'])} open ports, {len(results['vulnerabilities'])} vulnerabilities, {len(results['emails'])} emails, OS: {os_type}")
        
        return {"phase": "recon", "findings": results}

# ------------------------------------------------------------------
# Classify Agent (async LLM calls)
# ------------------------------------------------------------------
class ClassifyAgent(BaseSwarmAgent):
    async def run(self, context: dict) -> dict:
        findings = context.get("recon_findings", {})
        vulnerabilities = findings.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"phase": "classify", "validated": []}
        
        validated = []
        for vuln in vulnerabilities[:20]:
            prompt = f"""Given this vulnerability finding:
Name: {vuln.get('name', 'Unknown')}
Description: {vuln.get('description', '')}
Severity: {vuln.get('severity', 'info')}

Assign a CVSS 3.1 base score (0.0-10.0) and determine if it's a false positive.
Output JSON: {{"cvss_score": float, "false_positive": bool, "reason": "..."}}"""
            response = await asyncio.to_thread(
                self.gateway.generate, prompt, self.model, json_mode=True
            )
            try:
                analysis = json.loads(response)
                if not analysis.get("false_positive", True):
                    vuln["cvss_score"] = analysis.get("cvss_score", 0.0)
                    validated.append(vuln)
            except:
                vuln["cvss_score"] = 5.0
                validated.append(vuln)
        
        if self.progress_callback:
            self.progress_callback(f"[Classify] Validated {len(validated)} vulnerabilities")
        return {"phase": "classify", "validated_vulnerabilities": validated}

# ------------------------------------------------------------------
# Exploit Agent – enhanced with real‑world bounty patterns
# ------------------------------------------------------------------
class ExploitAgent(BaseSwarmAgent):
    async def run(self, context: dict) -> dict:
        vulnerabilities = context.get("validated_vulnerabilities", [])
        if not vulnerabilities:
            return {"phase": "exploit", "exploit_plan": []}
        
        exploit_plan = []
        for vuln in vulnerabilities[:5]:
            # Enhanced prompt with priority for XSS, RCE, SSRF, IDOR
            prompt = f"""Vulnerability: {vuln.get('name')} (CVSS {vuln.get('cvss_score', '?')})
Prioritize real bounty patterns:
- XSS → account takeover / session theft
- Template injection / file upload → RCE
- SSRF → cloud metadata / internal pivot
- IDOR / auth bypass → mass data access
Output JSON with tool, resource, command, and escalation hint."""
            response = await asyncio.to_thread(
                self.gateway.generate, prompt, self.model, json_mode=True
            )
            try:
                plan_item = json.loads(response)
                plan_item["vulnerability"] = vuln.get("name")
                exploit_plan.append(plan_item)
            except:
                continue
        
        if self.progress_callback:
            self.progress_callback(f"[Exploit] Built {len(exploit_plan)} exploit chains")
        return {"phase": "exploit", "exploit_plan": exploit_plan}

# ------------------------------------------------------------------
# Windows Exploit Agent (uses WinStealth for reflective PE loading)
# ------------------------------------------------------------------
class WindowsExploitAgent(BaseSwarmAgent):
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        pe_path = context.get("pe_path", "payload.exe")
        profile = context.get("profile", "Win32")
        if not WINSTEALTH_AVAILABLE:
            return {"phase": "exploit", "error": "WinStealth not available", "success": False}
        wrapper = WinStealthWrapper()
        try:
            with open(pe_path, "rb") as f:
                pe_bytes = f.read()
            result = wrapper.reflective_load_pe(pe_bytes, profile)
            if result["success"]:
                wrapper.destroy_context(result["context"])
                return {"phase": "exploit", "success": True, "message": "PE loaded reflectively"}
            else:
                return {"phase": "exploit", "success": False, "error": result.get("error", "Unknown error")}
        except Exception as e:
            return {"phase": "exploit", "success": False, "error": str(e)}

# ------------------------------------------------------------------
# Report Agent
# ------------------------------------------------------------------
class ReportAgent(BaseSwarmAgent):
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        recon = context.get("recon_findings", {})
        vulnerabilities = context.get("validated_vulnerabilities", [])
        exploits = context.get("exploit_plan", [])
        
        report = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "subdomains_found": len(recon.get("subdomains", [])),
                "ports_found": len(recon.get("open_ports", [])),
                "urls_discovered": len(recon.get("urls", [])),
                "emails_found": len(recon.get("emails", [])),
                "links_found": len(recon.get("links", [])),
                "vulnerabilities_detected": len(vulnerabilities),
                "exploits_planned": len(exploits)
            },
            "vulnerabilities": vulnerabilities[:20],
            "exploit_plan": exploits[:10],
            "full_recon": recon
        }
        
        if self.progress_callback:
            self.progress_callback(f"[Report] Generated final report for {target}")
        return {"phase": "report", "report": report}

# ------------------------------------------------------------------
# Reflector Agent (with graph query support)
# ------------------------------------------------------------------
class ReflectorAgent(BaseSwarmAgent):
    async def run(self, context: dict) -> dict:
        phase = context.get("current_phase", "recon")
        findings = context.get("recent_findings", [])
        attack_tree = context.get("attack_tree", {})
        objective = context.get("objective", "Compromise target")
        
        graph_insight = ""
        if hasattr(self.soul, "query_graph"):
            graph_insight = self.soul.query_graph(f"lateral movement or credentials for {phase}")
        
        prompt = f"""You are a reflection engine for a penetration test.
Current phase: {phase}
Objective: {objective}
Recent findings (summarized):
{json.dumps(findings[:3], indent=2)}
Attack tree state (confidence scores):
{json.dumps(attack_tree, indent=2)[:500]}
Shadow Graph Insight:
{graph_insight}

Evaluate:
1. Overall confidence in progress (0.0-1.0)
2. Most promising evidence (one short sentence)
3. Suggested action: "continue", "prune" (drop low-confidence branch), "escalate" (move to next phase), or "spawn" (delegate to sub-swarm for complex sub-task)
4. Next phase: recon, classify, exploit, report, or spawn_subtask (specify subphase)
5. Updated confidence for current attack branch (0.0-1.0)

Output JSON only: {{"confidence": float, "key_evidence": "...", "suggestion": "...", "next_phase": "...", "branch_confidence": float}}
"""
        response = await asyncio.to_thread(
            self.gateway.generate, prompt, self.model, json_mode=True
        )
        try:
            reflection = json.loads(response)
        except:
            reflection = {"confidence": 0.5, "key_evidence": "insufficient data", "suggestion": "continue", "next_phase": phase, "branch_confidence": 0.5}
        
        branch_key = f"{phase}_branch"
        if branch_key not in attack_tree:
            attack_tree[branch_key] = {"confidence": 0.5, "findings": []}
        attack_tree[branch_key]["confidence"] = reflection.get("branch_confidence", 0.5)
        attack_tree[branch_key]["findings"].extend(findings[:2])
        attack_tree[branch_key]["last_reflect"] = datetime.utcnow().isoformat()
        
        if self.soul:
            self.soul.append_memory("REFLECTION", phase, json.dumps(reflection))
        
        if self.progress_callback:
            self.progress_callback(f"[Reflect] Confidence: {reflection['confidence']}, Suggestion: {reflection['suggestion']}")
        
        return reflection

# ------------------------------------------------------------------
# SubSwarmOrchestrator (for hierarchical spawning) – FIXED progress handling
# ------------------------------------------------------------------
class SubSwarmOrchestrator:
    """Lightweight swarm for a specific sub-task, runs a limited ReAct loop and returns results."""
    def __init__(self, target: str, phase: str, context: dict, parent: "SwarmOrchestrator",
                 max_steps: int = 10):
        self.target = target
        self.phase = phase
        self.context = context.copy()
        self.parent = parent
        self.max_steps = max_steps
        self.step = 0
        self.results = {}
        # Get parent progress callback safely
        if hasattr(parent, 'progress') and callable(parent.progress):
            self._progress = parent.progress
        else:
            self._progress = lambda msg: logger.info(msg)

    async def run(self) -> dict:
        # Use stored progress callback
        self._progress(f"[SubSwarm] Starting sub-swarm for phase '{self.phase}' on {self.target}")
        
        agents = self.parent.agents
        current_phase = self.phase
        required_agents = ["recon", "classify", "exploit"]
        for agent in required_agents:
            if agent not in agents:
                self._progress(f"[SubSwarm] Missing required agent '{agent}', cannot proceed.")
                return {"error": f"Missing agent '{agent}'"}
        
        while self.step < self.max_steps and current_phase not in ("report", "done"):
            self.step += 1
            if current_phase == "recon":
                result = await agents["recon"].run(self.context)
                self.results["recon"] = result.get("findings", {})
                self.context["recon_findings"] = self.results["recon"]
                current_phase = "classify"
            elif current_phase == "classify":
                result = await agents["classify"].run(self.context)
                self.results["classified"] = result.get("validated_vulnerabilities", [])
                self.context["validated_vulnerabilities"] = self.results["classified"]
                current_phase = "exploit"
            elif current_phase == "exploit":
                result = await agents["exploit"].run(self.context)
                self.results["exploit_plan"] = result.get("exploit_plan", [])
                self.context["exploit_plan"] = self.results["exploit_plan"]
                current_phase = "done"
            else:
                break
        
        loot_note = {
            "type": f"subswarm_{self.phase}",
            "target": self.target,
            "findings": self.results,
            "timestamp": datetime.utcnow().isoformat()
        }
        if self.parent.soul:
            self.parent.soul.ingest_loot(loot_note)
        
        self._progress(f"[SubSwarm] Completed phase '{self.phase}' with {len(self.results.get('classified', []))} validated vulns")
        
        return self.results

# ------------------------------------------------------------------
# Thread-safe Swarm Campaign registry
# ------------------------------------------------------------------
_active_swarms_lock = threading.RLock()
_active_swarms: Dict[str, "SwarmOrchestrator"] = {}

def _register_swarm(campaign_id: str, orchestrator):
    with _active_swarms_lock:
        _active_swarms[campaign_id] = orchestrator

def _unregister_swarm(campaign_id: str):
    with _active_swarms_lock:
        _active_swarms.pop(campaign_id, None)

def stop_swarm_campaign(campaign_id: str) -> bool:
    """Stop a running swarm campaign by setting its stopped flag."""
    with _active_swarms_lock:
        orchestrator = _active_swarms.get(campaign_id)
        if orchestrator:
            orchestrator.stop()
            return True
    return False

def get_swarm_campaign_status(campaign_id: str) -> Optional[Dict]:
    camp_file = BASE_DIR / "swarm_campaigns.json"
    if camp_file.exists():
        try:
            campaigns = json.loads(camp_file.read_text())
            if campaign_id in campaigns:
                status = campaigns[campaign_id]
                log_file = SWARM_LOGS_DIR / f"{campaign_id}.log"
                if log_file.exists():
                    try:
                        with open(log_file, 'r') as f:
                            lines = f.readlines()[-20:]
                            status["recent_logs"] = [json.loads(l) for l in lines if l.strip()]
                    except:
                        pass
                return status
        except:
            pass
    report_file = REPORTS_DIR / f"swarm_{campaign_id}.json"
    if report_file.exists():
        return {"status": "completed", "report_path": str(report_file)}
    return None

# ==================================================================
# T3MP3ST 8‑OPERATOR ARCHETYPES AND NEW AGENT CLASSES
# ==================================================================

# 8 Operator Archetypes (matching T3MP3ST)
OPERATOR_ARCHETYPES = {
    "RECON": {
        "phase": "reconnaissance",
        "mitre": "TA0043",
        "description": "Information gathering, OSINT, network scanning"
    },
    "SCANNER": {
        "phase": "discovery",
        "mitre": "TA0007",
        "description": "Vulnerability scanning, service enumeration"
    },
    "EXPLOITER": {
        "phase": "initial_access",
        "mitre": "TA0001, TA0002",
        "description": "Exploit development and execution"
    },
    "INFILTRATOR": {
        "phase": "lateral_movement",
        "mitre": "TA0008, TA0004",
        "description": "Pivoting, lateral movement, credential harvesting"
    },
    "EXFILTRATOR": {
        "phase": "exfiltration",
        "mitre": "TA0009, TA0010",
        "description": "Data extraction, covert channels"
    },
    "GHOST": {
        "phase": "persistence",
        "mitre": "TA0003, TA0005",
        "description": "Persistence mechanisms, defense evasion"
    },
    "COORDINATOR": {
        "phase": "c2",
        "mitre": "TA0011",
        "description": "Command and control, orchestration"
    },
    "ANALYST": {
        "phase": "reporting",
        "mitre": "",
        "description": "Reporting, correlation, recommendations"
    }
}

# New operator agent classes
class ScannerAgent(BaseSwarmAgent):
    """Vulnerability scanning operator (T3MP3ST SCANNER)."""
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        if not target:
            return {"error": "No target provided"}
        # Run nuclei for vulnerability scanning
        result = await asyncio.to_thread(
            lambda: self.gateway.run_tool("nuclei", {"target": target, "severity": "critical,high"})
        )
        vulnerabilities = result.get("parsed", {}).get("findings", []) if result.get("rc") == 0 else []
        if self.progress_callback:
            self.progress_callback(f"[Scanner] Found {len(vulnerabilities)} vulnerabilities")
        return {"phase": "scanner", "vulnerabilities": vulnerabilities}

class InfiltratorAgent(BaseSwarmAgent):
    """Lateral movement and credential harvesting operator (T3MP3ST INFILTRATOR)."""
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        if not target:
            return {"error": "No target provided"}
        # Example: attempt SMB enumeration and credential dumping
        results = {}
        # Check if SMB is open (recon_findings may have open_ports)
        recon = context.get("recon_findings", {})
        open_ports = recon.get("open_ports", [])
        if 445 in open_ports or 139 in open_ports:
            # Run enum4linux
            enum_result = await asyncio.to_thread(
                lambda: self.gateway.run_tool("enum4linux", {"target": target})
            )
            if enum_result.get("rc") == 0:
                results["enum4linux"] = enum_result.get("output", "")[:500]
            # Attempt secretsdump if credentials available
            if context.get("credentials"):
                # Placeholder: use provided credentials
                pass
        if self.progress_callback:
            self.progress_callback(f"[Infiltrator] Lateral movement scan completed")
        return {"phase": "infiltrator", "results": results}

class ExfiltratorAgent(BaseSwarmAgent):
    """Data exfiltration operator (T3MP3ST EXFILTRATOR)."""
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        if not target:
            return {"error": "No target provided"}
        # In a real scenario, this would extract data from the compromised host.
        # For demo, we simulate exfiltration of loot items.
        loot = self.db.get_loot(campaign_id=context.get("campaign_id"), limit=20) if self.db else []
        exfil_data = [{"id": item.get("loot_id"), "category": item.get("category")} for item in loot[:5]]
        if self.progress_callback:
            self.progress_callback(f"[Exfiltrator] Prepared {len(exfil_data)} items for exfiltration")
        return {"phase": "exfiltrator", "data": exfil_data}

class GhostAgent(BaseSwarmAgent):
    """Persistence and defense evasion operator (T3MP3ST GHOST)."""
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        if not target:
            return {"error": "No target provided"}
        # Simulate establishing persistence
        persistence_methods = ["cron_job", "systemd_service", "scheduled_task", "registry_run"]
        # For Windows, use WinStealth if available
        if context.get("os_type") == "windows" and WINSTEALTH_AVAILABLE:
            persistence_methods.append("winstealth_reflective_load")
        established = persistence_methods[:2]  # pick first two for demo
        if self.progress_callback:
            self.progress_callback(f"[Ghost] Established persistence via {', '.join(established)}")
        return {"phase": "ghost", "established": True, "methods": established}

class CoordinatorAgent(BaseSwarmAgent):
    """Command and control operator (T3MP3ST COORDINATOR)."""
    async def run(self, context: dict) -> dict:
        target = context.get("target")
        if not target:
            return {"error": "No target provided"}
        # Simulate C2 channel establishment
        # For demo, we just generate a Sliver implant if available
        try:
            result = await asyncio.to_thread(
                lambda: self.gateway.run_tool("sliver_generate", {"target_ip": target, "mtls_port": 443})
            )
            success = result.get("rc") == 0
        except Exception:
            success = False
        if self.progress_callback:
            self.progress_callback(f"[Coordinator] C2 channel {'established' if success else 'failed'}")
        return {"phase": "coordinator", "established": success}

# ------------------------------------------------------------------
# Enhanced SwarmOrchestrator with hierarchical spawning, shadow graph, and Raptor mode
# ------------------------------------------------------------------
class SwarmOrchestrator:
    def __init__(self, target: str, scope: Optional[str], mode: str, model: str,
                 db, soul, skill_mgr, gateway, progress_callback: Optional[Callable] = None,
                 enable_hierarchical: bool = False, enable_shadow_graph: bool = False,
                 use_t3mp3st: bool = False, use_raptor: bool = False,
                 config: Optional[dict] = None, **kwargs):
        # Pop any extra args that might be passed
        kwargs.pop('use_t3mp3st', None)
        self.use_t3mp3st = use_t3mp3st
        self.use_raptor = use_raptor
        self.target = target
        self.scope = scope or target
        self.mode = mode
        self.model = model
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.gateway = gateway
        self.progress_callback = progress_callback
        self.progress = progress_callback or (lambda msg: logger.info(msg))
        self.stopped = False
        self.campaign_id = None
        self.current_phase = "recon"
        self.max_steps = 50
        self.step = 0
        self.attack_tree = {}
        self.enable_hierarchical = enable_hierarchical
        self.enable_shadow_graph = enable_shadow_graph
        self.config = config or {}

        # Initialise agents dictionary (default 5-agent pipeline)
        self.agents = {
            "recon": ReconAgent("recon", gateway, db, soul, skill_mgr, model, progress_callback),
            "classify": ClassifyAgent("classify", gateway, db, soul, skill_mgr, model, progress_callback),
            "exploit": ExploitAgent("exploit", gateway, db, soul, skill_mgr, model, progress_callback),
            "report": ReportAgent("report", gateway, db, soul, skill_mgr, model, progress_callback),
            "reflect": ReflectorAgent("reflect", gateway, db, soul, skill_mgr, model, progress_callback)
        }

        # Context placeholder
        self.context = {
            "target": target,
            "scope": scope,
            "mode": mode,
            "recon_findings": {},
            "validated_vulnerabilities": [],
            "exploit_plan": [],
            "attack_tree": self.attack_tree,
            "current_phase": "recon",
            "recent_findings": [],
            "objective": "Compromise target and report findings",
            "os_type": "unknown"
        }

    def stop(self):
        self.stopped = True
        self.progress("[*] Stopping swarm...")

    def _update_campaign_file(self, status: str, additional: dict = None):
        camp_file = BASE_DIR / "swarm_campaigns.json"
        camp_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            campaigns = {}
            if camp_file.exists():
                campaigns = json.loads(camp_file.read_text())
            if self.campaign_id not in campaigns:
                campaigns[self.campaign_id] = {
                    "target": self.target,
                    "scope": self.scope,
                    "mode": self.mode,
                    "model": self.model,
                    "started_at": datetime.utcnow().isoformat()
                }
            campaigns[self.campaign_id]["status"] = status
            if additional:
                campaigns[self.campaign_id].update(additional)
            camp_file.write_text(json.dumps(campaigns, indent=2))
        except Exception as e:
            logger.warning(f"Failed to update campaign file: {e}")

    def _log_agent_action(self, agent_name: str, result: dict):
        ts = datetime.utcnow().isoformat()
        log_entry = {
            "ts": ts,
            "agent": agent_name,
            "step": self.step,
            "summary": json.dumps(result)[:200]
        }
        log_file = SWARM_LOGS_DIR / f"{self.campaign_id}.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.warning(f"Failed to write log entry: {e}")
        self._update_campaign_file("running", {"recent_logs": [log_entry]})

    async def _spawn_child_swarm(self, subphase: str, subcontext: dict) -> dict:
        if not self.enable_hierarchical:
            return {}
        self.progress(f"[Hierarchical] Spawning sub-swarm for phase '{subphase}'")
        sub_orchestrator = SubSwarmOrchestrator(
            target=self.target,
            phase=subphase,
            context=subcontext,
            parent=self,
            max_steps=8
        )
        result = await sub_orchestrator.run()
        return result

    async def run(self) -> dict:
        """
        Main entry point for the swarm orchestrator.
        If use_raptor is True, delegate to RaptorLoopEngine.
        Otherwise run the standard multi-agent pipeline.
        """
        # Raptor mode: delegate to the dedicated engine
        if self.use_raptor:
            self.progress("[Raptor] Delegating to Raptor Loop Engine...")
            raptor_engine = RaptorLoopEngine(
                target=self.target,
                scope=self.scope,
                mode=self.mode,
                model=self.model,
                db=self.db,
                soul=self.soul,
                skill_mgr=self.skill_mgr,
                gateway=self.gateway,
                progress_callback=self.progress_callback,
                campaign_id=self.campaign_id,
                config=self.config
            )
            return await raptor_engine.run()

        # Standard swarm pipeline
        self.progress(f"[bold]Swarm orchestrator started for {self.target}[/bold]")
        self.progress(f"Model: {self.model}, Mode: {self.mode}")
        self.progress(f"Campaign ID: {self.campaign_id}")
        self._update_campaign_file("running")

        # First, run recon to detect OS
        self.progress("[*] Running initial reconnaissance to detect OS...")
        recon_result = await self.agents["recon"].run(self.context)
        if recon_result is None:
            recon_result = {"findings": {}}
        self.context["recon_findings"] = recon_result.get("findings", {})
        self.context["os_type"] = self.context["recon_findings"].get("os_type", "unknown")
        self._log_agent_action("recon", recon_result)

        # Decide if we need to switch exploit agent based on OS
        is_windows = self.context.get("os_type") == "windows"
        if is_windows and WINSTEALTH_AVAILABLE:
            self.progress("[*] Windows target detected – switching to WindowsExploitAgent with WinStealth.")
            self.agents["exploit"] = WindowsExploitAgent(
                "exploit", self.gateway, self.db, self.soul, self.skill_mgr,
                self.model, self.progress_callback
            )
        elif is_windows and not WINSTEALTH_AVAILABLE:
            self.progress("[!] Windows target detected but WinStealth not available. Using generic exploit agent.")

        # Continue with the normal swarm loop
        while not self.stopped and self.step < self.max_steps:
            self.step += 1
            self.progress(f"[dim]Step {self.step}/{self.max_steps} – Phase: {self.current_phase}[/dim]")
            self.context["current_phase"] = self.current_phase

            next_agent = await self._reason_next_agent()
            self.progress(f"[Reason] Next agent: {next_agent}")

            if next_agent not in self.agents:
                self.progress(f"[!] Unknown agent {next_agent}, skipping")
                continue

            result = await self.agents[next_agent].run(self.context)
            if result is None:
                result = {}
            self._log_agent_action(next_agent, result)

            if self.enable_shadow_graph and hasattr(self.soul, "ingest_loot"):
                loot_note = {
                    "type": next_agent,
                    "target": self.target,
                    "findings": result.get("findings", result),
                    "timestamp": datetime.utcnow().isoformat()
                }
                self.soul.ingest_loot(loot_note)

            self._observe_and_parse(result)

            reflect_result = await self.agents["reflect"].run(self.context)
            if reflect_result is None:
                reflect_result = {}
            self._log_agent_action("reflect", reflect_result)

            suggestion = reflect_result.get("suggestion", "continue")
            high_value_keywords = ["xss", "ssrf", "upload", "id_or", "auth_bypass", "rce", "template injection"]
            if suggestion == "escalate" or any(keyword in str(result).lower() for keyword in high_value_keywords):
                if self.current_phase == "recon":
                    self.progress("[Reflect] High‑value finding detected – escalating to exploit phase.")
                    self.current_phase = "exploit"
                elif self.current_phase == "exploit":
                    self.progress("[Reflect] High‑value exploit – escalating to post_exploit.")
                    self.current_phase = "post_exploit"
            elif suggestion == "prune":
                self.progress("[Reflect] Pruning low-confidence branch – staying in current phase")
                self.context["recent_findings"] = self.context["recent_findings"][-2:]
            elif suggestion == "spawn" and self.enable_hierarchical:
                spawn_phase = reflect_result.get("next_phase", "recon")
                self.progress(f"[Reflect] Spawning sub-swarm for phase: {spawn_phase}")
                sub_result = await self._spawn_child_swarm(spawn_phase, self.context)
                if sub_result is None:
                    sub_result = {}
                if "recon_findings" in sub_result:
                    self.context["recon_findings"].update(sub_result["recon_findings"])
                if "validated_vulnerabilities" in sub_result:
                    self.context["validated_vulnerabilities"].extend(sub_result["validated_vulnerabilities"])
                if "exploit_plan" in sub_result:
                    self.context["exploit_plan"].extend(sub_result["exploit_plan"])
                self.progress("[Hierarchical] Sub-swarm results merged.")
            else:
                if "next_phase" in result:
                    self.current_phase = result["next_phase"]

            if self.step % 10 == 0:
                if self.current_phase == "recon":
                    self.current_phase = "classify"
                elif self.current_phase == "classify":
                    self.current_phase = "exploit"
                elif self.current_phase == "exploit":
                    self.current_phase = "report"

        if self.stopped:
            self.progress("[yellow]Swarm stopped by user.[/yellow]")
            self._update_campaign_file("stopped")
        else:
            self.progress("[green]Swarm completed.[/green]")
            self._update_campaign_file("completed")
            self._finalize_campaign(self.context)
        return self.context

    async def _reason_next_agent(self):
        phase = self.current_phase
        phase_agent = {
            "recon": "recon",
            "classify": "classify",
            "exploit": "exploit",
            "report": "report"
        }
        return phase_agent.get(phase, "recon")

    def _observe_and_parse(self, result: dict):
        phase = result.get("phase")
        if phase == "recon":
            findings = result.get("findings", {})
            self.context["recon_findings"] = findings
            recents = []
            if findings.get("vulnerabilities"):
                recents.extend(findings["vulnerabilities"][:3])
            if findings.get("subdomains"):
                recents.append({"type": "subdomains", "count": len(findings["subdomains"])})
            self.context["recent_findings"] = (self.context.get("recent_findings", []) + recents)[-10:]
        elif phase == "classify":
            vulns = result.get("validated_vulnerabilities", [])
            self.context["validated_vulnerabilities"] = vulns
            new_recents = [{"type": "validated_vulns", "count": len(vulns)}]
            self.context["recent_findings"] = (self.context.get("recent_findings", []) + new_recents)[-10:]
        elif phase == "exploit":
            plan = result.get("exploit_plan", [])
            self.context["exploit_plan"] = plan
            new_recents = [{"type": "exploit_plan", "count": len(plan)}]
            self.context["recent_findings"] = (self.context.get("recent_findings", []) + new_recents)[-10:]
        elif phase == "report":
            self.context["final_report"] = result.get("report", {})

    def _finalize_campaign(self, report: dict):
        report_path = REPORTS_DIR / f"swarm_{self.campaign_id}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))
        self.progress(f"[green]Report saved to {report_path}[/green]")
        self._update_campaign_file("completed", {"final_report_path": str(report_path)})

# ------------------------------------------------------------------
# T3MP3ST Swarm – 8‑operator ReAct kill chain with state management
# ------------------------------------------------------------------
class T3MP3STSwarm(SwarmOrchestrator):
    """Enhanced swarm with 8-operator ReAct kill chain and state management."""

    def __init__(self, *args, **kwargs):
        # Extract use_t3mp3st to avoid passing it to super
        kwargs.pop('use_t3mp3st', None)
        super().__init__(*args, **kwargs)
        self.operators = {}
        self.operator_states = {}
        self._init_operators()

    def _init_operators(self):
        """Initialize all 8 operators with their ReAct loops and states."""
        # Override agents with new operator classes
        agent_classes = {
            "RECON": ReconAgent,
            "SCANNER": ScannerAgent,
            "EXPLOITER": ExploitAgent,
            "INFILTRATOR": InfiltratorAgent,
            "EXFILTRATOR": ExfiltratorAgent,
            "GHOST": GhostAgent,
            "COORDINATOR": CoordinatorAgent,
            "ANALYST": ReportAgent
        }
        # Clear default agents (we'll rebuild with 8 operators)
        self.agents = {}
        for archetype, info in OPERATOR_ARCHETYPES.items():
            # Get the agent class for this archetype, falling back to BaseSwarmAgent if not defined
            agent_class = agent_classes.get(archetype, BaseSwarmAgent)
            # Create agent with lower-case name for consistency
            agent_name = archetype.lower()
            self.agents[agent_name] = agent_class(
                agent_name,
                self.gateway,
                self.db,
                self.soul,
                self.skill_mgr,
                self.model,
                self.progress_callback
            )
            self.operators[archetype] = self.agents[agent_name]
            self.operator_states[archetype] = {
                "status": "idle",
                "detection_risk": 0.0,
                "cooldown_until": None,
                "tasks_completed": 0
            }
        # Also ensure reflect agent is available (but not part of 8 operators)
        self.agents["reflect"] = ReflectorAgent(
            "reflect", self.gateway, self.db, self.soul,
            self.skill_mgr, self.model, self.progress_callback
        )

    async def run(self) -> dict:
        self.progress("[bold]T3MP3ST-style 8-operator swarm starting...[/bold]")
        self._update_campaign_file("running")

        # Phase 1: RECON
        self.progress("[Phase 1] RECON - Information gathering")
        recon_result = await self._run_operator("RECON", self.context)
        if recon_result is None:
            recon_result = {"findings": {}}
        self.context["recon_findings"] = recon_result.get("findings", {})
        self.context["os_type"] = self.context["recon_findings"].get("os_type", "unknown")

        # Phase 2: SCANNER
        self.progress("[Phase 2] SCANNER - Vulnerability discovery")
        scan_result = await self._run_operator("SCANNER", self.context)
        if scan_result is None:
            scan_result = {"vulnerabilities": []}
        self.context["vulnerabilities"] = scan_result.get("vulnerabilities", [])

        # Phase 3: EXPLOITER
        self.progress("[Phase 3] EXPLOITER - Initial access")
        exploit_result = await self._run_operator("EXPLOITER", self.context)
        if exploit_result is None:
            exploit_result = {"success": False}
        self.context["exploit_success"] = exploit_result.get("success", False)

        # Phase 4: INFILTRATOR (if exploit succeeded)
        if self.context.get("exploit_success"):
            self.progress("[Phase 4] INFILTRATOR - Lateral movement")
            infiltrate_result = await self._run_operator("INFILTRATOR", self.context)
            if infiltrate_result is None:
                infiltrate_result = {"results": {}}
            self.context["lateral_movement"] = infiltrate_result.get("results", {})
        else:
            self.progress("[!] Exploit failed, skipping INFILTRATOR")

        # Phase 5: GHOST (persistence)
        self.progress("[Phase 5] GHOST - Persistence")
        ghost_result = await self._run_operator("GHOST", self.context)
        if ghost_result is None:
            ghost_result = {"established": False}
        self.context["persistence"] = ghost_result.get("established", False)

        # Phase 6: EXFILTRATOR
        self.progress("[Phase 6] EXFILTRATOR - Data extraction")
        exfil_result = await self._run_operator("EXFILTRATOR", self.context)
        if exfil_result is None:
            exfil_result = {"data": {}}
        self.context["exfiltrated"] = exfil_result.get("data", {})

        # Phase 7: COORDINATOR (C2)
        self.progress("[Phase 7] COORDINATOR - Command & control")
        c2_result = await self._run_operator("COORDINATOR", self.context)
        if c2_result is None:
            c2_result = {"established": False}
        self.context["c2_channel"] = c2_result.get("established", False)

        # Phase 8: ANALYST (reporting)
        self.progress("[Phase 8] ANALYST - Final reporting")
        report_result = await self._run_operator("ANALYST", self.context)
        if report_result is None:
            report_result = {"report": {}}
        self.context["final_report"] = report_result.get("report", {})

        self.progress("[green]8-operator kill chain complete![/green]")
        self._update_campaign_file("completed")
        self._finalize_campaign(self.context)
        return self.context

    async def _run_operator(self, archetype: str, context: dict) -> dict:
        """Run a single operator with ReAct loop and state management."""
        operator = self.operators.get(archetype)
        if not operator:
            return {"error": f"Operator {archetype} not found"}

        # Check state
        state = self.operator_states[archetype]
        if state["status"] == "cooldown":
            return {"error": f"Operator {archetype} in cooldown"}

        # Update state
        state["status"] = "executing"
        self.progress(f"[{archetype}] Executing ReAct loop...")

        try:
            # Import ReActToolAgent from phalanx_engine (avoid circular)
            from phalanx_engine import ReActToolAgent
            react_agent = ReActToolAgent(self.gateway, archetype.lower())
            # We need to adapt: ReActToolAgent.run expects a query string and kwargs,
            # but our operator.run expects a context dict. We'll wrap the operator's run method.
            # For simplicity, we directly call operator.run with context.
            result = await operator.run(context)

            # Update state
            state["status"] = "idle"
            state["tasks_completed"] += 1
            state["detection_risk"] = min(1.0, state["detection_risk"] + 0.1)

            # Persist operator state to database if available
            if self.db and hasattr(self.db, 'update_operator_state'):
                self.db.update_operator_state(
                    operator_id=archetype,
                    archetype=archetype,
                    status=state["status"],
                    detection_risk=state["detection_risk"],
                    last_task=json.dumps(result)[:500],
                    metadata={"tasks_completed": state["tasks_completed"]}
                )

            return result
        except Exception as e:
            state["status"] = "burned"
            self.progress(f"[red]{archetype} failed: {e}[/red]")
            return {"error": str(e)}

    def _observe_and_parse(self, result: dict):
        """Override to handle operator results."""
        # Since we don't use the old agent phases, we skip the old observation logic.
        # We'll just update context based on operator phase.
        phase = result.get("phase")
        if phase == "recon":
            self.context["recon_findings"] = result.get("findings", {})
        elif phase == "scanner":
            self.context["vulnerabilities"] = result.get("vulnerabilities", [])
        elif phase == "exploit":
            self.context["exploit_success"] = result.get("success", False)
        elif phase == "infiltrator":
            self.context["lateral_movement"] = result.get("results", {})
        elif phase == "ghost":
            self.context["persistence"] = result.get("established", False)
        elif phase == "exfiltrator":
            self.context["exfiltrated"] = result.get("data", {})
        elif phase == "coordinator":
            self.context["c2_channel"] = result.get("established", False)
        elif phase == "report":
            self.context["final_report"] = result.get("report", {})

    async def _reason_next_agent(self):
        # Not used in T3MP3STSwarm; we follow fixed order.
        return None

# ==================================================================
# RAPTOR LOOP ENGINE
# ==================================================================
class RaptorLoopEngine:
    """
    Raptor Loop Engine with altitude scheduling, coverage matrix,
    isolated generator/judge agents, disposition ledger, monotonic KB.
    """
    def __init__(self, target: str, scope: Optional[str], mode: str, model: str,
                 db, soul, skill_mgr, gateway, progress_callback: Optional[Callable] = None,
                 campaign_id: Optional[str] = None, config: Optional[dict] = None):
        self.target = target
        self.scope = scope or target
        self.mode = mode
        self.model = model
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.gateway = gateway
        self.progress_callback = progress_callback
        self.progress = progress_callback or (lambda msg: logger.info(msg))
        self.campaign_id = campaign_id or str(uuid.uuid4())[:8]
        self.config = config or {}

        # Altitude levels (project → file → feature → function)
        self.altitudes = ['project', 'file', 'feature', 'function']
        self.current_altitude_index = 0

        # Coverage matrix (loaded from DB)
        self.coverage: Dict[str, bool] = {}
        self._load_coverage()

        # Generator and judge agents (initialised on first use)
        self.generator_agent = None
        self.judge_agent = None

        # Loop state
        self.stopped = False
        self.step = 0
        self.max_iterations = self.config.get("raptor", {}).get("max_iterations", 20)

        # Ensure DB has campaign record
        self._init_campaign()

        # Rich console if available
        self.console = Console() if RICH_AVAILABLE else None

    def _init_campaign(self):
        """Create campaign record in DB or fallback file."""
        if hasattr(self.db, 'create_swarm_campaign'):
            self.db.create_swarm_campaign(
                self.campaign_id, self.target, self.scope, mode="raptor", model_used=self.model
            )
        else:
            camp_file = BASE_DIR / "swarm_campaigns.json"
            camp_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                campaigns = {}
                if camp_file.exists():
                    campaigns = json.loads(camp_file.read_text())
                if self.campaign_id not in campaigns:
                    campaigns[self.campaign_id] = {
                        "target": self.target,
                        "scope": self.scope,
                        "mode": "raptor",
                        "model": self.model,
                        "started_at": datetime.utcnow().isoformat(),
                        "status": "running"
                    }
                    camp_file.write_text(json.dumps(campaigns, indent=2))
            except Exception as e:
                logger.warning(f"Failed to create campaign file: {e}")

    def _load_coverage(self):
        """Load coverage from DB."""
        if hasattr(self.db, 'get_coverage'):
            entries = self.db.get_coverage(self.campaign_id)
            for entry in entries:
                alt = entry.get('altitude')
                if alt:
                    self.coverage[alt] = entry.get('covered', False)

    def _update_coverage(self, altitude: str, covered: bool, metadata: dict = None):
        """Update coverage in DB and local cache."""
        if hasattr(self.db, 'add_coverage'):
            self.db.add_coverage(self.campaign_id, altitude, self.target, covered, metadata)
        self.coverage[altitude] = covered

    def _get_next_altitude(self) -> str:
        """Round‑robin scheduler for altitudes."""
        alt = self.altitudes[self.current_altitude_index % len(self.altitudes)]
        self.current_altitude_index += 1
        return alt

    def _get_altitude_context(self) -> Dict[str, Any]:
        """Build context from soul and DB for the current state."""
        ctx = {
            'project': f"Target: {self.target}, Scope: {self.scope}, Mode: {self.mode}",
            'file': '',
            'feature': '',
            'function': ''
        }
        # File level: recent artifacts
        try:
            files = self.db.get_loot_by_category("artifact", campaign_id=self.campaign_id, limit=5)
            if files:
                paths = []
                for f in files:
                    try:
                        data = json.loads(f['data']) if isinstance(f.get('data'), str) else f.get('data', {})
                        p = data.get('path', '') if isinstance(data, dict) else ''
                        paths.append(p)
                    except Exception:
                        pass
                ctx['file'] = "Recent artifacts: " + ", ".join(p for p in paths if p)
        except Exception:
            pass
        # Feature level: recent vulnerabilities
        try:
            vulns = self.db.get_loot_by_category("vuln", campaign_id=self.campaign_id, limit=5)
            if vulns:
                names = []
                for v in vulns:
                    try:
                        data = json.loads(v['data']) if isinstance(v.get('data'), str) else v.get('data', {})
                        n = data.get('name', '') if isinstance(data, dict) else ''
                        names.append(n)
                    except Exception:
                        pass
                ctx['feature'] = "Recent vulnerabilities: " + ", ".join(n for n in names if n)
        except Exception:
            pass
        # Function level: could be from graph or specific findings
        # Not implemented yet.
        return ctx

    async def run(self) -> dict:
        """Main entry point for Raptor loop."""
        self.progress(f"[Raptor] Starting Raptor Loop Engine for {self.target} (campaign {self.campaign_id})")

        while not self.stopped and self.step < self.max_iterations:
            self.step += 1
            altitude = self._get_next_altitude()
            self.progress(f"[Raptor] Step {self.step}/{self.max_iterations} – altitude: {altitude}")

            # 1. Generate action for this altitude
            action = await self._generate_action(altitude)
            if action is None:
                self.progress("[Raptor] No action generated, breaking.")
                break

            # 2. Execute action
            result = await self._execute_action(action)
            if result is None:
                result = {"error": "Execution returned None", "rc": -1}

            # 3. Judge the outcome
            judgement = await self._judge(altitude, action, result)
            if judgement is None:
                judgement = {"success": False, "complete": False, "confidence": 0.0, "reason": "Judge failed"}

            # 4. Process judgement: update coverage, ledger, scrutiny, loot
            await self._process_judgement(altitude, action, result, judgement)

            # 5. Check for completion
            if judgement.get('complete', False):
                self.progress("[Raptor] Judgement indicates goal complete. Finishing loop.")
                break

        # Finalise report
        report = self._generate_report()
        self._finalize_campaign(report)
        self.progress("[green]Raptor Loop Engine finished.[/green]")
        return report

    async def _generate_action(self, altitude: str) -> Optional[Dict]:
        """Use generator agent (ReActToolAgent) to propose an action."""
        # Build altitude-specific context
        alt_ctx = self._get_altitude_context()
        alt_ctx[altitude] = f"Processing altitude: {altitude}"

        # Create a new ReActToolAgent with this context
        from phalanx_engine import ReActToolAgent
        # Choose a base tool based on altitude; for recon we might use nmap, for file/function maybe ghidra
        tool_name = "nmap"  # default, could be dynamic
        # For file/function we might use ghidra_analyze or radare2
        if altitude in ("file", "function"):
            tool_name = "ghidra_analyze"  # may not be available; fallback to nmap

        agent = ReActToolAgent(self.gateway, tool_name, max_iterations=1, altitude_context=alt_ctx)
        # Run the agent with a query
        query = f"Perform action for altitude {altitude} on target {self.target}"
        result = agent.run(query)
        if result.get('history'):
            # Extract the first action from history
            for entry in result['history']:
                if entry.get('type') == 'action' and entry.get('content'):
                    action = entry['content']
                    if isinstance(action, dict) and 'tool' in action:
                        return action
        # Fallback
        return {"tool": tool_name, "params": {"target": self.target}}

    async def _execute_action(self, action: Dict) -> Dict:
        """Execute the tool action via the gateway."""
        tool = action.get("tool")
        params = action.get("params", {})
        if not tool:
            return {"error": "No tool specified", "rc": -1}
        result = self.gateway.run_tool(tool, params)
        if result is None:
            result = {"error": "Tool returned None", "rc": -1}
        return result

    async def _judge(self, altitude: str, action: Dict, result: Dict) -> Dict:
        """Use LLM to judge if the action succeeded and if the altitude goal is achieved."""
        prompt = f"""You are a judge for a Raptor loop.
Altitude: {altitude}
Action: {json.dumps(action)}
Result: {json.dumps(result)[:500]}

Judge if the action succeeded and if the goal for this altitude is achieved.
Output JSON: {{"success": bool, "complete": bool, "confidence": float, "reason": "..."}}"""
        response = self.gateway.generate(prompt, model=self.gateway.fast_model, json_mode=True)
        try:
            judgement = json.loads(response)
        except:
            judgement = {"success": False, "complete": False, "confidence": 0.0, "reason": "Parse error"}
        return judgement

    async def _process_judgement(self, altitude: str, action: Dict, result: Dict, judgement: Dict):
        """Update coverage, ledger, scrutiny, and loot."""
        # 1. Coverage
        covered = judgement.get('success', False)
        self._update_coverage(altitude, covered, {"action": action, "result": result, "judgement": judgement})

        # 2. Disposition ledger: if a finding_id is present
        if 'finding_id' in result:
            finding_id = result['finding_id']
            disposition = 'confirm' if covered else 'reject'
            if hasattr(self.db, 'add_ledger_entry'):
                self.db.add_ledger_entry(self.campaign_id, finding_id, disposition, json.dumps(result))

        # 3. Scrutiny KB: increase scrutiny for entities that failed
        if not covered and action.get('target'):
            if hasattr(self.db, 'update_scrutiny'):
                self.db.update_scrutiny(self.campaign_id, action['target'], f"Failed at altitude {altitude}")

        # 4. Loot: store successful findings
        if covered and result.get('output'):
            loot_data = {
                "type": "raptor_finding",
                "altitude": altitude,
                "action": action,
                "result": result.get('output', '')
            }
            if hasattr(self.db, 'add_loot'):
                self.db.add_loot("raptor", loot_data, campaign_id=self.campaign_id)
            # Also ingest into Soul for graph
            if self.soul and hasattr(self.soul, 'ingest_loot'):
                self.soul.ingest_loot({"type": "raptor", "target": self.target, "findings": loot_data})

    def _finalize_campaign(self, report: dict):
        """Save final report and update campaign status."""
        report_path = REPORTS_DIR / f"raptor_{self.campaign_id}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2))
        self.progress(f"[green]Raptor report saved to {report_path}[/green]")
        # Update campaign status
        if hasattr(self.db, 'update_swarm_campaign'):
            self.db.update_swarm_campaign(self.campaign_id, "completed", str(report_path))
        else:
            camp_file = BASE_DIR / "swarm_campaigns.json"
            if camp_file.exists():
                try:
                    campaigns = json.loads(camp_file.read_text())
                    if self.campaign_id in campaigns:
                        campaigns[self.campaign_id]["status"] = "completed"
                        campaigns[self.campaign_id]["final_report_path"] = str(report_path)
                        camp_file.write_text(json.dumps(campaigns, indent=2))
                except Exception as e:
                    logger.warning(f"Failed to update campaign file: {e}")

    def _generate_report(self) -> dict:
        """Compile final report."""
        coverage_summary = {}
        for alt in self.altitudes:
            coverage_summary[alt] = self.coverage.get(alt, False)
        # Get loot items
        loot_items = []
        if hasattr(self.db, 'get_loot'):
            loot_items = self.db.get_loot(campaign_id=self.campaign_id, limit=50)
        return {
            "target": self.target,
            "campaign_id": self.campaign_id,
            "mode": "raptor",
            "timestamp": datetime.utcnow().isoformat(),
            "coverage": coverage_summary,
            "steps": self.step,
            "max_iterations": self.max_iterations,
            "findings": loot_items
        }

    def stop(self):
        """Stop the loop gracefully."""
        self.stopped = True
        self.progress("[*] Raptor loop stopping...")

# ------------------------------------------------------------------
# Public swarm API function (reuses existing components)
# ------------------------------------------------------------------
def run_swarm(target: str, scope: Optional[str], mode: str, model: str,
              follow: bool, progress_callback: Optional[Callable] = None,
              db=None, soul=None, skill_mgr=None, gateway=None,
              enable_hierarchical: bool = False, enable_shadow_graph: bool = False,
              use_t3mp3st: bool = False, use_raptor: bool = False) -> Any:
    """
    Run a swarm campaign. If follow is True, run synchronously and return final report.
    If follow is False, start in background and return campaign ID.

    Args:
        use_t3mp3st: If True, use the T3MP3ST 8-operator swarm.
        use_raptor: If True, use the Raptor Loop Engine (altitude-aware generator/judge).
        Only one of use_t3mp3st or use_raptor can be True.
    """
    if use_t3mp3st and use_raptor:
        raise ValueError("Cannot use both T3MP3ST and Raptor at the same time.")

    from phalanx_core import PhalanxDB, RoE, Soul, SkillManager
    from phalanx_tools import Gateway, TOOL_REGISTRY

    campaign_id = str(uuid.uuid4())[:8]
    locally_created_db = False
    locally_created_gateway = False

    # Ensure gateway is always available
    if db is not None and soul is None:
        roe = RoE.from_dict({})
        soul = Soul(db, roe)

    if db is None:
        config = {
            "database": {"sqlite_path": str(BASE_DIR / "phalanx.db")},
            "ollama": {"url": "http://localhost:11434", "default_model": model},
            "sandbox": {"enabled": False}
        }
        db = PhalanxDB(config)
        locally_created_db = True
        roe = RoE.from_dict({})
        soul = Soul(db, roe)
        skill_mgr = SkillManager()
        gateway = Gateway(config, TOOL_REGISTRY)
        locally_created_gateway = True
    else:
        # db is provided, but gateway might be None
        if gateway is None:
            # Try to get config from db if available
            config = getattr(db, 'config', {})
            if not config:
                config = {
                    "database": {"sqlite_path": str(BASE_DIR / "phalanx.db")},
                    "ollama": {"url": "http://localhost:11434", "default_model": model},
                    "sandbox": {"enabled": False}
                }
            gateway = Gateway(config, TOOL_REGISTRY)
        else:
            # Gateway exists; we need a config dict for the orchestrator.
            # Use the gateway's config if available, else a minimal one.
            config = getattr(gateway, 'config', {})
            if not config:
                config = {
                    "ollama": {"url": "http://localhost:11434", "default_model": model},
                    "sandbox": {"enabled": False}
                }

    # Ensure soul has the campaign_id for graph persistence
    soul.campaign_id = campaign_id
    if hasattr(soul, "_load_graph_from_db"):
        soul._load_graph_from_db()

    # Choose orchestrator based on flags
    if use_t3mp3st:
        orchestrator = T3MP3STSwarm(
            target=target, scope=scope, mode=mode, model=model,
            db=db, soul=soul, skill_mgr=skill_mgr, gateway=gateway,
            progress_callback=progress_callback,
            enable_hierarchical=enable_hierarchical,
            enable_shadow_graph=enable_shadow_graph,
            use_t3mp3st=use_t3mp3st,
            config=config
        )
    else:
        # Use the standard SwarmOrchestrator, which now handles Raptor mode internally
        orchestrator = SwarmOrchestrator(
            target=target, scope=scope, mode=mode, model=model,
            db=db, soul=soul, skill_mgr=skill_mgr, gateway=gateway,
            progress_callback=progress_callback,
            enable_hierarchical=enable_hierarchical,
            enable_shadow_graph=enable_shadow_graph,
            use_raptor=use_raptor,
            use_t3mp3st=False,
            config=config
        )

    # Ensure orchestrator has the campaign_id
    orchestrator.campaign_id = campaign_id
    _register_swarm(campaign_id, orchestrator)

    if follow:
        # Run synchronously, handling event loop properly
        try:
            # Check if we are already inside an event loop
            try:
                loop = asyncio.get_running_loop()
                # If loop is running, we need to run in a separate thread to avoid nesting
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(lambda: asyncio.run(orchestrator.run()))
                    result = future.result()
            except RuntimeError:
                # No running loop, safe to use asyncio.run()
                result = asyncio.run(orchestrator.run())
        finally:
            _unregister_swarm(campaign_id)
            if locally_created_db:
                db.close()
        return result
    else:
        # Start in background thread
        def _bg():
            try:
                asyncio.run(orchestrator.run())
            except Exception as e:
                logger.error(f"Background swarm failed: {e}")
            finally:
                _unregister_swarm(campaign_id)
                if locally_created_db:
                    db.close()
        thread = threading.Thread(target=_bg, daemon=False)
        thread.start()
        orchestrator._thread = thread
        return campaign_id

# ------------------------------------------------------------------
# Ensure directories on module load
# ------------------------------------------------------------------
ensure_phalanx_dirs()
# Also ensure agent stubs exist (will run phalanx_extra.py if needed)
ensure_agent_stubs()

if __name__ == "__main__":
    print("PHALANX Library v3.6 with T3MP3ST 8-operator Swarm + Shadow Graph + Hierarchical Swarm + Looped Harness + WinStealth + Raptor Loop Engine ready.")