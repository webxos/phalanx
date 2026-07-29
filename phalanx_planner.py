#!/usr/bin/env python3
"""
PHALANX v3.8 – Standalone Planner CLI and Public API.

Generates an engagement plan (OPPLAN) for a given target using the PlannerAgent
if available, otherwise falls back to a static (but realistic) plan.

This module provides both a CLI interface and a programmatic function
`generate_engagement_plan` that can be imported and used by other PHALANX
components. It includes robust fallback logic to ensure a valid plan is
always returned.

Enhancements (v3.8):
- Corrected `safe_run_tool` wrapper to match `Gateway.run_tool` signature.
- `--json` CLI flag now properly disables logging to keep stdout pure.
- Deep copy of config prevents shared state and latent mutation bugs.
- Optimized `_collect_source_files` using `os.walk` to prune heavy directories
  (like `node_modules`) early, significantly improving Raptor demo performance.
- Robust `generate_engagement_plan` fallback chain (static plan guaranteed).
- Metasploitable container support gracefully degrades if Docker is missing.
- Explicit Ollama connectivity check with actionable diagnostics.
- **NEW**: Plans now include a `tasks` field with actionable shell/tool commands.
- **NEW**: `--with-tasks` CLI flag to include tasks in the output.
- **NEW**: `generate_action_plan()` function to produce a list of tool invocations.
"""

from __future__ import annotations

import sys
import os
import json
import logging
import argparse
import subprocess
import shutil
import re
import copy
import time
import traceback
from pathlib import Path
from typing import Dict, Optional, List, Any, Callable, Tuple

# ------------------------------------------------------------------
# Configure logging
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger("phalanx_planner")

# ------------------------------------------------------------------
# Centralized paths – robust PROJECT_ROOT detection
# ------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent

# If we are not in the project root, walk up to find a 'phalanx' directory.
if not (PROJECT_ROOT / "phalanx").exists():
    for parent in PROJECT_ROOT.parents:
        if (parent / "phalanx").exists():
            PROJECT_ROOT = parent
            break
    else:
        logger.warning(
            "Could not locate project root containing 'phalanx' directory. "
            "Using current directory."
        )
        PROJECT_ROOT = Path.cwd()

PHALANX_DIR = PROJECT_ROOT / "phalanx"
CONFIG_CANDIDATES = [
    PHALANX_DIR / "config" / "config.json",
    PROJECT_ROOT / "config.json",
    Path.home() / ".phalanx" / "config.json",
]

DEFAULT_CONFIG: Dict[str, Any] = {
    "ollama": {
        "url": "http://localhost:11434",
        "default_model": "qwen2.5:0.5b",
        "fast_model": "qwen2.5:0.5b",
    },
    "sandbox": {"enabled": False},
    "raptor": {
        "iterations": 3,
        "max_files": 50,
    },
}

# Metasploitable container configuration
METASPLOITABLE_IMAGE = "tleemcbbc/metasploitable2"
METASPLOITABLE_CONTAINER_NAME = "phalanx-metasploitable"

# Add project root to sys.path so local imports work in any CWD.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ------------------------------------------------------------------
# Core imports with graceful fallback
# ------------------------------------------------------------------
Gateway = None  # type: ignore
TOOL_REGISTRY: Dict[str, Any] = {}

try:
    from phalanx_tools import Gateway as _Gateway, TOOL_REGISTRY as _TOOL_REGISTRY  # type: ignore
    Gateway = _Gateway
    TOOL_REGISTRY = _TOOL_REGISTRY or {}
except ImportError as e:
    logger.error(f"Failed to import phalanx_tools: {e}")
    logger.error("Make sure you are running from the PHALANX root directory.")
    logger.error("If you are in the correct directory, try: python phalanx_extra.py --force")

# Optional Raptor engine import (lazy / soft dependency)
# If phalanx_raptor is not installed, the built-in fallback loop is used.
RaptorLoopEngine: Optional[Callable[..., Any]] = None
try:
    from phalanx_raptor import RaptorLoopEngine as _RaptorLoopEngine  # type: ignore
    RaptorLoopEngine = _RaptorLoopEngine
except Exception as e:  # pragma: no cover - optional dependency
    logger.debug(f"phalanx_raptor.RaptorLoopEngine not available: {e}")


# ------------------------------------------------------------------
# Configuration loader with explicit error messages
# ------------------------------------------------------------------
def _load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from a JSON file, merging with defaults."""
    # Use true deep copy to prevent shared state across calls
    config_data: Dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)

    if config_path is None:
        for candidate in CONFIG_CANDIDATES:
            if candidate.exists():
                config_path = candidate
                break
        else:
            logger.debug("No configuration file found. Using defaults.")
            return config_data

    if not config_path.exists():
        logger.debug(f"Configuration file not found: {config_path}. Using defaults.")
        return config_data

    try:
        user_config = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(user_config, dict):
            raise ValueError("Top-level JSON is not an object.")
        # Deep-merge defaults to preserve required subkeys (lightweight models).
        _deep_merge(config_data, user_config)
        return config_data
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from {config_path}: {e}")
        logger.warning("Using default configuration instead.")
        return copy.deepcopy(DEFAULT_CONFIG)
    except Exception as e:
        logger.error(f"Unexpected error loading config from {config_path}: {e}")
        logger.warning("Using default configuration instead.")
        return copy.deepcopy(DEFAULT_CONFIG)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
    """Recursively merge `override` into `base` (mutates `base`)."""
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


# ------------------------------------------------------------------
# Helper to create Gateway with graceful fallback
# ------------------------------------------------------------------
def _create_gateway(config: Dict[str, Any]) -> Optional[Any]:
    """Create a Gateway instance and test Ollama connectivity."""
    if Gateway is None:
        logger.warning("Gateway class not available (phalanx_tools missing).")
        return None
    try:
        gateway = Gateway(config, TOOL_REGISTRY)
        # Test Ollama connection (explicit check, with a short timeout fallback).
        check_fn = getattr(gateway, "check_ollama", None)
        ok = False
        if callable(check_fn):
            try:
                ok = bool(check_fn())
            except Exception as inner:
                logger.debug(f"check_ollama raised: {inner}")
                ok = False
        else:
            logger.debug("Gateway has no check_ollama() method; assuming reachable.")
            ok = True

        if not ok:
            logger.warning("Ollama not reachable. Static plan will be used.")
            return None
        return gateway
    except Exception as e:
        logger.warning(f"Gateway initialization failed: {e}. Using static plan only.")
        return None


# ------------------------------------------------------------------
# Safe run_tool wrapper – guards every gateway.run_tool result
# ------------------------------------------------------------------
def safe_run_tool(gateway: Any, tool_name: str, **kwargs) -> Optional[Any]:
    """
    Invoke `gateway.run_tool` with full guarding.
    Returns the tool result on success, or None on any failure.
    Correctly maps kwargs to the `params` argument expected by Gateway.
    """
    if gateway is None:
        logger.debug(f"safe_run_tool('{tool_name}') called with no gateway.")
        return None
    run_fn = getattr(gateway, "run_tool", None)
    if not callable(run_fn):
        logger.warning(f"Gateway has no callable run_tool ('{tool_name}' skipped).")
        return None
    try:
        # Gateway.run_tool expects: run_tool(tool_name, params=dict, parse_output=bool)
        result = run_fn(tool_name, params=kwargs, parse_output=True)
        if result is None:
            logger.debug(f"run_tool('{tool_name}') returned None.")
        return result
    except Exception as e:
        logger.warning(f"run_tool('{tool_name}') raised: {e}")
        return None


# ------------------------------------------------------------------
# Plan validation helper – extended to handle "tasks" field
# ------------------------------------------------------------------
def _validate_plan(plan: Any) -> bool:
    """Validate that the plan has the required structure."""
    if not isinstance(plan, dict):
        return False
    if "objectives" not in plan or not isinstance(plan["objectives"], list):
        return False
    if "roe" not in plan or not isinstance(plan["roe"], dict):
        return False
    # "tasks" is optional, but if present it must be a list of dicts
    if "tasks" in plan and not isinstance(plan["tasks"], list):
        return False
    for obj in plan["objectives"]:
        if not isinstance(obj, dict) or "description" not in obj:
            return False
    return True


def _repair_plan(plan: Dict[str, Any], target: str, user_input: str,
                 reason: str) -> Dict[str, Any]:
    """Repair a plan in-place to ensure mandatory keys exist."""
    required_keys = ["objectives", "roe", "schema_version"]
    for key in required_keys:
        if key not in plan:
            logger.error(f"Plan missing required key '{key}' – adding empty value.")
            if key == "objectives":
                plan[key] = []
            elif key == "roe":
                plan[key] = {}
            else:
                plan[key] = "2.0"

    roe_defaults = {
        "allowed_targets": [target] if target else [],
        "excluded_targets": [],
        "forbidden_actions": ["data_exfiltration", "destruction",
                              "ransomware", "denial_of_service"],
        "require_human_confirm": ["privilege_escalation", "exploit",
                                  "auth_bypass", "idor", "data_modification",
                                  "race_condition", "c2_deployment"],
        "max_severity": "critical",
    }
    plan["roe"] = plan.get("roe") or {}
    for k, v in roe_defaults.items():
        if k not in plan["roe"]:
            plan["roe"][k] = v

    plan.setdefault("user_input", user_input)
    plan.setdefault("generated_by", "static_fallback")
    plan.setdefault("fallback_reason", reason)
    # Ensure tasks field exists (may be empty)
    plan.setdefault("tasks", [])
    return plan


# ------------------------------------------------------------------
# Helper: generate default tasks from objectives
# ------------------------------------------------------------------
def _generate_default_tasks(target: str, objectives: List[Dict]) -> List[Dict[str, Any]]:
    """
    Convert a list of objectives into a set of actionable tool invocations.
    This provides a simple mapping from objective keywords to typical tools.
    """
    tasks = []
    # Simple keyword-to-tool mapping
    tool_map = {
        "reconnaissance": [{"tool": "nmap", "params": {"target": target, "options": "-sV -p- --open"},
                            "description": "Full port scan with service detection"},
                           {"tool": "whatweb", "params": {"target": target},
                            "description": "Web technology fingerprint"}],
        "vulnerability assessment": [{"tool": "nuclei", "params": {"target": target, "severity": "critical,high"},
                                      "description": "Run nuclei for critical/high vulnerabilities"}],
        "exploitation": [{"tool": "searchsploit", "params": {"query": f"{target}"},
                          "description": "Search for known exploits"},
                         {"tool": "msfconsole", "params": {"resource": "exploit/example.rc"},
                          "description": "Launch Metasploit resource script (placeholder)"}],
        "post-exploitation": [{"tool": "enum4linux", "params": {"target": target},
                               "description": "SMB enumeration"},
                              {"tool": "secretsdump", "params": {"target": target},
                               "description": "Dump credentials (requires credentials)"}],
        "reporting": [],  # no specific tools
    }

    for obj in objectives:
        desc = obj["description"].lower()
        for keyword, tool_list in tool_map.items():
            if keyword in desc:
                tasks.extend(tool_list)
                break

    # Add a generic web scan if target is likely a web server
    if any(kw in target for kw in ["http", "https", "www."]) or not tasks:
        tasks.append({
            "tool": "nikto",
            "params": {"target": target},
            "description": "Web server vulnerability scan"
        })
        tasks.append({
            "tool": "gobuster",
            "params": {"target": target, "wordlist": "/usr/share/wordlists/dirb/common.txt"},
            "description": "Directory brute-force"
        })

    # Remove duplicates by (tool, params) tuple
    seen = set()
    unique_tasks = []
    for task in tasks:
        key = (task["tool"], json.dumps(task["params"], sort_keys=True))
        if key not in seen:
            seen.add(key)
            unique_tasks.append(task)
    return unique_tasks[:10]  # limit to 10 tasks


# ------------------------------------------------------------------
# Static fallback plan generator (no LLM) – with strict validation
# ------------------------------------------------------------------
def _static_plan(target: str, user_input: str = "", reason: str = "") -> Dict[str, Any]:
    """
    Generate a comprehensive static plan when PlannerAgent is unavailable.
    Structure matches expectations of `RoEEnforcer` and `AutonomousPentest`.
    Validates and repairs the plan to ensure mandatory keys exist.
    Now includes a `tasks` field with default actionable steps.
    """
    if reason:
        logger.warning(f"Static plan used because: {reason}")
    else:
        logger.info("Using static plan generator (PlannerAgent not available).")

    # Strict sanitization – allow only safe characters for hostnames/IPs.
    safe_target = re.sub(r'[^a-zA-Z0-9\.\-_:]', '', target or "")[:100]
    safe_user_input = re.sub(r'[^a-zA-Z0-9\s\.\-_,/]', '', user_input or "")[:200]

    if not safe_target:
        safe_target = "unknown-target"

    objectives: List[Dict[str, Any]] = [
        {
            "description": (f"Reconnaissance of {safe_target} – discover open "
                            f"ports, services, subdomains, and technologies"),
            "mitre_tags": ["T1595", "T1046"],
            "evidence_guided": False,
        },
        {
            "description": (f"Vulnerability assessment of {safe_target} – scan "
                            f"for known CVEs, misconfigurations, and logical flaws"),
            "mitre_tags": ["T1595.002", "T1190"],
            "evidence_guided": False,
        },
        {
            "description": (f"Exploitation of {safe_target} – attempt to "
                            f"compromise via highest severity vulnerabilities "
                            f"(RCE, SQLi, XSS, etc.)"),
            "mitre_tags": ["T1190", "T1210"],
            "evidence_guided": True,
        },
        {
            "description": (f"Post-exploitation and pivoting – extract "
                            f"credentials, establish persistence, and map "
                            f"lateral movement"),
            "mitre_tags": ["T1003", "T1059"],
            "evidence_guided": True,
        },
        {
            "description": ("Reporting – generate final report with findings, "
                            "evidence, and remediation recommendations"),
            "mitre_tags": [],
            "evidence_guided": False,
        },
    ]

    logical_bugs = [
        "Identify IDOR vulnerabilities in API endpoints",
        "Test for authentication bypass (JWT, session fixation)",
        "Check for CSRF and race conditions in sensitive actions",
    ]
    if any(term in safe_user_input.lower()
           for term in ["web", "api", "app", "bug"]):
        for bug in logical_bugs:
            objectives.insert(2, {
                "description": bug,
                "mitre_tags": ["T1190", "T1555"],
                "evidence_guided": True,
            })

    roe = {
        "allowed_targets": [safe_target],
        "excluded_targets": [],
        "forbidden_actions": ["data_exfiltration", "destruction",
                              "ransomware", "denial_of_service"],
        "require_human_confirm": ["privilege_escalation", "exploit",
                                  "auth_bypass", "idor", "data_modification",
                                  "race_condition", "c2_deployment"],
        "max_severity": "critical",
    }

    # Generate default tasks based on objectives
    tasks = _generate_default_tasks(safe_target, objectives)

    plan = {
        "objectives": objectives,
        "roe": roe,
        "tasks": tasks,  # <-- NEW: actionable steps
        "user_input": safe_user_input,
        "generated_by": "static_fallback",
        "fallback_reason": (reason if reason
                            else "PlannerAgent not available or LLM unreachable"),
        "schema_version": "2.1",  # version bump to indicate tasks support
    }

    # Final validation / repair – never trust the generator entirely.
    _repair_plan(plan, safe_target, safe_user_input,
                 plan.get("fallback_reason", ""))
    return plan


# ------------------------------------------------------------------
# Lazy import for PlannerAgent (may not be installed)
# ------------------------------------------------------------------
def _get_planning_function() -> Optional[Callable[..., Any]]:
    """
    Attempt to import `generate_engagement_plan` from phalanx_library.
    Returns the function or None if unavailable.
    """
    try:
        from phalanx_library import generate_engagement_plan as lib_generate  # type: ignore
        if not callable(lib_generate):
            logger.debug("phalanx_library.generate_engagement_plan is not callable.")
            return None
        return lib_generate
    except ImportError as e:
        logger.debug(f"phalanx_library.generate_engagement_plan not available: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error importing phalanx_library: {e}")
        return None


# ------------------------------------------------------------------
# Public API function – extended to include tasks
# ------------------------------------------------------------------
def generate_engagement_plan(target: str, user_input: str = "",
                             gateway: Optional[Any] = None,
                             include_tasks: bool = False) -> Dict[str, Any]:
    """
    Generate an engagement plan (OPPLAN) for a given target.

    Attempts to use the AI-powered PlannerAgent if available, otherwise
    falls back to a static plan. Designed to be called from other PHALANX
    components (e.g., AutonomousPentest).

    Args:
        target: Target hostname or IP address.
        user_input: Optional additional context or instructions.
        gateway: Optional Gateway instance (a default one will be created
            if not supplied).
        include_tasks: If True, the plan will include a `tasks` field with
            actionable steps (tool invocations). Defaults to False for
            backward compatibility.

    Returns:
        A dictionary containing the plan with 'objectives', 'roe', and
        optionally 'tasks'. A plan is **always** returned.
    """
    config = _load_config()

    if gateway is None:
        gateway = _create_gateway(config)
        if gateway is None:
            logger.warning("No valid Gateway; static plan will be used.")

    plan_func = _get_planning_function()

    plan: Optional[Dict[str, Any]] = None
    fallback_reason = ""

    if plan_func and gateway:
        try:
            logger.info(f"Generating AI-driven plan for {target}")
            plan = plan_func(target, user_input, gateway)
            if not _validate_plan(plan):
                raise ValueError(
                    "AI plan failed validation (missing required keys)."
                )
            # Repair minor structural gaps (e.g., missing roe subkeys).
            plan = _repair_plan(plan, target, user_input, "ai_planner")
            plan.setdefault("generated_by", "ai_planner")
            # If tasks are requested and not present, generate from objectives
            if include_tasks and "tasks" not in plan:
                plan["tasks"] = _generate_default_tasks(target, plan["objectives"])
            return plan
        except Exception as e:
            logger.error(f"AI planning failed: {e}. Falling back to static plan.")
            logger.debug(traceback.format_exc())
            fallback_reason = f"AI planning exception: {e}"
    else:
        if not plan_func:
            fallback_reason = ("PlannerAgent not available "
                               "(phalanx_library missing or import error)")
        elif not gateway:
            fallback_reason = "Ollama unreachable or Gateway initialization failed"
        else:
            fallback_reason = "Unknown reason (missing plan_func or gateway)"

    # Actionable diagnostics for the most common failure modes.
    if "Ollama" in fallback_reason:
        logger.warning("Make sure Ollama is running: `ollama serve`")
    elif "phalanx_library" in fallback_reason:
        logger.warning("Try running 'python phalanx_extra.py --force' "
                       "to install missing components.")

    plan = _static_plan(target, user_input, reason=fallback_reason)

    # If tasks are not needed, we could remove them, but we keep them.
    # If include_tasks is False, we can drop the tasks field to save space,
    # but we'll keep them by default (the static plan already includes them).
    # For backward compatibility, if include_tasks is False, we remove tasks.
    if not include_tasks and "tasks" in plan:
        del plan["tasks"]

    # Last-resort safety net – should be unreachable.
    if plan is None:
        logger.error("Static plan unexpectedly None – emergency fallback.")
        plan = _static_plan(
            target, user_input,
            reason="Emergency fallback after both AI and static plan failed",
        )
        if not include_tasks and "tasks" in plan:
            del plan["tasks"]

    return plan


# ------------------------------------------------------------------
# Metasploitable container management (graceful Docker-less operation)
# ------------------------------------------------------------------
def _docker_available() -> bool:
    """Return True if the `docker` CLI is on PATH and responsive."""
    docker_path = shutil.which("docker")
    if not docker_path:
        return False
    try:
        proc = subprocess.run(
            [docker_path, "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError) as e:
        logger.debug(f"docker info failed: {e}")
        return False


def ensure_metasploitable_container(
    image: str = METASPLOITABLE_IMAGE,
    container_name: str = METASPLOITABLE_CONTAINER_NAME,
    ports: Optional[Dict[str, int]] = None,
) -> Optional[str]:
    """
    Ensure a Metasploitable container is running. Returns the container IP
    (or '127.0.0.1') on success, or None if Docker is unavailable / startup
    failed. **Never raises** – prints warnings and continues.
    """
    if ports is None:
        ports = {"22": 2222, "80": 8080, "445": 4455, "21": 2121}

    if not _docker_available():
        logger.warning(
            "Docker is not installed or not running. Skipping container startup; "
            "demo will continue with limited functionality."
        )
        return None

    docker = shutil.which("docker")
    try:
        # Check if container exists (running or stopped).
        exists = subprocess.run(
            [docker, "ps", "-a", "--filter", f"name=^{container_name}$",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15,
        )
        if exists.returncode != 0:
            logger.warning(f"docker ps failed: {exists.stderr.strip()}")
            return None

        already_exists = container_name in (exists.stdout or "").split()

        if already_exists:
            # Ensure it's running.
            subprocess.run(
                [docker, "start", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            logger.info(f"Container '{container_name}' started.")
        else:
            # Pull image (best-effort).
            logger.info(f"Pulling image {image} (may take a while)...")
            pull = subprocess.run(
                [docker, "pull", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600,
            )
            if pull.returncode != 0:
                logger.warning(f"docker pull failed: {pull.stderr.strip()}")
                return None

            port_args: List[str] = []
            for host_port, container_port in ports.items():
                port_args += ["-p", f"{host_port}:{container_port}"]

            run = subprocess.run(
                [docker, "run", "-d", "--name", container_name,
                 *port_args, image],
                capture_output=True, text=True, timeout=60,
            )
            if run.returncode != 0:
                logger.warning(f"docker run failed: {run.stderr.strip()}")
                return None
            logger.info(f"Container '{container_name}' created and started.")

        # Inspect for IP address.
        time.sleep(2)
        inspect = subprocess.run(
            [docker, "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
             container_name],
            capture_output=True, text=True, timeout=15,
        )
        ip = (inspect.stdout or "").strip() if inspect.returncode == 0 else ""
        if not ip:
            ip = "127.0.0.1"
            logger.info("Container has no detectable bridge IP; "
                        "falling back to host port mapping (127.0.0.1).")
        else:
            logger.info(f"Metasploitable reachable at {ip}")
        return ip

    except subprocess.TimeoutExpired:
        logger.warning("Docker operation timed out. Continuing without container.")
        return None
    except FileNotFoundError:
        logger.warning("Docker binary not found at runtime. Continuing without container.")
        return None
    except Exception as e:
        logger.warning(f"Unexpected Docker error: {e}. Continuing without container.")
        return None


# ------------------------------------------------------------------
# Raptor loop demo – verification against a local codebase
# ------------------------------------------------------------------
def _default_raptor_codebase() -> Optional[Path]:
    """Pick a reasonable default codebase for the Raptor demo."""
    candidates = [
        PROJECT_ROOT,
        PROJECT_ROOT / "metasploitable",
        PROJECT_ROOT / "phalanx",
        Path.home() / "metasploitable",
    ]
    for c in candidates:
        if c.exists() and c.is_dir():
            return c
    return None


def run_raptor_demo(
    codebase_path: Optional[Path] = None,
    iterations: int = 3,
    max_files: int = 50,
    gateway: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Run a short Raptor loop against a local codebase for verification.

    Uses `RaptorLoopEngine` from phalanx_raptor if available; otherwise
    runs a minimal local approximation that iterates over source files
    and produces a hierarchical summary. Always returns a result dict –
    never raises.
    """
    config = _load_config()
    if gateway is None:
        gateway = _create_gateway(config)

    if codebase_path is None:
        codebase_path = _default_raptor_codebase()

    result: Dict[str, Any] = {
        "engine": "RaptorLoopEngine" if RaptorLoopEngine else "builtin_minimal",
        "codebase": str(codebase_path) if codebase_path else None,
        "iterations": iterations,
        "max_files": max_files,
        "summaries": [],
        "findings": [],
        "errors": [],
    }

    if codebase_path is None or not Path(codebase_path).exists():
        msg = ("No codebase path provided and no default found. "
               "Pass --raptor-target PATH.")
        logger.warning(msg)
        result["errors"].append(msg)
        return result

    codebase_path = Path(codebase_path)

    # Preferred path: use the real RaptorLoopEngine.
    if RaptorLoopEngine is not None:
        try:
            engine = RaptorLoopEngine(
                codebase_path=str(codebase_path),
                gateway=gateway,
                iterations=iterations,
                max_files=max_files,
            )
            loop_result = engine.run() if hasattr(engine, "run") else None
            if isinstance(loop_result, dict):
                result["summaries"] = loop_result.get("summaries", [])
                result["findings"] = loop_result.get("findings", [])
                if loop_result.get("errors"):
                    result["errors"].extend(loop_result["errors"])
            elif isinstance(loop_result, list):
                result["summaries"] = loop_result
            else:
                result["errors"].append("RaptorLoopEngine.run() returned unexpected type.")
            logger.info(f"Raptor loop completed: {len(result['summaries'])} summaries, "
                        f"{len(result['findings'])} findings.")
            return result
        except Exception as e:
            logger.warning(f"RaptorLoopEngine failed; using builtin minimal loop: {e}")
            logger.debug(traceback.format_exc())
            result["errors"].append(f"RaptorLoopEngine error: {e}")

    # Fallback: minimal local Raptor-like iteration over source files.
    try:
        source_files = _collect_source_files(codebase_path, max_files)
        result["files_scanned"] = len(source_files)
        for i in range(iterations):
            tier_summaries: List[str] = []
            batch = source_files[i::iterations] or source_files
            for fp in batch:
                try:
                    snippet = _read_head(fp)
                    tier_summaries.append(f"[iter {i}] {fp.name}: {snippet}")
                except Exception as inner:
                    result["errors"].append(f"read {fp}: {inner}")
            result["summaries"].extend(tier_summaries)
            logger.info(f"Raptor (builtin) iter {i}: summarized "
                        f"{len(tier_summaries)} files.")
        # Heuristic findings
        if gateway is not None:
            result["findings"].append(
                "Gateway available – real Raptor engine recommended for full "
                "semantic verification."
            )
        else:
            result["findings"].append(
                "No LLM gateway – only structural/statistical summaries produced."
            )
    except Exception as e:
        logger.error(f"Builtin Raptor loop failed: {e}")
        result["errors"].append(f"builtin loop error: {e}")

    return result


def _collect_source_files(root: Path, max_files: int) -> List[Path]:
    """
    Collect a bounded list of source files under `root`.
    Uses `os.walk` and prunes skip directories in-place for performance.
    """
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                 "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
    exts = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".c",
            ".h", ".cpp", ".cc", ".sh", ".yml", ".yaml", ".conf", ".json"}
    collected: List[Path] = []
    
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place to prevent os.walk from descending into them
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        
        for filename in filenames:
            filepath = Path(dirpath) / filename
            if filepath.suffix.lower() in exts:
                collected.append(filepath)
                if len(collected) >= max_files:
                    return collected
    return collected


def _read_head(path: Path, max_bytes: int = 256) -> str:
    """Read the first bytes of a file as a compact snippet."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            data = fh.read(max_bytes)
        data = re.sub(r'\s+', ' ', data).strip()
        return data[:200]
    except Exception as e:
        return f"<unreadable: {e}>"


# ------------------------------------------------------------------
# CLI entry point – extended with --with-tasks flag
# ------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phalanx_planner.py",
        description="Generate a PHALANX engagement plan (OPPLAN) for a target.",
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="Target hostname or IP (e.g., example.com).")
    parser.add_argument("user_input", nargs="?", default="",
                        help="Optional context / instructions (quote it).")
    parser.add_argument("--raptor-demo", action="store_true",
                        help="Run a short Raptor loop against a local codebase "
                             "for verification after generating the plan.")
    parser.add_argument("--raptor-target", default=None,
                        help="Codebase path for the Raptor demo "
                             "(default: auto-detect).")
    parser.add_argument("--raptor-iters", type=int, default=3,
                        help="Number of Raptor iterations (default: 3).")
    parser.add_argument("--metasploitable", action="store_true",
                        help="Attempt to start a Metasploitable container "
                             "and use its IP as the target.")
    parser.add_argument("--json", action="store_true",
                        help="Emit only the plan as JSON (suppresses log output to stdout).")
    parser.add_argument("--with-tasks", action="store_true",
                        help="Include actionable tasks (tool invocations) in the plan.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable DEBUG logging.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line interface for generating a plan."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
        
    # If --json is explicitly requested, disable logging entirely so that 
    # stdout contains pure JSON output (useful for piping to other tools).
    if args.json:
        logging.disable(logging.CRITICAL)

    # Optionally spin up Metasploitable container.
    target = args.target
    if args.metasploitable:
        ip = ensure_metasploitable_container()
        if ip:
            target = target or ip
            logger.info(f"Using Metasploitable container IP as target: {ip}")
        else:
            logger.warning("Metasploitable container unavailable; "
                           "continuing with limited functionality.")
            if not target:
                target = "127.0.0.1"

    if not target:
        parser.error("target is required (or use --metasploitable).")

    # Generate the plan via the public API.
    plan = generate_engagement_plan(target, args.user_input,
                                    include_tasks=args.with_tasks)

    # Optional Raptor demo.
    raptor_result: Optional[Dict[str, Any]] = None
    if args.raptor_demo:
        raptor_codebase = (Path(args.raptor_target)
                           if args.raptor_target else None)
        logger.info("Starting Raptor demo loop...")
        raptor_result = run_raptor_demo(
            codebase_path=raptor_codebase,
            iterations=args.raptor_iters,
        )
        plan["raptor_demo"] = raptor_result

    # Output plan as JSON.
    try:
        print(json.dumps(plan, indent=2, default=str))
    except Exception as e:
        logger.error(f"Failed to serialize plan to JSON: {e}")
        return 1

    # Non-zero exit code when degraded (static fallback used).
    if plan.get("generated_by") == "static_fallback":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())