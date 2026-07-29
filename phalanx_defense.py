#!/usr/bin/env python3
"""
PHALANX v3.6 Cross-Platform – Defense Mode (LavaWall Enhanced + War Room API)
Simple background monitor that prints alerts to the normal CLI.
No TUI, no screen takeover.

FIXES applied (v3.5):
- _GEO_UPDATE_THREAD explicitly initialized
- self.metrics["start_time"] uses datetime.now()
- Graceful fallback if GitPython is not installed
- Increased alert cooldown to 10 seconds to prevent duplicate alerts
- GeoIP endpoint changed to HTTPS with User-Agent header
- Metrics collected even in standby mode (risk counting moved outside standby block)
- Added explicit checks for required dependencies (psutil) with clear error messages
- Added warning for missing sentence-transformers (embedder optional)

NEW (v3.6):
- Reverse‑engineering tool detection – alerts when known RE tools are executed.
- LavaWall enhancements: VPN toggle, system metrics, firewall status, WiFiScanner.
- War Room API (FastAPI) endpoints for defense status, logs, export, missions, findings, graph.
- OGhidra malware pattern detection integration (optional).
- Start War Room server in background thread function.
- /defense CLI extended with wifi, vpn, metrics, firewall, config.
- Ledger integration: defense alerts can be recorded in the disposition ledger
  via config flag `defense.ledger_integration: true` and a campaign_id
  `defense.campaign_id` (default "defense").

NEW (v3.6.2) – Raptor Insights Integration:
- Defense monitor now queries Raptor loop data (coverage, ledger, scrutiny) to
  enrich alerts with contextual information.
- For each HIGH/MED connection, if the remote IP matches a target in the Raptor
  campaign, the alert will include:
    * Raptor coverage status (whether the target has been scanned at various altitudes)
    * Raptor scrutiny level (monotonic suspicion score)
    * Disposition ledger entries related to that target
- Alert risk can be dynamically escalated if scrutiny level exceeds a configurable threshold.
- New CLI command: `/defense raptor [ip]` to display Raptor insights for the current campaign.
- Integration with Raptor ledger: alerts are recorded in the disposition ledger
  (already implemented via `add_ledger_entry`).

EXPORTS:
- get_defense_monitor() – returns the global monitor instance.
- app – FastAPI app for War Room (if FastAPI is installed).
- start_warroom_server() – starts the War Room HTTP server in a background thread.

IMPROVEMENTS (v3.6):
- Better error message when FastAPI/uvicorn are missing, with installation instructions.
- start_warroom_server now returns a clear error message if dependencies are missing.
- Added debug logging for import failures.
- Fixed FastAPI conditional import: app is defined only when FastAPI is available.
- Proper GeoIP thread cleanup on exit.
- Safe GitPython import with warning.
- Global monitor access is now thread-safe with a lock.
- calculate_risk logic simplified with clearer port and process checks.

NEW FIXES in this version:
- Added health endpoint (`/api/health`) with DB connection retry (3 attempts).
- CORS origins are now configurable via PHALANX_CORS_ORIGINS environment variable
  (comma-separated); defaults to ["*"] for development.
- Health endpoint checks database connectivity and returns status accordingly.
- War Room server start function ensures monitor is ready (no race).
- LavaWallManager.__init__ now safely handles None config.
- Added clarifying comments for fallback behavior in WiFiScanner.scan.
- WiFiScanner.scan now properly parses airodump-ng CSV output, extracting real BSSIDs
  and network counts. It also checks for root privileges and interface existence.
- Improved CSV parsing robustness: detects header line dynamically, stops at blank line.
- Added more informative messages when airodump-ng fails or produces no data.
- Added graceful handling of missing netifaces (optional) and sudo password requirements.
"""

import time
import threading
import requests
import json
import logging
import sys
import os
import platform
import shutil
import subprocess
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from collections import deque

# ------------------------------------------------------------------
# Logger must be defined early so it can be used in import blocks
# ------------------------------------------------------------------
logger = logging.getLogger("phalanx.defense")
logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------
# Required dependencies – with clear error messages
# ------------------------------------------------------------------
try:
    import psutil
except ImportError as e:
    raise ImportError(
        "psutil is required for defense mode. Install it with: pip install psutil"
    ) from e

# Optional Rich for coloured output
RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    pass

if RICH_AVAILABLE:
    console = Console()
else:
    console = None

# GitPython – optional
GIT_AVAILABLE = False
try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    git = None
    logger.warning("GitPython not installed. Git logging disabled.")

# FastAPI / Uvicorn – optional for War Room
FASTAPI_AVAILABLE = False
UVICORN_AVAILABLE = False
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.debug(
        "FastAPI not installed – War Room endpoints will be disabled. "
        "To enable, run: pip install fastapi uvicorn[standard] python-multipart aiofiles"
    )

try:
    import uvicorn
    UVICORN_AVAILABLE = True
except ImportError:
    UVICORN_AVAILABLE = False
    logger.debug(
        "Uvicorn not installed – War Room server will not start. "
        "To enable, run: pip install uvicorn[standard]"
    )

# Optional netifaces for interface checking (WiFiScanner)
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    netifaces = None
    NETIFACES_AVAILABLE = False
    logger.debug("netifaces not installed – interface existence check skipped.")

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
BASE_DIR = Path.cwd() / "phalanx"
DEFENSE_LOGS_DIR = BASE_DIR / "defense_logs"
GIT_REPO_PATH = DEFENSE_LOGS_DIR / "git_repo"

# ------------------------------------------------------------------
# Reverse‑engineering tool detection – known process names and path patterns
# ------------------------------------------------------------------
REVERSE_TOOL_NAMES = {
    # Android / Java
    "jadx", "apktool", "dex2jar", "jd-gui", "bytecode-viewer",
    # Binary / static analysis
    "radare2", "r2", "ida", "idat", "ida64", "ghidra", "ghidraRun",
    "objdump", "strings", "nm", "readelf", "gdb", "lldb",
    # Dynamic instrumentation
    "frida", "frida-server", "frida-gadget", "frida-trace",
    "objection", "cycript",
    # Decompilers / disassemblers
    "dnSpy", "ILSpy", "dotPeek", "decompiler",
    # Custom scripts
    "deobfuscate", "ollvm-deobfuscator", "unflatten",
    # Python reverse tools (often invoked via python)
    "python.*jadx", "python.*apktool", "python.*frida",
}

def is_reverse_tool_process(proc_name: str, proc_path: str) -> bool:
    """
    Check if the given process name or path matches known reverse‑engineering tools.
    Returns True if a match is found.
    """
    if not proc_name and not proc_path:
        return False
    lower_name = proc_name.lower() if proc_name else ""
    lower_path = proc_path.lower() if proc_path else ""

    for tool in REVERSE_TOOL_NAMES:
        if tool in lower_name:
            return True
        if tool in lower_path:
            return True
    return False

# ------------------------------------------------------------------
# GeoIP with background updater (thread-safe)
# ------------------------------------------------------------------
_GEO_CACHE: Dict[str, str] = {}
_GEO_CACHE_LOCK = threading.RLock()
_GEO_UPDATE_QUEUE = deque(maxlen=5000)
_GEO_UPDATE_THREAD: Optional[threading.Thread] = None
_GEOIP_ENABLED = True
_GEOIP_LOCK = threading.Lock()
_GEOIP_STOP_EVENT = threading.Event()

def set_geoip_enabled(enabled: bool) -> None:
    global _GEOIP_ENABLED
    with _GEOIP_LOCK:
        _GEOIP_ENABLED = enabled

def _geoip_updater() -> None:
    while not _GEOIP_STOP_EVENT.is_set():
        ip = None
        with _GEO_CACHE_LOCK:
            if _GEO_UPDATE_QUEUE:
                ip = _GEO_UPDATE_QUEUE.popleft()
                if ip in _GEO_CACHE:
                    continue
        if ip:
            try:
                resp = requests.get(
                    f"https://ip-api.com/json/{ip}?fields=country,city,org",
                    timeout=2,
                    headers={"User-Agent": "PHALANX-Defense/3.6"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    geo = f"{data.get('country','?')} | {data.get('city','?')} | {data.get('org','?')[:25]}"
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[ip] = geo
                else:
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[ip] = "Unknown"
            except Exception:
                with _GEO_CACHE_LOCK:
                    _GEO_CACHE[ip] = "Unknown"
        time.sleep(0.5)

def start_geoip_updater() -> None:
    global _GEO_UPDATE_THREAD
    with _GEOIP_LOCK:
        if not _GEOIP_ENABLED:
            return
    if _GEO_UPDATE_THREAD is None or not _GEO_UPDATE_THREAD.is_alive():
        _GEOIP_STOP_EVENT.clear()
        _GEO_UPDATE_THREAD = threading.Thread(target=_geoip_updater, daemon=True)
        _GEO_UPDATE_THREAD.start()

def stop_geoip_updater() -> None:
    """Stop the GeoIP updater thread and clear the queue."""
    _GEOIP_STOP_EVENT.set()
    if _GEO_UPDATE_THREAD and _GEO_UPDATE_THREAD.is_alive():
        _GEO_UPDATE_THREAD.join(timeout=2.0)
    with _GEO_CACHE_LOCK:
        _GEO_UPDATE_QUEUE.clear()

def get_geoip(ip: str) -> str:
    if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return "Local"
    with _GEOIP_LOCK:
        if not _GEOIP_ENABLED:
            return "Disabled"
    with _GEO_CACHE_LOCK:
        if ip in _GEO_CACHE:
            return _GEO_CACHE[ip]
        if ip not in _GEO_UPDATE_QUEUE:
            _GEO_UPDATE_QUEUE.append(ip)
        return "Fetching..."

# ------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------
def is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    suspicious = [
        "/tmp/", "/dev/shm/", "/var/tmp/", ".tmp",
        "python", "node", "bash", "sh", "perl", "ruby"
    ]
    return any(s in path.lower() for s in suspicious)

def calculate_risk(conn, proc, detect_reverse: bool = True) -> Tuple[str, str]:
    """
    Calculate risk level for a network connection.
    If detect_reverse is True, also check for reverse‑engineering tool processes.
    """
    risk = "LOW"
    reason = ""
    laddr = getattr(conn, 'laddr', None)
    raddr = getattr(conn, 'raddr', None)
    port = getattr(laddr, 'port', 0) if laddr else 0
    remote_ip = getattr(raddr, 'ip', None) if raddr else None
    remote_port = getattr(raddr, 'port', 0) if raddr else 0
    status = getattr(conn, 'status', '')

    high_risk_ports = {
        21, 23, 445, 139, 3389, 5900, 4444, 1337, 8080, 6667, 6668, 6669
    }
    if port in high_risk_ports or remote_port in high_risk_ports:
        risk = "HIGH"
        reason = f"High-risk port {port if port in high_risk_ports else remote_port}"
    elif remote_ip and remote_ip not in ("127.0.0.1", "::1") and status == "ESTABLISHED":
        proc_path = ""
        proc_name = ""
        if proc:
            try:
                proc_path = proc.exe()
                proc_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                pass
        if is_suspicious_path(proc_path):
            risk = "HIGH"
            reason = "Suspicious process path"
        elif detect_reverse and is_reverse_tool_process(proc_name, proc_path):
            risk = "MED"
            reason = f"Reverse engineering tool detected: {proc_name or 'unknown'}"
        else:
            risk = "MED"
            reason = "Outbound connection to internet"
    return risk, reason

# ------------------------------------------------------------------
# Defense Policy Engine
# ------------------------------------------------------------------
class DefensePolicyEngine:
    def __init__(self, policy_path: Path = BASE_DIR / "policies" / "defense.yaml"):
        self.policy_path = policy_path
        self.policy = self._load_policy()

    def _load_policy(self) -> Dict:
        # In production, load from YAML. For now, fallback to default.
        return {
            "name": "default",
            "rules": [
                {"name": "alert_high_risk", "condition": "risk == 'HIGH'", "action": "alert", "notify": True},
                {"name": "log_medium_risk", "condition": "risk == 'MED'", "action": "log", "notify": False},
                {"name": "alert_reverse_tool", "condition": "risk == 'MED' and 'reverse' in reason", "action": "alert", "notify": True},
                # NEW: Raptor insight escalation
                {"name": "escalate_raptor_scrutiny", "condition": "risk == 'MED' and 'raptor_scrutiny' in conn_info and conn_info['raptor_scrutiny'] > 3", "action": "alert", "notify": True},
            ],
            "default_action": "log"
        }

    def evaluate(self, conn_info: Dict) -> Dict:
        risk = conn_info.get("risk", "LOW")
        reason = conn_info.get("reason", "")
        # Check Raptor scrutiny level if present
        if "raptor_scrutiny" in conn_info:
            scrutiny = conn_info["raptor_scrutiny"]
            # If scrutiny is high, we can elevate risk even if it's MED
            if risk == "MED" and scrutiny > 3:
                risk = "HIGH"
                reason += " (Raptor scrutiny escalation)"
        for rule in self.policy.get("rules", []):
            cond = rule.get("condition", "")
            # Simplified evaluation for known conditions
            if cond == "risk == 'HIGH'" and risk == "HIGH":
                return {
                    "action": rule.get("action", "log"),
                    "rule_name": rule.get("name", "unnamed"),
                    "notify": rule.get("notify", False)
                }
            elif cond == "risk == 'MED' and 'reverse' in reason" and risk == "MED" and "reverse" in reason.lower():
                return {
                    "action": rule.get("action", "log"),
                    "rule_name": rule.get("name", "unnamed"),
                    "notify": rule.get("notify", False)
                }
            elif cond == "risk == 'MED'" and risk == "MED":
                return {
                    "action": rule.get("action", "log"),
                    "rule_name": rule.get("name", "unnamed"),
                    "notify": rule.get("notify", False)
                }
            elif cond == "risk == 'MED' and 'raptor_scrutiny' in conn_info and conn_info['raptor_scrutiny'] > 3" and risk == "MED" and conn_info.get("raptor_scrutiny", 0) > 3:
                return {
                    "action": "alert",
                    "rule_name": "escalate_raptor_scrutiny",
                    "notify": True
                }
        return {
            "action": self.policy.get("default_action", "log"),
            "rule_name": "default",
            "notify": False
        }

# ------------------------------------------------------------------
# LavaWall Manager – VPN, system metrics, firewall status
# ------------------------------------------------------------------
class LavaWallManager:
    def __init__(self, config: Dict):
        # Guard against None config
        self.config = config or {}
        lavawall_cfg = self.config.get("lavawall", {})
        self.wifi_interface = lavawall_cfg.get("wifi_interface", "wlan0")
        self.scan_duration = lavawall_cfg.get("scan_duration", 30)
        self.vpn_config_path = lavawall_cfg.get("vpn_config_path", "/etc/openvpn/client.ovpn")
        self.metrics_interval = lavawall_cfg.get("metrics_interval", 5)

        self.vpn_active = False
        self.vpn_process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._metrics_thread: Optional[threading.Thread] = None
        self._stop_metrics = threading.Event()
        self._cached_metrics = {}
        self._last_scan_time = None

    def _metrics_collector(self):
        while not self._stop_metrics.is_set():
            self._cached_metrics = self._get_system_metrics()
            time.sleep(self.metrics_interval)

    def start_metrics_collector(self):
        if self._metrics_thread is None or not self._metrics_thread.is_alive():
            self._stop_metrics.clear()
            self._metrics_thread = threading.Thread(target=self._metrics_collector, daemon=True)
            self._metrics_thread.start()

    def stop_metrics_collector(self):
        self._stop_metrics.set()
        if self._metrics_thread and self._metrics_thread.is_alive():
            self._metrics_thread.join(timeout=2.0)

    def _get_system_metrics(self) -> Dict:
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "net_connections": len(psutil.net_connections()),
            "timestamp": datetime.now().isoformat()
        }

    def get_system_metrics(self) -> Dict:
        if self._metrics_thread and self._metrics_thread.is_alive():
            return self._cached_metrics
        return self._get_system_metrics()

    def toggle_vpn(self, action: str) -> str:
        if action == "on":
            if self.vpn_active:
                return "VPN already active."
            if not self.vpn_config_path or not Path(self.vpn_config_path).exists():
                return f"VPN config file not found: {self.vpn_config_path}"
            cmd = ["sudo", "openvpn", "--config", self.vpn_config_path]
            try:
                # Use subprocess.Popen with proper error handling; capture stderr for debugging
                self.vpn_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True
                )
                # Wait a moment to see if it starts; non-blocking check
                time.sleep(0.5)
                if self.vpn_process.poll() is not None:
                    # Process exited immediately; read stderr
                    _, stderr = self.vpn_process.communicate()
                    return f"VPN failed to start: {stderr.strip() or 'unknown error'}"
                self.vpn_active = True
                return f"VPN started (config: {self.vpn_config_path})."
            except Exception as e:
                return f"Failed to start VPN: {e}"
        elif action == "off":
            if not self.vpn_active:
                return "VPN not active."
            if self.vpn_process:
                self.vpn_process.terminate()
                try:
                    self.vpn_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.vpn_process.kill()
            self.vpn_active = False
            return "VPN stopped."
        return "Invalid action. Use 'on' or 'off'."

    def get_firewall_status(self) -> str:
        if platform.system() == "Linux":
            try:
                result = subprocess.run(
                    ["sudo", "iptables", "-L", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return "Firewall active (iptables)."
                return f"Firewall status unknown (return code {result.returncode})."
            except subprocess.TimeoutExpired:
                return "Firewall check timed out."
            except Exception as e:
                return f"Failed to check firewall: {e}"
        return "Firewall check not implemented for this OS."

# ------------------------------------------------------------------
# WiFi Scanner – uses airodump‑ng for RF environment reconnaissance
# ------------------------------------------------------------------
class WiFiScanner:
    def __init__(self, lava_manager: LavaWallManager):
        self.lava_manager = lava_manager

    def _check_sudo(self) -> bool:
        """Check if sudo is available without password (or we are root)."""
        if os.geteuid() == 0:
            return True
        try:
            # Try sudo -n (non-interactive) to see if passwordless sudo works
            subprocess.run(["sudo", "-n", "true"], check=True, timeout=2,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    def scan(self, interface: str = "wlan0", duration: int = 10) -> Dict:
        """
        Perform a Wi-Fi scan using airodump-ng.
        Returns a dict with status, networks_found, bssids, and messages.
        """
        if not shutil.which("airodump-ng"):
            return {
                "status": "error",
                "message": "airodump‑ng not installed. Please install aircrack-ng.",
                "networks_found": 0,
                "bssids": []
            }

        # Check if interface exists (optional)
        if NETIFACES_AVAILABLE:
            if interface not in netifaces.interfaces():
                return {
                    "status": "error",
                    "message": f"Interface {interface} does not exist.",
                    "networks_found": 0,
                    "bssids": []
                }
        else:
            logger.debug("netifaces not available; skipping interface existence check.")

        # Check for sudo/root
        if not self._check_sudo():
            return {
                "status": "error",
                "message": "sudo requires a password or is not configured. Please run as root or set NOPASSWD in sudoers.",
                "networks_found": 0,
                "bssids": []
            }

        out_file = Path("/tmp/lavawall_scan")
        # Use sudo only if not root
        cmd = []
        if os.geteuid() != 0:
            cmd.append("sudo")
        cmd.extend(["airodump-ng", interface,
                    "--write", str(out_file),
                    "--output-format", "csv",
                    "--duration", str(duration)])

        try:
            # Use check=False to handle errors gracefully
            result = subprocess.run(
                cmd,
                timeout=duration + 5,
                stderr=subprocess.PIPE,
                text=True,
                stdin=subprocess.DEVNULL  # prevent waiting for password
            )
            if result.returncode != 0:
                return {
                    "status": "error",
                    "message": f"airodump-ng failed (return code {result.returncode}): {result.stderr.strip()}",
                    "networks_found": 0,
                    "bssids": []
                }
            self.lava_manager._last_scan_time = datetime.now().isoformat()

            csv_file = Path("/tmp/lavawall_scan-01.csv")
            networks_found = 0
            bssids = []
            if csv_file.exists():
                # Parse CSV: airodump-ng format has a header line starting with "BSSID"
                # followed by data lines, then a blank line, then station lines.
                # We'll read until a blank line after the header.
                try:
                    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    # Find the line that starts with "BSSID" (header)
                    header_idx = None
                    for i, line in enumerate(lines):
                        if line.strip().startswith("BSSID"):
                            header_idx = i
                            break
                    if header_idx is not None:
                        # We'll process lines from header_idx+1 until we hit a blank line
                        # or a line that doesn't look like a network data line.
                        # Network data lines have at least one comma and start with a MAC address.
                        import csv
                        # Build a list of data lines
                        data_lines = []
                        for line in lines[header_idx+1:]:
                            stripped = line.strip()
                            if not stripped:
                                break  # blank line separates networks from stations
                            # Also, station lines sometimes start with "Station MAC" - skip those
                            if stripped.startswith("Station MAC"):
                                break
                            data_lines.append(line)
                        if data_lines:
                            # Use DictReader on the header + data lines
                            reader = csv.DictReader([lines[header_idx]] + data_lines)
                            for row in reader:
                                bssid = row.get('BSSID', '').strip()
                                if bssid and bssid != "BSSID":
                                    bssids.append(bssid)
                                    networks_found += 1
                except Exception as e:
                    logger.warning(f"Failed to parse airodump-ng CSV: {e}")
                    return {
                        "status": "partial",
                        "message": f"Scan completed but CSV parsing failed: {e}",
                        "interface": interface,
                        "duration": duration,
                        "networks_found": 0,
                        "bssids": [],
                        "output_file": str(csv_file)
                    }
            else:
                return {
                    "status": "error",
                    "message": f"CSV file {csv_file} not found after scan.",
                    "networks_found": 0,
                    "bssids": []
                }

            return {
                "status": "success",
                "interface": interface,
                "duration": duration,
                "networks_found": networks_found,
                "bssids": bssids[:20],  # limit to 20 for brevity
                "message": f"Scan completed on {interface} for {duration}s. Found {networks_found} networks.",
                "output_file": str(csv_file) if csv_file.exists() else None
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": f"Scan timed out after {duration+5}s.", "networks_found": 0, "bssids": []}
        except Exception as e:
            return {"status": "error", "message": str(e), "networks_found": 0, "bssids": []}

# ------------------------------------------------------------------
# Global monitor instance with thread-safe access
# ------------------------------------------------------------------
_WARROOM_MONITOR: Optional["NetWatchMonitor"] = None
_MONITOR_LOCK = threading.RLock()

def get_defense_monitor() -> Optional["NetWatchMonitor"]:
    """Return the global defense monitor instance for War Room endpoints."""
    with _MONITOR_LOCK:
        return _WARROOM_MONITOR

def _set_defense_monitor(monitor: Optional["NetWatchMonitor"]) -> None:
    """Internal: set the global monitor instance."""
    with _MONITOR_LOCK:
        global _WARROOM_MONITOR
        _WARROOM_MONITOR = monitor

# ------------------------------------------------------------------
# NetWatchMonitor – simplified notification system (now with LavaWall + Raptor)
# ------------------------------------------------------------------
class NetWatchMonitor:
    def __init__(self, gateway=None, soul=None, db=None, config: Optional[Dict] = None):
        self.gateway = gateway
        self.soul = soul
        self.db = db
        # Guard against None config
        self.config = config or {}

        self.running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.standby_mode = self.config.get("defense", {}).get("standby", True)
        self.detect_reverse_tools = self.config.get("defense", {}).get("detect_reverse_tools", True)
        self.git_enabled = self.config.get("defense", {}).get("git_enabled", True)
        self.git_repo = self._init_git_repo()

        # Embedder (optional)
        self.embedder = None
        embed_cfg = self.config.get("embed", {})
        if embed_cfg.get("enabled", True):
            try:
                from sentence_transformers import SentenceTransformer
                model_name = embed_cfg.get("model", "all-MiniLM-L6-v2")
                self.embedder = SentenceTransformer(model_name)
            except ImportError:
                logger.warning("sentence-transformers not installed – embedder disabled.")
            except Exception as e:
                logger.warning(f"Failed to load embedder: {e}")

        self.low_profile = embed_cfg.get("low_profile", False) or os.environ.get("PHALANX_LOW_PROFILE", "0") == "1"

        # Connection tracking
        self._alert_cooldown: Dict[Tuple[str, str], float] = {}
        self._cooldown_seconds = 15.0  # increased from 10 to reduce spam
        self._lock = threading.RLock()
        self.policy_engine = DefensePolicyEngine()

        self.metrics = {
            "start_time": datetime.now(),
            "total_connections_seen": 0,
            "high_risk_count": 0,
            "alert_count": 0,
            "last_alert_time": None,
        }

        geoip_enabled = self.config.get("defense", {}).get("geoip_enabled", True)
        set_geoip_enabled(geoip_enabled)
        start_geoip_updater()

        # LavaWall
        self.lava_manager = LavaWallManager(config)
        self.wifi_scanner = WiFiScanner(self.lava_manager)

        # Register this instance as the global monitor
        _set_defense_monitor(self)

        # OGhidra integration (optional)
        self.oghidra_enabled = self.config.get("oghidra", {}).get("enabled", True)
        self._run_oghidra_analyze = None
        if self.oghidra_enabled:
            try:
                from phalanx_tools import run_oghidra_analyze
                self._run_oghidra_analyze = run_oghidra_analyze
                logger.info("OGhidra malware detection enabled.")
            except ImportError:
                self.oghidra_enabled = False
                logger.warning("OGhidra tools not available – malware detection disabled.")
            except Exception as e:
                self.oghidra_enabled = False
                logger.warning(f"OGhidra initialization failed: {e}")

        # Cache for malware checks to avoid repeated analysis of same binary
        self._malware_cache: Dict[str, List[Dict]] = {}
        self._malware_cache_lock = threading.Lock()

        # Raptor ledger integration
        defense_cfg = self.config.get("defense", {})
        self.ledger_integration = defense_cfg.get("ledger_integration", False)
        self.campaign_id_for_ledger = defense_cfg.get("campaign_id", "defense")

        # Raptor campaign ID (if available from soul)
        self._raptor_campaign_id = None
        if self.soul and hasattr(self.soul, 'campaign_id'):
            self._raptor_campaign_id = self.soul.campaign_id

    def _init_git_repo(self) -> Optional[Any]:
        if not self.git_enabled or not GIT_AVAILABLE:
            return None
        try:
            GIT_REPO_PATH.mkdir(parents=True, exist_ok=True)
            if (GIT_REPO_PATH / ".git").exists():
                return git.Repo(GIT_REPO_PATH)
            else:
                repo = git.Repo.init(GIT_REPO_PATH)
                (GIT_REPO_PATH / ".gitignore").write_text("*.log\n*.tmp\n")
                repo.index.add([".gitignore"])
                repo.index.commit("Initial commit: PHALANX defense logs")
                return repo
        except Exception as e:
            logger.error(f"Failed to init git repo: {e}")
            return None

    def log_to_git(self, event_type: str, data: Dict) -> None:
        if not self.git_enabled or not self.git_repo or not GIT_AVAILABLE:
            return
        try:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filepath = GIT_REPO_PATH / f"{ts}_{event_type}.json"
            filepath.write_text(json.dumps(data, indent=2, default=str))
            self.git_repo.index.add([str(filepath)])
            self.git_repo.index.commit(f"[{event_type}] {data.get('summary', '')[:80]}")
        except Exception as e:
            logger.warning(f"Git logging failed: {e}")

    def _print_alert(self, message: str, style: str = "red"):
        if RICH_AVAILABLE and console:
            console.print(message, style=style)
        else:
            print(message)

    # ------------------------------------------------------------------
    # Raptor Insights integration
    # ------------------------------------------------------------------
    def _get_raptor_insight_for_target(self, target_ip: str) -> Optional[Dict]:
        """
        Query Raptor loop data (coverage, ledger, scrutiny) for a given IP address.
        Returns a dict with coverage, ledger entries, and scrutiny level, or None if no data.
        """
        if not self.db or not self._raptor_campaign_id:
            return None
        try:
            # Try to find if this IP appears as a target in any coverage entry
            coverage = self.db.get_coverage(self._raptor_campaign_id)
            # Filter coverage entries where target matches the IP
            target_entries = [c for c in coverage if c.get('target') == target_ip]
            if not target_entries:
                # If no direct match, maybe the IP is a host in the graph? We can check later.
                return None

            # Get scrutiny for this IP (if any)
            scrutiny_entries = self.db.get_scrutiny(self._raptor_campaign_id, entity=target_ip)
            scrutiny_level = 0
            if scrutiny_entries:
                scrutiny_level = max(e.get('scrutiny_level', 0) for e in scrutiny_entries)

            # Get ledger entries related to this IP (by finding_id or evidence)
            # For simplicity, we'll fetch all ledger entries and filter by evidence containing the IP
            ledger_entries = self.db.get_ledger(self._raptor_campaign_id, limit=100)
            relevant_ledger = [e for e in ledger_entries if target_ip in e.get('evidence_receipt', '')]

            return {
                "target": target_ip,
                "coverage_entries": target_entries,
                "scrutiny_level": scrutiny_level,
                "ledger_entries": relevant_ledger,
                "has_coverage": len(target_entries) > 0,
                "covered_altitudes": [e.get('altitude') for e in target_entries if e.get('covered')]
            }
        except Exception as e:
            logger.warning(f"Failed to get Raptor insight for {target_ip}: {e}")
            return None

    def get_connections(self) -> List[Dict]:
        conns = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    proc_name = proc.name() if proc else "Unknown"
                    proc_path = ""
                    if proc:
                        try:
                            proc_path = proc.exe()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    risk, reason = calculate_risk(conn, proc, detect_reverse=self.detect_reverse_tools)
                    laddr = getattr(conn, 'laddr', None)
                    raddr = getattr(conn, 'raddr', None)
                    local_ip = getattr(laddr, 'ip', '') if laddr else ''
                    local_port = getattr(laddr, 'port', 0) if laddr else 0
                    remote_ip = getattr(raddr, 'ip', '') if raddr else ''
                    remote_port = getattr(raddr, 'port', 0) if raddr else 0
                    status = getattr(conn, 'status', '')
                    proto = "TCP" if conn.type == psutil.AF_INET else "UDP"
                    geo = get_geoip(remote_ip)
                    entry = {
                        "proto": proto,
                        "local": f"{local_ip}:{local_port}" if local_ip else "",
                        "remote": f"{remote_ip}:{remote_port}" if remote_ip else "",
                        "status": status,
                        "pid": conn.pid or "",
                        "process": proc_name,
                        "path": proc_path[:60],
                        "risk": risk,
                        "reason": reason,
                        "geo": geo,
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "direction": "inbound" if status == "LISTEN" else "outbound",
                        "port": local_port,
                        "remote_ip": remote_ip,
                        "process_path": proc_path
                    }
                    # OGhidra malware check on suspicious binaries (with caching)
                    if self.oghidra_enabled and proc_path and Path(proc_path).exists():
                        if risk in ("HIGH", "MED") and "suspicious" in reason.lower():
                            with self._malware_cache_lock:
                                if proc_path in self._malware_cache:
                                    malware_findings = self._malware_cache[proc_path]
                                else:
                                    malware_findings = self._check_oghidra_malware(proc_path)
                                    self._malware_cache[proc_path] = malware_findings
                            if malware_findings:
                                entry["malware_findings"] = malware_findings
                                entry["risk"] = "HIGH"
                                entry["reason"] += f" (OGhidra: {len(malware_findings)} patterns)"

                    # ----------------------------------------------------------------
                    # Raptor Insights enrichment
                    # ----------------------------------------------------------------
                    if remote_ip:
                        raptor_insight = self._get_raptor_insight_for_target(remote_ip)
                        if raptor_insight:
                            entry["raptor_insight"] = raptor_insight
                            entry["raptor_scrutiny"] = raptor_insight.get("scrutiny_level", 0)
                            # If there is high scrutiny, escalate risk
                            if raptor_insight.get("scrutiny_level", 0) > 3:
                                entry["risk"] = "HIGH"
                                entry["reason"] += " (Raptor scrutiny escalation)"
                            # Add coverage info to reason
                            if raptor_insight.get("has_coverage"):
                                covered_alts = raptor_insight.get("covered_altitudes", [])
                                if covered_alts:
                                    entry["reason"] += f" (Raptor covered: {', '.join(covered_alts)})"
                                else:
                                    entry["reason"] += " (Raptor scanned but uncovered)"
                    # ----------------------------------------------------------------

                    conns.append(entry)
                except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                    continue
        except Exception as e:
            logger.warning(f"Error iterating connections: {e}")
        return conns

    def _check_oghidra_malware(self, binary_path: str) -> List[Dict]:
        if not self.oghidra_enabled or self._run_oghidra_analyze is None:
            return []
        try:
            result = self._run_oghidra_analyze(binary_path, task_mode="malware")
            # Guard against None or non-dict returns
            if result and isinstance(result, dict) and result.get("rc") == 0:
                parsed = result.get("parsed", {})
                return parsed.get("findings", [])
        except Exception as e:
            logger.warning(f"OGhidra malware check failed for {binary_path}: {e}")
        return []

    def _monitor_loop(self) -> None:
        while self.running:
            conns = self.get_connections()
            with self._lock:
                self.metrics["total_connections_seen"] += len(conns)
                self.metrics["high_risk_count"] = sum(1 for c in conns if c["risk"] in ("HIGH", "MED"))

            if not self.standby_mode:
                now = time.time()
                for c in conns:
                    if c["risk"] in ("HIGH", "MED"):
                        action = self.policy_engine.evaluate(c)
                        if action["action"] == "alert":
                            key = (c["remote_ip"], c["process"])
                            last = self._alert_cooldown.get(key, 0)
                            if now - last >= self._cooldown_seconds:
                                self._alert_cooldown[key] = now
                                with self._lock:
                                    self.metrics["alert_count"] += 1
                                    self.metrics["last_alert_time"] = datetime.now()
                                alert_msg = f"[DEFENSE ALERT] {action['rule_name']} – {c['remote_ip']} ({c['reason']})"
                                if "malware_findings" in c:
                                    alert_msg += f" | OGhidra: {len(c['malware_findings'])} patterns"
                                if "raptor_insight" in c:
                                    ri = c["raptor_insight"]
                                    if ri.get("has_coverage"):
                                        alert_msg += f" | Raptor coverage: {', '.join(ri.get('covered_altitudes', []))}"
                                    if ri.get("scrutiny_level", 0) > 0:
                                        alert_msg += f" | Raptor scrutiny: {ri['scrutiny_level']}"
                                self._print_alert(alert_msg, "red")
                                self.log_to_git("alert", {
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "remote_ip": c["remote_ip"],
                                    "process": c["process"],
                                    "risk": c["risk"],
                                    "reason": c["reason"],
                                    "action": action["rule_name"],
                                    "malware_findings": c.get("malware_findings", []),
                                    "raptor_insight": c.get("raptor_insight")
                                })
                                if self.soul:
                                    self.soul.ingest_loot({"type": "defense", "target": c["remote_ip"], "findings": c})
                                if self.db and hasattr(self.db, 'add_defense_alert'):
                                    self.db.add_defense_alert(
                                        risk=c["risk"],
                                        source_ip=c["local"].split(":")[0] if c["local"] else "",
                                        dest_ip=c["remote_ip"],
                                        process=c["process"],
                                        action_taken="alerted",
                                        llm_analysis=json.dumps(c.get("malware_findings", []))
                                    )
                                # Raptor ledger integration
                                if self.ledger_integration and self.db and hasattr(self.db, 'add_ledger_entry'):
                                    try:
                                        alert_id = f"defense_alert_{int(time.time())}"
                                        self.db.add_ledger_entry(
                                            campaign_id=self.campaign_id_for_ledger,
                                            finding_id=alert_id,
                                            disposition="alert",
                                            evidence_receipt=json.dumps({
                                                "remote_ip": c["remote_ip"],
                                                "process": c["process"],
                                                "risk": c["risk"],
                                                "reason": c["reason"],
                                                "timestamp": datetime.utcnow().isoformat(),
                                                "raptor_insight": c.get("raptor_insight")
                                            })
                                        )
                                    except Exception as e:
                                        logger.warning(f"Failed to add ledger entry: {e}")
            time.sleep(2)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.lava_manager.start_metrics_collector()
        self._print_alert("[DEFENSE] Monitoring started. Use /defense standby off to enable alerts.", "green")

    def stop(self) -> None:
        self.running = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=3.0)
        self.lava_manager.stop_metrics_collector()
        stop_geoip_updater()
        # If this monitor is the global one, clear it
        with _MONITOR_LOCK:
            if _WARROOM_MONITOR is self:
                _set_defense_monitor(None)
        self._print_alert("[DEFENSE] Monitoring stopped.", "yellow")

    def set_standby(self, enabled: bool) -> None:
        self.standby_mode = enabled
        state = "ON (alerts paused)" if enabled else "OFF (alerts active)"
        self._print_alert(f"[DEFENSE] Standby mode {state}", "cyan")

    def set_low_profile(self, enabled: bool) -> None:
        self.low_profile = enabled
        self._print_alert(f"[DEFENSE] Low-profile mode {'ON' if enabled else 'OFF'}", "dim")

    def get_metrics(self) -> Dict:
        with self._lock:
            return self.metrics.copy()

    def self_test(self) -> Dict:
        return {
            "ollama": self.gateway.check_ollama() if self.gateway else False,
            "docker": False,
            "geoip_thread": _GEO_UPDATE_THREAD and _GEO_UPDATE_THREAD.is_alive(),
            "connections_count": len(self.get_connections()),
            "policy_valid": bool(self.policy_engine.policy),
            "database_ok": self.db is not None,
            "soul_ok": self.soul is not None,
            "embedder_loaded": self.embedder is not None,
            "git_repo_ok": self.git_repo is not None,
            "git_enabled": self.git_enabled,
            "standby_mode": self.standby_mode,
            "low_profile": self.low_profile,
            "detect_reverse_tools": self.detect_reverse_tools,
            "lavawall_vpn_active": self.lava_manager.vpn_active,
            "oghidra_enabled": self.oghidra_enabled,
            "ledger_integration": self.ledger_integration,
            "raptor_campaign_id": self._raptor_campaign_id,
        }

    # ------------------------------------------------------------------
    # Raptor CLI helper
    # ------------------------------------------------------------------
    def get_raptor_status(self, target_ip: Optional[str] = None) -> str:
        """Return a human-readable summary of Raptor insights for the current campaign."""
        if not self.db or not self._raptor_campaign_id:
            return "No Raptor campaign active or database unavailable."
        if target_ip:
            insight = self._get_raptor_insight_for_target(target_ip)
            if not insight:
                return f"No Raptor data found for {target_ip}."
            lines = [
                f"Raptor insights for {target_ip}:",
                f"  Scrutiny level: {insight.get('scrutiny_level', 0)}",
                f"  Coverage entries: {len(insight.get('coverage_entries', []))}",
                f"  Covered altitudes: {', '.join(insight.get('covered_altitudes', [])) or 'None'}",
                f"  Relevant ledger entries: {len(insight.get('ledger_entries', []))}"
            ]
            return "\n".join(lines)
        else:
            # Summary for campaign
            coverage = self.db.get_coverage(self._raptor_campaign_id)
            ledger = self.db.get_ledger(self._raptor_campaign_id, limit=50)
            scrutiny = self.db.get_scrutiny(self._raptor_campaign_id)
            return (
                f"Raptor campaign: {self._raptor_campaign_id}\n"
                f"  Total coverage entries: {len(coverage)}\n"
                f"  Total ledger entries: {len(ledger)}\n"
                f"  Total scrutiny entities: {len(scrutiny)}"
            )

# ------------------------------------------------------------------
# CLI handler for defense commands (extended with LavaWall + Raptor)
# ------------------------------------------------------------------
def run_defense_cli(args: List[str], defense_monitor: Optional[NetWatchMonitor]) -> str:
    if not args:
        if defense_monitor and defense_monitor.running:
            standby = "ON" if defense_monitor.standby_mode else "OFF"
            return f"Defense mode is ACTIVE (standby={standby})"
        return "Defense mode is not active."

    cmd = args[0].lower()

    if cmd == "start":
        if defense_monitor:
            defense_monitor.start()
            return "Defense mode started."
        return "Defense monitor not initialized."

    elif cmd == "stop":
        if defense_monitor:
            defense_monitor.stop()
            return "Defense mode stopped."
        return "Defense monitor not initialized."

    elif cmd == "status":
        if defense_monitor is None:
            return "Defense monitor not initialized."
        if not defense_monitor.running:
            return "Defense mode not active."
        standby = "ON" if defense_monitor.standby_mode else "OFF"
        metrics = defense_monitor.get_metrics()
        uptime = datetime.now() - metrics["start_time"]
        vpn_state = "ACTIVE" if defense_monitor.lava_manager.vpn_active else "INACTIVE"
        last_scan = defense_monitor.lava_manager._last_scan_time or "Never"
        sys_metrics = defense_monitor.lava_manager.get_system_metrics()
        return (f"Defense mode ACTIVE (standby={standby})\n"
                f"  Uptime: {str(uptime).split('.')[0]}\n"
                f"  Total connections seen: {metrics['total_connections_seen']}\n"
                f"  High-risk connections: {metrics['high_risk_count']}\n"
                f"  Alerts triggered: {metrics['alert_count']}\n"
                f"  VPN: {vpn_state}\n"
                f"  Last Wi‑Fi scan: {last_scan}\n"
                f"  System: CPU {sys_metrics.get('cpu_percent',0)}%  "
                f"Memory {sys_metrics.get('memory_percent',0)}%  "
                f"Disk {sys_metrics.get('disk_usage',0)}%")

    elif cmd == "standby":
        if defense_monitor is None:
            return "Defense monitor not initialized."
        if len(args) > 1:
            val = args[1].lower()
            if val in ("on", "true", "1"):
                defense_monitor.set_standby(True)
                return "Standby mode ENABLED (alerts paused)."
            elif val in ("off", "false", "0"):
                defense_monitor.set_standby(False)
                return "Standby mode DISABLED (full alerting)."
        return "Usage: /defense standby on|off"

    elif cmd == "self-test":
        if defense_monitor:
            return json.dumps(defense_monitor.self_test(), indent=2)
        return "Defense monitor not available."

    elif cmd == "tui":
        return "TUI mode removed. Use /defense status for info."

    # LavaWall additions
    elif cmd == "wifi":
        if not defense_monitor:
            return "Defense monitor not initialized."
        if len(args) < 2:
            return "Usage: /defense wifi scan [interface]"
        sub_cmd = args[1].lower()
        if sub_cmd == "scan":
            iface = args[2] if len(args) > 2 else "wlan0"
            result = defense_monitor.wifi_scanner.scan(interface=iface)
            return json.dumps(result, indent=2)
        return f"Unknown wifi subcommand: {sub_cmd}"

    elif cmd == "vpn":
        if not defense_monitor:
            return "Defense monitor not initialized."
        if len(args) < 2:
            return "Usage: /defense vpn on|off"
        action = args[1].lower()
        return defense_monitor.lava_manager.toggle_vpn(action)

    elif cmd == "metrics":
        if not defense_monitor:
            return "Defense monitor not initialized."
        metrics = defense_monitor.lava_manager.get_system_metrics()
        return json.dumps(metrics, indent=2)

    elif cmd == "firewall":
        if not defense_monitor:
            return "Defense monitor not initialized."
        return defense_monitor.lava_manager.get_firewall_status()

    elif cmd == "config":
        return "Config management not yet implemented. Use /defense config set <key> <value> in future."

    # NEW: Raptor command
    elif cmd == "raptor":
        if not defense_monitor:
            return "Defense monitor not initialized."
        if len(args) > 1:
            ip = args[1]
            return defense_monitor.get_raptor_status(target_ip=ip)
        else:
            return defense_monitor.get_raptor_status()

    else:
        return f"Unknown defense command: {cmd}"

# ------------------------------------------------------------------
# War Room API (FastAPI) – only if FastAPI is available
# ------------------------------------------------------------------
if FASTAPI_AVAILABLE:
    # ------------------------------------------------------------------
    # CORS configuration: allow specific origins from environment or default to all
    # ------------------------------------------------------------------
    cors_origins_env = os.environ.get("PHALANX_CORS_ORIGINS", "")
    if cors_origins_env:
        # Expect comma-separated list, e.g., "http://localhost:3000,https://example.com"
        cors_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
    else:
        # Default to allow all origins (development mode)
        cors_origins = ["*"]

    app = FastAPI(title="PHALANX War Room API", version="3.6")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Health endpoint with DB connection retry
    # ------------------------------------------------------------------
    @app.get("/api/health")
    async def health_check():
        """Health check endpoint with database connectivity verification (retry 3 times)."""
        monitor = get_defense_monitor()
        db_status = "unknown"
        db_error = None

        if monitor and monitor.db:
            # Try to execute a simple query with retry
            for attempt in range(3):
                try:
                    monitor.db.conn.execute("SELECT 1").fetchone()
                    db_status = "connected"
                    break
                except Exception as e:
                    db_status = "error"
                    db_error = str(e)
                    if attempt < 2:
                        time.sleep(0.5)
        else:
            db_status = "not_available"
            db_error = "Defense monitor or database not initialized"

        return {
            "status": "healthy" if db_status == "connected" else "degraded",
            "database": db_status,
            "database_error": db_error,
            "timestamp": datetime.utcnow().isoformat()
        }

    # ------------------------------------------------------------------
    # Existing API endpoints
    # ------------------------------------------------------------------
    @app.get("/api/defense/status")
    async def get_defense_status():
        monitor = get_defense_monitor()
        if not monitor:
            raise HTTPException(404, "Defense monitor not active")
        return {
            "status": "active" if monitor.running else "inactive",
            "standby": monitor.standby_mode,
            "vpn": {
                "active": monitor.lava_manager.vpn_active,
                "config": monitor.lava_manager.vpn_config_path
            },
            "wifi": {
                "last_scan": monitor.lava_manager._last_scan_time,
                "interface": monitor.lava_manager.wifi_interface
            },
            "metrics": monitor.lava_manager.get_system_metrics(),
            "alerts_count": monitor.metrics.get("alert_count", 0),
            "connections_seen": monitor.metrics.get("total_connections_seen", 0),
            "raptor_campaign_id": monitor._raptor_campaign_id
        }

    @app.get("/api/defense/logs")
    async def get_defense_logs(limit: int = 50, risk: str = None):
        monitor = get_defense_monitor()
        if not monitor or not monitor.db:
            raise HTTPException(404, "Defense monitor or database not active")
        conn = monitor.db.conn
        query = "SELECT * FROM defense_alerts ORDER BY timestamp DESC LIMIT ?"
        params = [limit]
        if risk:
            query = "SELECT * FROM defense_alerts WHERE risk = ? ORDER BY timestamp DESC LIMIT ?"
            params = [risk, limit]
        cur = conn.execute(query, params)
        return {"logs": [dict(row) for row in cur.fetchall()]}

    @app.get("/api/defense/export")
    async def export_defense_logs(format: str = "json"):
        monitor = get_defense_monitor()
        if not monitor or not monitor.db:
            raise HTTPException(404, "Defense monitor or database not active")
        cur = monitor.db.conn.execute("SELECT * FROM defense_alerts ORDER BY timestamp DESC")
        logs = [dict(row) for row in cur.fetchall()]
        if format == "csv":
            import csv
            from io import StringIO
            output = StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                writer.writerows(logs)
            return JSONResponse(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=defense_logs.csv"})
        return JSONResponse(logs)

    @app.get("/api/missions")
    async def get_missions():
        monitor = get_defense_monitor()
        if not monitor or not monitor.db:
            raise HTTPException(404, "Defense monitor or database not active")
        campaigns = monitor.db.list_swarm_campaigns(20)
        return {"missions": campaigns}

    @app.get("/api/findings")
    async def get_findings(limit: int = 50):
        monitor = get_defense_monitor()
        if not monitor or not monitor.db:
            raise HTTPException(404, "Defense monitor or database not active")
        findings = monitor.db.get_findings(limit)
        return {"findings": findings}

    @app.get("/api/graph")
    async def get_graph(campaign_id: str = None):
        monitor = get_defense_monitor()
        if not monitor or not hasattr(monitor.soul, "graph"):
            return {"nodes": [], "edges": []}
        graph = monitor.soul.graph
        return {
            "nodes": [{"id": k, **v} for k, v in graph.nodes.items()],
            "edges": [{"from": e[0], "to": e[1], "relation": e[2]} for e in graph.edges]
        }

    @app.post("/api/defense/standby")
    async def set_standby(enabled: bool):
        monitor = get_defense_monitor()
        if monitor:
            monitor.set_standby(enabled)
            return {"standby": enabled}
        raise HTTPException(404, "Defense monitor not active")

    @app.post("/api/defense/vpn")
    async def toggle_vpn(action: str):
        monitor = get_defense_monitor()
        if monitor:
            result = monitor.lava_manager.toggle_vpn(action)
            return {"message": result}
        raise HTTPException(404, "Defense monitor not active")

    @app.post("/api/defense/wifi/scan")
    async def trigger_wifi_scan(interface: str = None, duration: int = 30):
        monitor = get_defense_monitor()
        if monitor:
            iface = interface or monitor.lava_manager.wifi_interface
            result = monitor.wifi_scanner.scan(interface=iface, duration=duration)
            return result
        raise HTTPException(404, "Defense monitor not active")

    # NEW: Raptor insights endpoint
    @app.get("/api/defense/raptor")
    async def get_raptor_insights(ip: str = None):
        monitor = get_defense_monitor()
        if not monitor:
            raise HTTPException(404, "Defense monitor not active")
        if ip:
            insight = monitor._get_raptor_insight_for_target(ip)
            if not insight:
                raise HTTPException(404, f"No Raptor data found for {ip}")
            return insight
        else:
            # Return summary of campaign
            if not monitor._raptor_campaign_id:
                return {"error": "No Raptor campaign active"}
            coverage = monitor.db.get_coverage(monitor._raptor_campaign_id)
            ledger = monitor.db.get_ledger(monitor._raptor_campaign_id, limit=50)
            scrutiny = monitor.db.get_scrutiny(monitor._raptor_campaign_id)
            return {
                "campaign_id": monitor._raptor_campaign_id,
                "coverage_count": len(coverage),
                "ledger_count": len(ledger),
                "scrutiny_count": len(scrutiny)
            }
else:
    app = None

# ------------------------------------------------------------------
# War Room server starter
# ------------------------------------------------------------------
def start_warroom_server(host: str = "0.0.0.0", port: int = 3333) -> Optional[threading.Thread]:
    """
    Start War Room HTTP server in a background thread.
    If FastAPI or uvicorn are not installed, print a clear error message
    with installation instructions and return None.
    """
    if not FASTAPI_AVAILABLE or not UVICORN_AVAILABLE:
        msg = (
            "War Room server cannot start because FastAPI and/or uvicorn are not installed.\n"
            "Install them with: pip install fastapi uvicorn[standard] python-multipart aiofiles\n"
            "Then restart PHALANX or run /warroom start again."
        )
        logger.error(msg)
        if console:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[ERROR] {msg}")
        return None

    if app is None:
        msg = "War Room app not created. Check FastAPI installation."
        logger.error(msg)
        if console:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[ERROR] {msg}")
        return None

    def _run_server():
        try:
            uvicorn.run(app, host=host, port=port, log_level="warning")
        except Exception as e:
            logger.error(f"War Room server failed: {e}")
            if console:
                console.print(f"[red]War Room server failed: {e}[/red]")
            else:
                print(f"[ERROR] War Room server failed: {e}")

    thread = threading.Thread(target=_run_server, daemon=True)
    thread.start()
    logger.info(f"War Room server started at http://{host}:{port}")
    if console:
        console.print(f"[green]War Room server started at http://{host}:{port}[/green]")
    return thread

# ------------------------------------------------------------------
# Dummy classes for compatibility
# ------------------------------------------------------------------
class DefenseTUI:
    def __init__(self, *args, **kwargs):
        pass
    def run(self):
        print("TUI mode deprecated. Use /defense status in REPL.")

# ------------------------------------------------------------------
# Public exports
# ------------------------------------------------------------------
__all__ = [
    "NetWatchMonitor",
    "LavaWallManager",
    "WiFiScanner",
    "run_defense_cli",
    "get_defense_monitor",
    "start_warroom_server",
    "app",  # will be None if FastAPI not available
]

if __name__ == "__main__":
    print("PHALANX Defense Module v3.6 Cross-Platform – LavaWall enhanced with War Room API and Raptor ledger integration.")