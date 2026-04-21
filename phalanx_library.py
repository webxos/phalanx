#!/usr/bin/env python3
"""
PHALANX Library v3.3 – Bootstrap, sandbox, interactive runner, demo mode,
reporting, multi‑agent orchestration, and SWARM with ReAct + reflection.
All data stored in ./phalanx/ (local to project).

Enhancements:
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

# ------------------------------------------------------------------
# Rich for pretty console output (optional)
# ------------------------------------------------------------------
try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

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
            return {
                "summary": f"Agentic demo completed against {target}",
                "orchestrator_decision": decision,
                "timestamp": datetime.utcnow().isoformat(),
                "session_id": session_id
            }
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
    return report

def generate_engagement_plan(target: str, user_input: str, gateway) -> Dict:
    """Generate a structured engagement plan (OPPLAN) using PlannerAgent if available.
    Works correctly even when called from an already running event loop."""
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
                return future.result()
        except RuntimeError:
            # No running loop, safe to use asyncio.run()
            return asyncio.run(_plan())
    except Exception as e:
        logger.warning(f"PlannerAgent failed: {e}, falling back to static plan")
        return {
            "objectives": [
                {"description": f"Reconnaissance of {target}", "mitre_tags": ["T1595"]},
                {"description": f"Vulnerability assessment of {target}", "mitre_tags": ["T1595.002"]},
                {"description": f"Exploitation of {target}", "mitre_tags": ["T1190"]}
            ],
            "roe": {
                "allowed_targets": [target],
                "forbidden_actions": ["data_exfiltration", "destruction"],
                "require_human_confirm": ["privilege_escalation"]
            }
        }

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

def print_banner():
    banner = r"""
    ██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
    ██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
    ██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
           Autonomous Pentesting Framework  v3.3
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
# Recon Agent (async-friendly)
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
        
        if self.progress_callback:
            self.progress_callback(f"[Recon] Found {len(results['subdomains'])} subdomains, {len(results['open_ports'])} open ports, {len(results['vulnerabilities'])} vulnerabilities, {len(results['emails'])} emails")
        
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
# SubSwarmOrchestrator (for hierarchical spawning)
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

    async def run(self) -> dict:
        parent_progress = getattr(self.parent, 'progress', None)
        if parent_progress:
            parent_progress(f"[SubSwarm] Starting sub-swarm for phase '{self.phase}' on {self.target}")
        
        agents = self.parent.agents
        current_phase = self.phase
        required_agents = ["recon", "classify", "exploit"]
        for agent in required_agents:
            if agent not in agents:
                if parent_progress:
                    parent_progress(f"[SubSwarm] Missing required agent '{agent}', cannot proceed.")
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
        
        if parent_progress:
            parent_progress(f"[SubSwarm] Completed phase '{self.phase}' with {len(self.results.get('classified', []))} validated vulns")
        
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

# ------------------------------------------------------------------
# Enhanced SwarmOrchestrator with hierarchical spawning and shadow graph
# ------------------------------------------------------------------
class SwarmOrchestrator:
    def __init__(self, target: str, scope: Optional[str], mode: str, model: str,
                 db, soul, skill_mgr, gateway, progress_callback: Optional[Callable] = None,
                 enable_hierarchical: bool = False, enable_shadow_graph: bool = False):
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
        
        self.agents = {
            "recon": ReconAgent("recon", gateway, db, soul, skill_mgr, model, progress_callback),
            "classify": ClassifyAgent("classify", gateway, db, soul, skill_mgr, model, progress_callback),
            "exploit": ExploitAgent("exploit", gateway, db, soul, skill_mgr, model, progress_callback),
            "report": ReportAgent("report", gateway, db, soul, skill_mgr, model, progress_callback),
            "reflect": ReflectorAgent("reflect", gateway, db, soul, skill_mgr, model, progress_callback)
        }
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
            "objective": "Compromise target and report findings"
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
        self.progress(f"[bold]Swarm orchestrator started for {self.target}[/bold]")
        self.progress(f"Model: {self.model}, Mode: {self.mode}")
        self.progress(f"Campaign ID: {self.campaign_id}")
        self._update_campaign_file("running")
        
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
            self._log_agent_action("reflect", reflect_result)
            
            suggestion = reflect_result.get("suggestion", "continue")
            # Escalate immediately if high‑value findings detected
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
        return self.context

    async def _reason_next_agent(self):
        """Dynamic reasoning to choose next agent using LLM reflection or rule-based."""
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
# Public swarm API function (reuses existing components)
# ------------------------------------------------------------------
def run_swarm(target: str, scope: Optional[str], mode: str, model: str,
              follow: bool, progress_callback: Optional[Callable] = None,
              db=None, soul=None, skill_mgr=None, gateway=None,
              enable_hierarchical: bool = False, enable_shadow_graph: bool = False) -> Any:
    """
    Run a swarm campaign. If follow is True, run synchronously and return final report.
    If follow is False, start in background and return campaign ID.
    """
    from phalanx_core import PhalanxDB, RoE, Soul, SkillManager
    from phalanx_tools import Gateway, TOOL_REGISTRY
    
    campaign_id = str(uuid.uuid4())[:8]
    locally_created_db = False
    locally_created_gateway = False
    
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
    
    # Ensure soul has the campaign_id for graph persistence
    soul.campaign_id = campaign_id
    if hasattr(soul, "_load_graph_from_db"):
        soul._load_graph_from_db()
    
    orchestrator = SwarmOrchestrator(
        target=target, scope=scope, mode=mode, model=model,
        db=db, soul=soul, skill_mgr=skill_mgr, gateway=gateway,
        progress_callback=progress_callback,
        enable_hierarchical=enable_hierarchical,
        enable_shadow_graph=enable_shadow_graph
    )
    orchestrator.campaign_id = campaign_id
    _register_swarm(campaign_id, orchestrator)
    
    if follow:
        try:
            try:
                loop = asyncio.get_running_loop()
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(lambda: asyncio.run(orchestrator.run()))
                    result = future.result()
            except RuntimeError:
                result = asyncio.run(orchestrator.run())
        finally:
            _unregister_swarm(campaign_id)
            if locally_created_db:
                db.close()
        return result
    else:
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

if __name__ == "__main__":
    print("PHALANX Library v3.3 with Shadow Graph + Hierarchical Swarm + Looped Harness ready.")
