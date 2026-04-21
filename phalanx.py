#!/usr/bin/env python3
"""
PHALANX v3.3 – Main Entry: REPL, CLI, and Embedded TUI.
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
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime

# Rich for pretty output
from rich.console import Console
from rich.table import Table
from rich.box import ROUNDED
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# Prompt toolkit for TUI (embedded)
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.styles import Style
    from prompt_toolkit.key_binding import KeyBindings
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

# Local imports (v3.3 core)
from phalanx_core import (
    PhalanxDB, Soul, SkillManager, AutonomousPentest,
    CONFIG_FILE, Finding, RoEEnforcer
)
from phalanx_library import generate_engagement_plan, run_demo, get_logger, bootstrap_all
from phalanx_engine import ToolExecutor
from phalanx_tools import Gateway, list_tools, get_skill_metadata, TOOL_REGISTRY, run_tool

console = Console()
logger = get_logger("phalanx.cli")

# ------------------------------------------------------------------
# ASCII Logo
# ------------------------------------------------------------------
LOGO = r"""
██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
           Autonomous Pentesting Framework  v3.3
    ⚠  Only use on systems you own or have written permission.
"""

def print_logo():
    console.print(Panel(Text(LOGO, style="bold bright_blue"), border_style="bright_blue", expand=False))

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
        severity_color = "red" if f["severity"] in ("critical","high") else "yellow" if f["severity"] == "medium" else "green"
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
# Agentic mode with safe dynamic imports
# ------------------------------------------------------------------
def _load_agent_components(config: dict):
    """Dynamically import agent components using importlib, with graceful failure."""
    try:
        import importlib
        agents_path = Path.cwd() / "phalanx" / "agents"
        if agents_path.exists() and str(agents_path) not in sys.path:
            sys.path.insert(0, str(agents_path))
        orchestrator_module = importlib.import_module("orchestrator")
        llm_gateway_module = importlib.import_module("llm_gateway")
        OrchestratorAgent = getattr(orchestrator_module, "OrchestratorAgent")
        OllamaGateway = getattr(llm_gateway_module, "OllamaGateway")
        return OrchestratorAgent, OllamaGateway
    except (ImportError, AttributeError, ModuleNotFoundError) as e:
        logger.warning(f"Failed to load agent components: {e}")
        return None, None

def run_agentic(target: str, config: dict, soul: Soul, skill_mgr: SkillManager,
                db: PhalanxDB, executor: ToolExecutor, gateway: Gateway,
                guardrail: bool = True, enable_shadow_graph: bool = False):
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
            ap.roe_enforcer.confirm_callback = lambda prompt, details: console.input(f"\n⚠️  {prompt}\nConfirm? (y/N): ").strip().lower() == "y"
        if enable_shadow_graph:
            campaign_id = f"agentic_{target}_{int(time.time())}"
            db.create_swarm_campaign(campaign_id, target, mode="agentic")
            soul.campaign_id = campaign_id
            soul._load_graph_from_db()
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

def _prompt_model_selection(default: str = "qwen2.5:0.5b") -> str:
    """Prompt user to select an Ollama model using console.input (safe in TUI)."""
    models = _get_ollama_models()
    if not models:
        console.print(f"[yellow]No Ollama models found. Using default: {default}[/yellow]")
        return default
    console.print("[bold cyan]Available Ollama models:[/bold cyan]")
    for idx, m in enumerate(models, 1):
        console.print(f"  {idx}. {m}")
    console.print(f"  [dim]Press Enter to use default: {default}[/dim]")
    choice = console.input("Select model number (or Enter): ").strip()
    if not choice:
        return default
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(models):
            return models[idx]
    except ValueError:
        pass
    return default

def _parse_swarm_args(arg_str: str) -> Dict[str, Any]:
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
    if subcmd == "scan":
        if not rest:
            return {"error": "Usage: swarm scan <target> [--scope SCOPE] [--mode MODE] [--follow] [--graph]"}
        target = rest[0]
        target = target.replace("http://", "").replace("https://", "").split("/")[0]
        scope = None
        mode = "manual"
        follow = False
        enable_graph = False
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
            else:
                i += 1
        return {"subcmd": "scan", "target": target, "scope": scope, "mode": mode, "follow": follow, "enable_graph": enable_graph}
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

def _run_swarm_scan(repl, target: str, scope: Optional[str], mode: str, follow: bool, model: str, enable_graph: bool):
    if not is_valid_network_target(target):
        console.print(f"[red]Invalid target: '{target}' is not a valid hostname or IP address.[/red]")
        return

    console.print(f"[bold cyan]Starting swarm scan against {target}[/bold cyan]")
    console.print(f"  Model: {model}, Mode: {mode}, Follow: {follow}, Shadow Graph: {enable_graph}")
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
                enable_shadow_graph=enable_graph
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
                enable_shadow_graph=enable_graph
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
PHALANX v3.3 – Autonomous Pentesting Framework
Type 'help' for commands, 'exit' to quit.
"""
    prompt = "phalanx> "

    def __init__(self, soul: Soul, skill_mgr: SkillManager, gateway: Gateway,
                 executor: ToolExecutor, db: PhalanxDB, config: dict, looped_harness=None):
        super().__init__()
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.gateway = gateway
        self.executor = executor
        self.db = db
        self.config = config
        self.current_session_id = None
        self.looped_harness = looped_harness

    def default(self, line):
        if line.startswith('/'):
            return self.onecmd(line[1:])
        else:
            print(f"*** Unknown syntax: {line}")
            return False

    def emptyline(self):
        pass

    # ------------------------------------------------------------------
    # Command implementations
    # ------------------------------------------------------------------
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
        """Query the Shadow Graph. Usage: /graph query "what credentials do we have?" or /graph summary"""
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

    def do_loop(self, arg: str):
        """Toggle Mythos-style looped recurrent refinement harness. Usage: /loop [start|stop] [target]"""
        if self.looped_harness is None:
            console.print("[red]Looped harness not available. Check config or PyTorch installation.[/red]")
            return
        args = shlex.split(arg)
        subcmd = args[0].lower() if args else "start"
        target = args[1] if len(args) > 1 else "current"
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
            self.looped_harness.start(target)
        elif subcmd in ("stop", "off"):
            self.looped_harness.stop()
        else:
            console.print("Usage: /loop start|stop [target]")

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
        parsed = _parse_swarm_args(arg)
        if "error" in parsed:
            console.print(f"[red]{parsed['error']}[/red]")
            return
        subcmd = parsed.get("subcmd")
        if subcmd == "scan":
            model = _prompt_model_selection(default="qwen2.5:0.5b")
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
                enable_graph=parsed.get("enable_graph", False)
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

    def do_agentic(self, arg):
        """Run agentic mode with optional guardrail and shadow graph. Usage: agentic <target> [--guardrail] [--graph]"""
        args = shlex.split(arg)
        if not args:
            console.print("Usage: agentic <target> [--guardrail] [--graph]")
            return
        target = args[0]
        guardrail = "--guardrail" in args
        enable_graph = "--graph" in args or "--shadow" in args
        run_agentic(target, self.config, self.soul, self.skill_mgr,
                    self.db, self.executor, self.gateway, guardrail, enable_shadow_graph=enable_graph)

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
        console.print("Assistant: ", end="", flush=True)
        for chunk in self.gateway.stream_generate(arg):
            piece = chunk.get("response", "")
            if piece:
                console.print(piece, end="", flush=True)
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
        result = run_tool("scrape", target=target)
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
        result = run_tool("copyright_osint", target=target)
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
        result = run_tool("burp_scan", target=target)
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
        result = run_tool("ghidra_analyze", binary_path=arg)
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

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
        else:
            t = Table(title="PHALANX v3.3 Commands", box=ROUNDED, show_header=True, header_style="bold cyan")
            t.add_column("Command", style="bright_green", no_wrap=True)
            t.add_column("Description", style="white")
            t.add_column("Example", style="dim")
            rows = [
                ("/swarm scan", "Launch autonomous swarm pentest (add --graph for shadow graph)", "/swarm scan example.com --follow --graph"),
                ("/swarm campaign watch", "Live view of running campaign", "/swarm campaign watch <id>"),
                ("/swarm doctor", "Check Ollama + tool prerequisites", ""),
                ("/swarm models list", "Show local Ollama models", ""),
                ("/agentic", "Multi‑agent autonomous mode (--graph for shadow graph)", "/agentic 192.168.1.1 --graph"),
                ("/scan", "Autonomous objective‑driven pentest", "/scan 192.168.1.1"),
                ("/plan", "Generate structured OPPLAN", "/plan example.com"),
                ("/scrape", "Web scrape: emails, links, forms", "/scrape https://example.com"),
                ("/loot", "List structured loot (creds, vulns, artifacts)", "/loot cred"),
                ("/graph", "Query Shadow Graph or show summary", "/graph query 'credentials'"),
                ("/spawn", "Manually spawn a hierarchical sub-swarm", "/spawn recon 10.0.0.1"),
                ("/loop", "Start/stop Mythos Looped Transformer background refinement", "/loop start"),
                ("/finding", "List recent unified findings", "/finding 30"),
                ("/reflect", "LLM reflection on current session", ""),
                ("/resume", "Resume session or campaign", "/resume <id>"),
                ("/sourcehunt", "Scan directory for secrets/binaries", "/sourcehunt /path/to/code"),
                ("/xss", "Show XSS-to-escalation patterns from real bounties", "/xss"),
                ("/tools", "List all registered pentest tools", ""),
                ("/history", "Show last n session records", "/history 5"),
                ("/model", "Switch Ollama model or profile", "/model eco"),
                ("/personality", "Set LLM tone", "/personality pentest"),
                ("/skills", "Show skill success/fail stats", ""),
                ("/soul", "Search soul (FTS5) memory", "/soul nmap"),
                ("/mitre", "Lookup MITRE ATT&CK technique", "/mitre T1190"),
                ("/demo", "Guided kill chain against Metasploitable 2", ""),
                ("/copyright", "Copyright OSINT scan", "/copyright example.com"),
                ("/burp", "Burp Suite web vulnerability scan", "/burp example.com"),
                ("/ghidra", "Ghidra headless binary analysis", "/ghidra /bin/ls"),
                ("/sandbox", "Toggle Docker sandbox mode", ""),
                ("/clear", "Clear screen", ""),
                ("/report", "Generate JSON report for current session", "/report"),
                ("/objectives", "List session objectives and status", "/objectives"),
                ("/chat", "Direct chat with LLM assistant", "/chat What is SQL injection?"),
                ("/help", "Show this table", ""),
                ("/quit or /exit", "Exit PHALANX", ""),
            ]
            for cmd, desc, ex in rows:
                t.add_row(cmd, desc, ex)
            console.print(t)

    def do_exit(self, arg):
        console.print("Goodbye.")
        self.db.close()
        return True

    def do_EOF(self, arg):
        return self.do_exit(arg)

# ------------------------------------------------------------------
# Embedded TUI with fallback
# ------------------------------------------------------------------
def run_tui(soul: Soul, skill_mgr: SkillManager, gateway: Gateway,
           executor: ToolExecutor, db: PhalanxDB, config: dict, looped_harness=None):
    print_logo()

    if not PROMPT_TOOLKIT_AVAILABLE:
        console.print("[yellow]prompt_toolkit not installed – falling back to basic cmd loop.[/yellow]")
        repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness)
        repl.cmdloop()
        return

    bindings = KeyBindings()
    @bindings.add('c-c')
    def _(event):
        event.app.exit()
    @bindings.add('c-d')
    def _(event):
        event.app.exit()

    style = Style.from_dict({'prompt': 'bold #00ff00'})
    history_file = Path.cwd() / "phalanx" / "tui_history.txt"
    history_file.parent.mkdir(parents=True, exist_ok=True)

    session = PromptSession(
        history=FileHistory(str(history_file)),
        auto_suggest=AutoSuggestFromHistory(),
        style=style,
        key_bindings=bindings,
        message="phalanx> "
    )

    repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness)
    console.print("[bold green]Type /help for commands, /quit to exit.[/bold green]")
    if not gateway.check_ollama():
        console.print(f"[bold yellow]⚠ Ollama not reachable at {gateway.ollama_url}[/bold yellow]")

    while True:
        try:
            line = session.prompt()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break
        except Exception as e:
            console.print(f"[red]Prompt error: {e}. Falling back to input().[/red]")
            try:
                line = input("phalanx> ")
            except (KeyboardInterrupt, EOFError):
                break
        try:
            if line.startswith('/'):
                line = line[1:]
            should_exit = repl.onecmd(line)
            if should_exit:
                break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

# ------------------------------------------------------------------
# Main entrypoint
# ------------------------------------------------------------------
def ensure_bootstrapped():
    """Run phalanx_extra.py only once, with proper error handling."""
    config_path = Path.cwd() / "phalanx" / "config" / "config.json"
    if not config_path.exists():
        console.print("[*] First run – running extra bootstrapper to set up agentic components...")
        try:
            result = subprocess.run(
                [sys.executable, "phalanx_extra.py", "--no-pull-models"],
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
            console.print("[!] Bootstrapping timed out. Continuing anyway.")
        except Exception as e:
            console.print(f"[!] Bootstrapping error: {e}")

def main():
    console.print("[*] PHALANX v3.3 – Checking system...")
    ensure_bootstrapped()

    parser = argparse.ArgumentParser(description="PHALANX v3.3 – Autonomous Pentesting Framework")
    parser.add_argument("--tui", action="store_true", help="Launch TUI mode (embedded prompt-toolkit)")
    parser.add_argument("--agentic", action="store_true", help="Run in multi‑agent autonomous mode")
    parser.add_argument("--target", help="Target for agentic mode (required if --agentic)")
    parser.add_argument("--guardrail", action="store_true", default=True, help="Enable human confirmation for exploit actions (default: True)")
    parser.add_argument("--no-guardrail", dest="guardrail", action="store_false", help="Disable human confirmation (automatic)")
    parser.add_argument("--graph", "--shadow", action="store_true", help="Enable Shadow Graph persistence for agentic/swarm modes")
    parser.add_argument("--config", default="config.json", help="Configuration file (overrides default)")
    parser.add_argument("--report-only", action="store_true", help="Generate report for existing session only")
    parser.add_argument("--session-id", help="Session ID for report-only mode")
    parser.add_argument("command", nargs="?", help="Single command (e.g., 'scan 192.168.1.1')")
    parser.add_argument("args", nargs="*", help="Arguments for the single command")
    args = parser.parse_args()

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

    # Bootstrap: returns soul, skill_mgr, db, auto_pentest, looped_harness
    soul, skill_mgr, db, _, looped_harness = bootstrap_all(config)
    gateway = Gateway(config, TOOL_REGISTRY)
    executor = ToolExecutor(timeout=30, soul=soul, config=config)

    def close_db(signum=None, frame=None):
        db.close()
        sys.exit(0)
    signal.signal(signal.SIGINT, close_db)
    signal.signal(signal.SIGTERM, close_db)

    if args.report_only:
        if not args.session_id:
            console.print("[!] --report-only requires --session-id")
            sys.exit(1)
        report = db.full_report(args.session_id)
        console.print_json(json.dumps(report, indent=2, default=str))
        db.close()
        return

    if args.agentic:
        if not args.target:
            console.print("[!] --agentic requires --target")
            sys.exit(1)
        run_agentic(args.target, config, soul, skill_mgr, db, executor, gateway,
                    guardrail=args.guardrail, enable_shadow_graph=args.graph)
        return

    if args.tui:
        run_tui(soul, skill_mgr, gateway, executor, db, config, looped_harness)
        return

    if args.command:
        repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness)
        cmd_line = f"{args.command} {' '.join(args.args)}"
        repl.onecmd(cmd_line)
        db.close()
        return

    print_logo()
    repl = PhalanxREPL(soul, skill_mgr, gateway, executor, db, config, looped_harness)
    try:
        repl.cmdloop()
    except KeyboardInterrupt:
        console.print("\nExiting.")
        db.close()

if __name__ == "__main__":
    main()
