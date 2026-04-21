#!/usr/bin/env python3
"""
PHALANX v3.2 – Main entry point.
Full polyglot toolset + objective‑driven orchestrator + sandbox + RoE.
"""

import argparse
import json
import readline
import sys
from pathlib import Path

from phalanx_core import (
    BASE_DIR, CONFIG_FILE, HISTORY_FILE,
    load_config, bootstrap as core_bootstrap,
    Soul, SkillManager, PentestDB, AutonomousPentest,
    generate_engagement_plan
)
from phalanx_tools import Gateway, run_tool, list_tools, get_mitre_for_tool
from phalanx_engine import ToolExecutor
from phalanx_library import bootstrap_all, get_logger
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

console = Console()
logger = get_logger("phalanx.main")

LOGO = r"""
██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
           Autonomous Pentesting Framework  v3.2
    ⚠  Only use on systems you own or have written permission.
"""

def print_logo():
    console.print(Panel(Text(LOGO, style="bold bright_blue"), border_style="bright_blue", expand=False))

def display_help():
    t = Table(title="PHALANX v3.2 Commands", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Command", style="bright_green", no_wrap=True)
    t.add_column("Description", style="white")
    t.add_column("Example", style="dim")
    rows = [
        ("/scan <target>",        "Autonomous objective‑driven pentest",      "/scan 192.168.1.1"),
        ("/plan <target>",        "Generate structured OPPLAN with objectives","/plan example.com"),
        ("/engage <target>",      "Legacy multi‑agent kill chain",            "/engage example.com"),
        ("/scrape <url>",         "Web scrape: emails, links, forms",         "/scrape https://example.com"),
        ("/tools",                "List all registered pentest tools",        ""),
        ("/history [n]",          "Show last n session records",              "/history 5"),
        ("/model <name|profile>", "Switch Ollama model or profile (eco/max/test)","/model eco"),
        ("/personality <mode>",   "Set LLM tone (concise/detailed/code/pentest)","/personality pentest"),
        ("/skills",               "Show skill success/fail stats + MITRE",    ""),
        ("/soul <query>",         "Search soul (FTS5) memory",                "/soul nmap"),
        ("/rebootstrap",          "Force re‑write all tool stubs",            ""),
        ("/mitre <id>",           "Lookup MITRE ATT&CK technique",            "/mitre T1190"),
        ("/demo",                 "Guided kill chain against Metasploitable 2",""),
        ("/copyright <target>",   "Copyright OSINT scan (piracy, DMCA)",      "/copyright example.com"),
        ("/burp <target>",        "Burp Suite web vulnerability scan",        "/burp example.com"),
        ("/ghidra <binary>",      "Ghidra headless binary analysis",          "/ghidra /bin/ls"),
        ("/sandbox",              "Toggle Docker sandbox mode",               ""),
        ("/clear",                "Clear screen",                             ""),
        ("/help",                 "Show this table",                          ""),
        ("/quit or /exit",        "Exit PHALANX",                             ""),
    ]
    for cmd, desc, ex in rows: t.add_row(cmd, desc, ex)
    console.print(t)

def bootstrap_test_suite():
    tests_dir = Path(__file__).parent / "tests"
    tests_dir.mkdir(exist_ok=True)
    test_file = tests_dir / "test_polyglot.py"
    if not test_file.exists():
        test_content = '''#!/usr/bin/env python3
import json, sys, pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from phalanx_engine import ToolExecutor
from phalanx_library import bootstrap_tools
from phalanx_tools import run_tool, list_tools

@pytest.fixture(scope="session")
def executor():
    bootstrap_tools(force=True)
    ex = ToolExecutor()
    ex.reload()
    return ex

def test_python_tool(executor):
    result = executor.execute("echo", {"message": "hello"})
    assert result["status"] == "SUCCESS"
    assert "hello" in result["summary"]

def test_wasm_echo(executor):
    result = executor.execute("echo_wasm", {"message": "hello from wasm"})
    assert result["status"] == "SUCCESS"
    assert "hello from wasm" in result.get("echo", "")

def test_scrape_static():
    result = run_tool("scrape", target="https://example.com", use_js=False)
    assert result["rc"] == 0
    assert result["parsed"]["title"] == "Example Domain"

def test_list_tools():
    tools = list_tools()
    assert any(t["name"] == "scrape" for t in tools)

def test_ghidra_available():
    tools = list_tools()
    assert any(t["name"] == "ghidra_analyze" for t in tools)
'''
        test_file.write_text(test_content)
        console.print("[green]✓ Created test suite at tests/test_polyglot.py[/green]")

def repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory, config):
    hist = HISTORY_FILE
    try: readline.read_history_file(str(hist))
    except FileNotFoundError: pass
    readline.set_history_length(500)
    console.print("[bold green]Type [bright_white]/help[/bright_white] for commands or just chat.[/bold green]")
    if not gateway.check_ollama():
        console.print(f"[bold yellow]⚠ Ollama not reachable at {gateway.ollama_url}[/bold yellow]")
    while True:
        try: line = console.input("[bold bright_blue]PHALANX>[/bold bright_blue] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Bye.[/dim]")
            break
        if not line: continue
        readline.write_history_file(str(hist))
        if line.startswith("/"):
            parts = line.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""
            if cmd in ("/quit", "/exit", "/q"): break
            elif cmd == "/help": display_help()
            elif cmd == "/clear": console.clear()
            elif cmd == "/tools":
                tools = list_tools()
                t = Table(box=box.SIMPLE, show_header=True)
                t.add_column("Tool", style="bright_green")
                t.add_column("MITRE", style="dim")
                t.add_column("Tags")
                t.add_column("Description")
                for tool in tools: t.add_row(tool["name"], ", ".join(tool.get("mitre", [])), ", ".join(tool.get("tags", [])), tool["desc"])
                console.print(t)
            elif cmd == "/scan":
                if not arg: console.print("[red]Usage: /scan <target>[/red]"); continue
                console.print(f"[bold cyan]Starting autonomous objective‑driven scan of {arg}…[/bold cyan]")
                try:
                    ap = auto_pentest_factory()
                    report = ap.run(arg, scan_type="full")
                    console.print_json(json.dumps(report, indent=2, default=str))
                except Exception as e: console.print(f"[red]Scan failed: {e}[/red]")
            elif cmd == "/plan":
                if not arg: console.print("[red]Usage: /plan <target>[/red]"); continue
                console.print(f"[bold cyan]Generating structured OPPLAN for {arg}…[/bold cyan]")
                plan = generate_engagement_plan(arg, "", gateway)
                console.print_json(json.dumps(plan, indent=2))
            elif cmd == "/engage":
                if not arg: console.print("[red]Usage: /engage <target>[/red]"); continue
                console.print(f"[bold yellow]Legacy engage mode – consider using /scan for objectives.[/bold yellow]")
                try:
                    ap = auto_pentest_factory()
                    report = ap.run(arg, scan_type="killchain")
                    console.print_json(json.dumps(report, indent=2, default=str))
                except Exception as e: console.print(f"[red]Engagement failed: {e}[/red]")
            elif cmd == "/scrape":
                if not arg: console.print("[red]Usage: /scrape <url>[/red]"); continue
                console.print(f"[bold cyan]Scraping {arg}…[/bold cyan]")
                result = run_tool("scrape", target=arg)
                if result.get("error"): console.print(f"[red]Error: {result['error']}[/red]")
                else:
                    parsed = result.get("parsed", {})
                    tbl = Table(title=f"Scrape results for {arg}", box=box.ROUNDED)
                    tbl.add_column("Key", style="cyan"); tbl.add_column("Value", style="white")
                    tbl.add_row("Status Code", str(parsed.get("status_code", "?")))
                    tbl.add_row("Title", parsed.get("title", "N/A"))
                    tbl.add_row("Emails", ", ".join(parsed.get("emails", [])[:5]) or "None")
                    tbl.add_row("Links Found", str(parsed.get("links_count", 0)))
                    tbl.add_row("Forms", str(len(parsed.get("forms", []))))
                    tbl.add_row("Tech Hints", ", ".join(parsed.get("tech_hints", [])[:3]) or "None")
                    tbl.add_row("robots.txt", "Yes" if parsed.get("robots_txt") else "No")
                    tbl.add_row("JS Rendered", "Yes" if parsed.get("js_rendered") else "No")
                    console.print(tbl)
                    soul.append("SCRAPE", arg, result["output"])
            elif cmd == "/model":
                if arg in ("eco", "max", "test"): gateway.set_profile(arg); console.print(f"[green]LLM profile set to {arg}[/green]")
                else: gateway.set_model(arg.strip()); console.print(f"[green]Model set to {arg.strip()}[/green]")
                console.print("[cyan]Available models:[/cyan] " + ", ".join(gateway.list_models()))
            elif cmd == "/personality":
                gateway.set_personality(arg.strip()); console.print(f"[green]Personality set to '{arg.strip()}'[/green]")
            elif cmd == "/skills":
                skills = skill_mgr.list_skills()
                if not skills: console.print("[dim]No skills recorded yet.[/dim]")
                else:
                    t = Table(box=box.SIMPLE)
                    t.add_column("Skill"); t.add_column("✓", style="green"); t.add_column("✗", style="red"); t.add_column("MITRE"); t.add_column("Last Used", style="dim")
                    for s in skills: t.add_row(s["name"], str(s["success"]), str(s["fail"]), ", ".join(get_mitre_for_tool(s["name"])), s["last_used"])
                    console.print(t)
            elif cmd == "/soul":
                results = soul.search(arg.strip()) if arg.strip() else soul.recent(20)
                for r in results: console.print(f"[dim]{r['ts']}[/dim] [{r['type']}] {r.get('summary', r.get('content', ''))}")
            elif cmd == "/history":
                try: limit = int(arg) if arg else 10
                except ValueError: limit = 10
                sessions = db.list_sessions(limit)
                for s in sessions: console.print(f"[dim]{s['started_at']}[/dim] [bold]{s['target']}[/bold] [{'green' if s['status']=='completed' else 'yellow'}]{s['status']}[/] [dim]{s['session_id']}[/dim]")
            elif cmd == "/rebootstrap":
                console.print("[yellow]Re-bootstrapping tools…[/yellow]")
                bootstrap_all(force=True)
                executor.reload()
                console.print("[green]Done.[/green]")
            elif cmd == "/mitre":
                if not arg: console.print("[red]Usage: /mitre <technique_id>[/red]"); continue
                name = gateway.get_mitre_technique(arg)
                console.print(f"[green]MITRE technique {arg}: {name}[/green]" if name else "[yellow]No matching technique found (or offline).[/yellow]")
            elif cmd == "/demo":
                console.print("[bold cyan]Starting DEMO mode against Metasploitable 2...[/bold cyan]")
                console.print("[yellow]Ensure 'docker compose up -d' is running.[/yellow]")
                try:
                    from phalanx_demo import run_demo
                    run_demo()
                except ImportError: console.print("[red]Demo module not found. Run guided demo manually: /scan metasploitable2[/red]")
            elif cmd == "/copyright":
                if not arg: console.print("[red]Usage: /copyright <target>[/red]"); continue
                result = run_tool("copyright_osint", target=arg)
                if result.get("error"): console.print(f"[red]Error: {result['error']}[/red]")
                else:
                    parsed = result.get("parsed", {})
                    console.print(f"[green]Risk Score:[/green] {parsed.get('risk_score', 0):.2f}")
                    console.print(f"[green]Findings:[/green] {parsed.get('evidence_count', 0)}")
                    table = Table(title=f"Copyright OSINT Findings for {arg}", box=box.ROUNDED)
                    table.add_column("#", style="dim"); table.add_column("Type", style="cyan"); table.add_column("Severity", style="bold"); table.add_column("Evidence", style="white")
                    for idx, f in enumerate(parsed.get("findings", [])[:20], 1): table.add_row(str(idx), f.get("type", "?"), f.get("severity", "info"), f.get("evidence", "")[:80])
                    console.print(table)
                    soul.append("COPYRIGHT_OSINT", arg, result["output"])
            elif cmd == "/burp":
                if not arg: console.print("[red]Usage: /burp <target>[/red]"); continue
                result = run_tool("burp_scan", target=arg)
                if result.get("error"): console.print(f"[red]Error: {result['error']}[/red]")
                else:
                    parsed = result.get("parsed", {})
                    console.print(f"[green]Issues found:[/green] {parsed.get('issues_count', 0)}")
                    table = Table(title=f"Burp Scan Findings for {arg}", box=box.ROUNDED)
                    table.add_column("Issue", style="cyan"); table.add_column("Severity", style="bold")
                    for issue in parsed.get("findings", [])[:10]: table.add_row(issue.get("name", "?"), issue.get("severity", "info"))
                    console.print(table)
                    soul.append("BURP_SCAN", arg, result["output"])
            elif cmd == "/ghidra":
                if not arg: console.print("[red]Usage: /ghidra <binary_path>[/red]"); continue
                if not Path(arg).exists(): console.print(f"[red]Binary not found: {arg}[/red]"); continue
                result = run_tool("ghidra_analyze", binary_path=arg)
                if result.get("error"): console.print(f"[red]Error: {result['error']}[/red]")
                else:
                    parsed = result.get("parsed", {})
                    console.print(f"[green]Functions:[/green] {parsed.get('functions_count', 0)}")
                    console.print(f"[green]Interesting strings:[/green] {', '.join(parsed.get('interesting_strings', [])[:5])}")
                    vulns = parsed.get("vulnerabilities", [])
                    if vulns:
                        console.print("[red]Potential vulnerabilities:[/red]")
                        for v in vulns: console.print(f"  - {v.get('function')} ({v.get('type')})")
                    else: console.print("[green]No obvious dangerous functions found.[/green]")
                    soul.append("GHIDRA_ANALYSIS", arg, result["output"])
            elif cmd == "/sandbox":
                new_state = not config.get("sandbox", {}).get("enabled", True)
                config["sandbox"]["enabled"] = new_state
                CONFIG_FILE.write_text(json.dumps(config, indent=2))
                console.print(f"[green]Sandbox {'enabled' if new_state else 'disabled'}[/green]")
            else: console.print(f"[red]Unknown command: {cmd}[/red]  Type /help for commands.")
        else:
            soul.append("USER_INPUT", "chat", line[:500])
            full_response = ""
            try:
                with console.status("[dim]Thinking…[/dim]", spinner="dots"):
                    for chunk in gateway.stream_generate(line):
                        full_response += chunk.get("response", "")
                        if chunk.get("done"): break
            except Exception as e: console.print(f"[red]LLM error: {e}[/red]"); continue
            console.print(Panel(full_response.strip(), border_style="dim"))
            soul.append("ASSISTANT", "chat", full_response[:500])

def run_tui(soul, skill_mgr, gateway, executor, db, auto_pentest_factory, config):
    try:
        import importlib
        tui_mod = importlib.import_module("phalanx_tui")
        tui_mod.run(soul=soul, skill_mgr=skill_mgr, gateway=gateway, executor=executor, db=db, config=config)
    except ModuleNotFoundError:
        console.print("[yellow]phalanx_tui.py not found – falling back to REPL.[/yellow]")
        repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory, config)
    except Exception as e:
        console.print(f"[red]TUI failed: {e} – falling back to REPL.[/red]")
        repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory, config)

def main():
    logger.info("PHALANX v3.2 starting up...")
    try:
        # Run full bootstrap (creates all polyglot stubs)
        bootstrap_all()
        logger.info("Bootstrap completed")

        parser = argparse.ArgumentParser(description="PHALANX v3.2 Autonomous Pentesting Framework")
        parser.add_argument("--tui", action="store_true", help="Launch terminal UI")
        parser.add_argument("--scan", metavar="TARGET", help="Run objective‑driven autonomous scan and exit")
        parser.add_argument("--plan", metavar="TARGET", help="Generate OPPLAN with objectives and exit")
        parser.add_argument("--demo", action="store_true", help="Run guided demo against Metasploitable 2")
        parser.add_argument("--scrape", metavar="URL", help="Run web scrape on a URL and exit")
        parser.add_argument("--scan-type", default="full", help="Scan type: full|web|network|killchain|demo")
        parser.add_argument("--user-input", default="", help="User requirements for planning / scanning")
        parser.add_argument("--no-agentic", action="store_true", help="Disable autonomous LangGraph engine")
        parser.add_argument("--test", action="store_true", help="Run the polyglot test suite")
        args = parser.parse_args()

        config = load_config(CONFIG_FILE)
        soul = Soul(BASE_DIR / "soul.db")
        skill_mgr = SkillManager(BASE_DIR / "skills.md")
        db = PentestDB(config)
        executor = ToolExecutor(timeout=config.get("tools", {}).get("timeout", 30), soul=soul, config=config)
        gateway = Gateway(config)

        def auto_pentest_factory():
            if args.no_agentic: raise RuntimeError("Autonomous engine disabled via --no-agentic")
            return AutonomousPentest(config=config, db=db, soul=soul, skill_mgr=skill_mgr, executor=executor,
                                     progress_cb=lambda msg: console.print(f"[dim]{msg}[/dim]"), gateway=gateway)

        bootstrap_test_suite()
        if args.test:
            console.print("[bold cyan]Running polyglot test suite...[/bold cyan]")
            try:
                import pytest
                tests_dir = Path(__file__).parent / "tests"
                if not tests_dir.exists(): console.print("[red]Tests directory not found.[/red]"); sys.exit(1)
                result_code = pytest.main([str(tests_dir), "-v"])
                sys.exit(result_code)
            except ImportError: console.print("[red]pytest not installed. Run: pip install pytest[/red]"); sys.exit(1)

        if args.demo:
            console.print("[bold cyan]PHALANX Demo Mode[/bold cyan]")
            try:
                from phalanx_demo import run_demo
                run_demo()
            except ImportError: console.print("[red]Demo module not found. Install phalanx_demo.py or run /scan metasploitable2[/red]")
            return

        if args.plan:
            console.print(f"[bold cyan]Generating OPPLAN for {args.plan}...[/bold cyan]")
            plan = generate_engagement_plan(args.plan, args.user_input, gateway)
            print(json.dumps(plan, indent=2))
            return

        if args.scrape:
            console.print(f"[bold cyan]PHALANX web scrape: {args.scrape}[/bold cyan]")
            result = run_tool("scrape", target=args.scrape)
            if result.get("error"): console.print(f"[red]Error: {result['error']}[/red]"); sys.exit(1)
            parsed = result.get("parsed", {})
            console.print(f"[green]Title:[/green] {parsed.get('title', 'N/A')}")
            console.print(f"[green]Emails:[/green] {', '.join(parsed.get('emails', []))}")
            console.print(f"[green]Links:[/green] {parsed.get('links_count', 0)} found")
            console.print(f"[green]Forms:[/green] {len(parsed.get('forms', []))}")
            console.print(f"[green]Tech hints:[/green] {', '.join(parsed.get('tech_hints', [])[:3])}")
            console.print(f"[green]robots.txt:[/green] {'Yes' if parsed.get('robots_txt') else 'No'}")
            console.print(f"[green]JS Rendered:[/green] {'Yes' if parsed.get('js_rendered') else 'No'}")
            sys.exit(0)

        if args.scan:
            console.print(f"[bold cyan]PHALANX autonomous scan: {args.scan} (type={args.scan_type})[/bold cyan]")
            try:
                ap = auto_pentest_factory()
                report = ap.run(args.scan, scan_type=args.scan_type, user_input=args.user_input)
                print(json.dumps(report, indent=2, default=str))
            except Exception as e: console.print(f"[red]Scan error: {e}[/red]"); sys.exit(1)
            return

        print_logo()
        if args.tui: run_tui(soul, skill_mgr, gateway, executor, db, auto_pentest_factory, config)
        else: repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory, config)

    except Exception as e:
        logger.exception("Fatal error during startup")
        console.print(f"[red]FATAL: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
