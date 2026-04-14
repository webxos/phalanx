#!/usr/bin/env python3
"""
PHALANX v3 – Main entry point.

Usage:
  python phalanx.py            # interactive REPL
  python phalanx.py --tui      # terminal UI (prompt_toolkit)
  python phalanx.py --scan 192.168.1.1
  python phalanx.py --scan example.com --scan-type web
  python phalanx.py --scrape https://example.com   # direct web scrape
  python phalanx.py --test                         # run polyglot test suite
"""

import argparse
import json
import readline
import sys
from pathlib import Path

# ── Core imports ───────────────────────────────────────────────────────────
from phalanx_core import (
    BASE_DIR, CONFIG_FILE, HISTORY_FILE,
    load_config, bootstrap,
    Soul, SkillManager, PentestDB, AutonomousPentest,
)
from phalanx_tools import Gateway, AgenticAnalyzer, run_tool, list_tools
from phalanx_engine import ToolExecutor, bootstrap_tools

# Rich is a hard dep – already in requirements.txt
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich import box

console = Console()


# ── ASCII logo ─────────────────────────────────────────────────────────────

LOGO = r"""
██████╗ ██╗  ██╗ █████╗ ██╗      █████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██║  ██║██╔══██╗██║     ██╔══██╗████╗  ██║╚██╗██╔╝
██████╔╝███████║███████║██║     ███████║██╔██╗ ██║ ╚███╔╝ 
██╔═══╝ ██╔══██║██╔══██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
██║     ██║  ██║██║  ██║███████╗██║  ██║██║ ╚████║██╔╝ ██╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
           Autonomous Pentesting Framework  v3.0
    ⚠  Only use on systems you own or have written permission to test.
"""


def print_logo():
    console.print(Panel(
        Text(LOGO, style="bold bright_blue"),
        border_style="bright_blue",
        expand=False,
    ))


# ── Help table ─────────────────────────────────────────────────────────────

def display_help():
    t = Table(title="PHALANX v3 Commands", box=box.ROUNDED,
              show_header=True, header_style="bold cyan")
    t.add_column("Command",     style="bright_green", no_wrap=True)
    t.add_column("Description", style="white")
    t.add_column("Example",     style="dim")

    rows = [
        ("/scan <target>",        "Autonomous LangGraph pentest (IP/domain)",   "/scan 192.168.1.1"),
        ("/scrape <url>",         "Web scrape: emails, links, forms, robots.txt","/scrape https://example.com"),
        ("/tools",                "List all registered pentest tools",""),
        ("/history [n]",          "Show last n session records",                "/history 5"),
        ("/model <name>",         "Switch Ollama model",                        "/model llama3"),
        ("/personality <mode>",   "Set LLM tone (concise/detailed/code/pentest)","/personality pentest"),
        ("/skills",               "Show skill success/fail stats",              ""),
        ("/soul <query>",         "Search soul (FTS5) memory",                  "/soul nmap"),
        ("/rebootstrap",          "Force re-write all tool stubs",              ""),
        ("/clear",                "Clear screen",                               ""),
        ("/help",                 "Show this table",                            ""),
        ("/quit or /exit",        "Exit PHALANX",                               ""),
    ]
    for cmd, desc, ex in rows:
        t.add_row(cmd, desc, ex)
    console.print(t)


# ── Bootstrap test suite (create tests/test_polyglot.py if missing) ──
def bootstrap_test_suite():
    """Create the test directory and test_polyglot.py on first launch."""
    tests_dir = Path(__file__).parent / "tests"
    tests_dir.mkdir(exist_ok=True)
    test_file = tests_dir / "test_polyglot.py"
    if not test_file.exists():
        test_content = '''#!/usr/bin/env python3
"""
PHALANX Polyglot Test Suite
Run with: pytest tests/ or python phalanx.py --test
"""

import json
import subprocess
import sys
from pathlib import Path
import pytest

# Add parent directory to path to import modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from phalanx_engine import ToolExecutor, bootstrap_tools, discover_tools
from phalanx_tools import run_tool, list_tools, run_scrape

# ---------- Fixtures ----------
@pytest.fixture(scope="session")
def executor():
    bootstrap_tools(force=True)
    ex = ToolExecutor()
    ex.reload()
    return ex

# ---------- Language Tests ----------
def test_python_tool(executor):
    result = executor.execute("echo", {"message": "hello"})
    assert result["status"] == "SUCCESS"
    assert "hello" in result["summary"]

def test_shell_tool(executor):
    result = executor.execute("shell", {"command": "echo hello"})
    assert result["status"] == "SUCCESS"
    assert "hello" in result["summary"]

def test_file_read(executor, tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("secret")
    result = executor.execute("file_read", {"path": str(f)})
    assert result["status"] == "SUCCESS"
    assert "secret" in result["summary"]

def test_web_fetch(executor):
    result = executor.execute("web_fetch", {"url": "https://example.com"})
    assert result["status"] == "SUCCESS"
    assert "Example Domain" in result["summary"]

# JavaScript (if Node available)
def test_javascript_stub(executor):
    result = executor.execute("DOMExploit", {"url": "https://example.com"})
    assert result["status"] == "SUCCESS"

# Rust stub
def test_rust_stub(executor):
    result = executor.execute("PhalanxNetScanner", {})
    assert result["status"] == "SUCCESS"

# C stub
def test_c_stub(executor):
    result = executor.execute("KernelHookWatcher", {})
    assert result["status"] == "SUCCESS"

# ---------- Web Scraping Tests ----------
def test_scrape_static():
    result = run_scrape("https://example.com", use_js=False)
    assert result["rc"] == 0
    assert result["parsed"]["title"] == "Example Domain"
    assert result["parsed"]["links_count"] > 0

# Try to detect Playwright availability
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

@pytest.mark.skipif(not _PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")
def test_scrape_dynamic_with_js():
    result = run_scrape("https://webxos.netlify.app", use_js=True)
    assert result["rc"] == 0
    # After JS render, there should be many links
    assert result["parsed"]["links_count"] > 10, "JS rendering failed: few links found"
    assert result["parsed"]["title"] == "webXOS 2026"

# ---------- Tool Discovery ----------
def test_discover_tools():
    tools = discover_tools()
    tool_names = [t.name for t in tools]
    assert "echo" in tool_names
    assert "shell" in tool_names
    # Check that Wasm stub is discovered
    assert any(t.lang == "wasm" for t in tools), "Wasm tool not discovered"

# ---------- Agentic Analysis (optional) ----------
def test_list_tools():
    tools = list_tools()
    assert isinstance(tools, list)
    assert len(tools) > 0
    assert any(t["name"] == "scrape" for t in tools)
'''
        test_file.write_text(test_content)
        console.print("[green]✓ Created test suite at tests/test_polyglot.py[/green]")


# ── REPL ───────────────────────────────────────────────────────────────────

def repl(soul: Soul, skill_mgr: SkillManager, gateway: Gateway,
         executor: ToolExecutor, db: PentestDB,
         auto_pentest_factory):
    """
    Interactive REPL.  auto_pentest_factory() → AutonomousPentest instance
    (called lazily so heavy deps load only when /scan is used).
    """
    # Set up readline history
    hist = HISTORY_FILE
    try:
        readline.read_history_file(str(hist))
    except FileNotFoundError:
        pass
    readline.set_history_length(500)

    console.print("[bold green]Type [bright_white]/help[/bright_white] for commands or just chat.[/bold green]")

    # Check Ollama connectivity
    if not gateway.check_ollama():
        console.print("[bold yellow]⚠ Ollama not reachable at "
                      f"{gateway.ollama_url} – chat will fail until Ollama starts.[/bold yellow]")

    while True:
        try:
            line = console.input("[bold bright_blue]PHALANX>[/bold bright_blue] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Bye.[/dim]")
            break

        if not line:
            continue

        readline.write_history_file(str(hist))

        # ── slash commands ────────────────────────────────────────────────
        if line.startswith("/"):
            parts = line.split(maxsplit=1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd in ("/quit", "/exit", "/q"):
                console.print("[dim]Bye.[/dim]")
                break

            elif cmd == "/help":
                display_help()

            elif cmd == "/clear":
                console.clear()

            elif cmd == "/tools":
                tools = list_tools()
                t = Table(box=box.SIMPLE, show_header=True)
                t.add_column("Tool", style="bright_green")
                t.add_column("Tags", style="dim")
                t.add_column("Description")
                for tool in tools:
                    t.add_row(tool["name"], ", ".join(tool["tags"]), tool["desc"])
                console.print(t)

            elif cmd == "/scan":
                target = arg.strip()
                if not target:
                    console.print("[red]Usage: /scan <target>[/red]")
                    continue
                console.print(f"[bold cyan]Starting autonomous scan of {target}…[/bold cyan]")
                try:
                    ap = auto_pentest_factory()
                    report = ap.run(target)
                    console.print_json(json.dumps(report, indent=2, default=str))
                except ImportError as e:
                    console.print(f"[red]Autonomous engine not available: {e}[/red]")
                except Exception as e:
                    console.print(f"[red]Scan failed: {e}[/red]")

            elif cmd == "/scrape":
                url = arg.strip()
                if not url:
                    console.print("[red]Usage: /scrape <url> (e.g., /scrape https://example.com)[/red]")
                    continue
                console.print(f"[bold cyan]Scraping {url}…[/bold cyan]")
                result = run_tool("scrape", target=url)
                if result.get("error"):
                    console.print(f"[red]Error: {result['error']}[/red]")
                else:
                    parsed = result.get("parsed", {})
                    tbl = Table(title=f"Scrape results for {url}", box=box.ROUNDED)
                    tbl.add_column("Key", style="cyan")
                    tbl.add_column("Value", style="white")
                    tbl.add_row("Status Code", str(parsed.get("status_code", "?")))
                    tbl.add_row("Title", parsed.get("title", "N/A"))
                    tbl.add_row("Emails", ", ".join(parsed.get("emails", [])[:5]) or "None")
                    tbl.add_row("Links Found", str(parsed.get("links_count", 0)))
                    tbl.add_row("Forms", str(len(parsed.get("forms", []))))
                    tbl.add_row("Tech Hints", ", ".join(parsed.get("tech_hints", [])[:3]) or "None")
                    tbl.add_row("robots.txt", "Yes" if parsed.get("robots_txt") else "No")
                    tbl.add_row("JS Rendered", "Yes" if parsed.get("js_rendered") else "No")
                    console.print(tbl)
                    soul.append("SCRAPE", url, result["output"])

            elif cmd == "/model":
                if arg:
                    gateway.set_model(arg.strip())
                    console.print(f"[green]Model set to {arg.strip()}[/green]")
                else:
                    models = gateway.list_models()
                    console.print("[cyan]Available models:[/cyan] " + ", ".join(models))

            elif cmd == "/personality":
                mode = arg.strip()
                gateway.set_personality(mode)
                console.print(f"[green]Personality set to '{mode}'[/green]")

            elif cmd == "/skills":
                skills = skill_mgr.list_skills()
                if not skills:
                    console.print("[dim]No skills recorded yet.[/dim]")
                else:
                    t = Table(box=box.SIMPLE)
                    t.add_column("Skill")
                    t.add_column("✓", style="green")
                    t.add_column("✗", style="red")
                    t.add_column("Last Used", style="dim")
                    for s in skills:
                        t.add_row(s["name"], str(s["success"]),
                                  str(s["fail"]), s["last_used"])
                    console.print(t)

            elif cmd == "/soul":
                query = arg.strip()
                if not query:
                    results = soul.recent(20)
                else:
                    results = soul.search(query)
                for r in results:
                    console.print(f"[dim]{r['ts']}[/dim] [{r['type']}] {r.get('summary', r.get('content', ''))}")

            elif cmd == "/history":
                try:
                    limit = int(arg) if arg else 10
                except ValueError:
                    limit = 10
                sessions = db.list_sessions(limit)
                for s in sessions:
                    status_color = "green" if s["status"] == "completed" else "yellow"
                    console.print(
                        f"[dim]{s['started_at']}[/dim] "
                        f"[bold]{s['target']}[/bold] "
                        f"[{status_color}]{s['status']}[/{status_color}] "
                        f"[dim]{s['session_id']}[/dim]"
                    )

            elif cmd == "/rebootstrap":
                console.print("[yellow]Re-bootstrapping tools…[/yellow]")
                bootstrap_tools(force=True)
                executor.reload()
                console.print("[green]Done.[/green]")

            else:
                console.print(f"[red]Unknown command: {cmd}[/red]  Type /help for commands.")

        # ── free-form chat ────────────────────────────────────────────────
        else:
            soul.append("USER_INPUT", "chat", line[:500])
            full_response = ""
            try:
                with console.status("[dim]Thinking…[/dim]", spinner="dots"):
                    for chunk in gateway.stream_generate(line):
                        full_response += chunk.get("response", "")
                        if chunk.get("done"):
                            break
            except Exception as e:
                console.print(f"[red]LLM error: {e}[/red]")
                continue
            console.print(Panel(full_response.strip(), border_style="dim"))
            soul.append("ASSISTANT", "chat", full_response[:500])


# ── TUI mode ───────────────────────────────────────────────────────────────

def run_tui(soul, skill_mgr, gateway, executor, db, auto_pentest_factory):
    """Launch the prompt_toolkit TUI."""
    try:
        import importlib
        tui_mod = importlib.import_module("phalanx_tui")
        tui_mod.run(soul=soul, skill_mgr=skill_mgr, gateway=gateway,
                    executor=executor, db=db)
    except ModuleNotFoundError:
        console.print("[yellow]phalanx_tui.py not found – falling back to REPL.[/yellow]")
        repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory)
    except Exception as e:
        console.print(f"[red]TUI failed: {e} – falling back to REPL.[/red]")
        repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PHALANX v3 Autonomous Pentesting Framework")
    parser.add_argument("--tui",       action="store_true", help="Launch terminal UI")
    parser.add_argument("--scan",      metavar="TARGET",    help="Run autonomous scan and exit")
    parser.add_argument("--scrape",    metavar="URL",       help="Run web scrape on a URL and exit")
    parser.add_argument("--scan-type", default="full",      help="Scan type: full|web|network")
    parser.add_argument("--no-agentic",action="store_true", help="Disable autonomous LangGraph engine")
    parser.add_argument("--test",      action="store_true", help="Run the polyglot test suite")
    args = parser.parse_args()

    # Bootstrap dirs + tools
    try:
        bootstrap()
    except Exception as e:
        print(f"[warn] bootstrap error: {e}", file=sys.stderr)

    config    = load_config(CONFIG_FILE)
    soul      = Soul(BASE_DIR / "soul.db")
    skill_mgr = SkillManager(BASE_DIR / "skills.md")
    db        = PentestDB(config)
    executor  = ToolExecutor(timeout=config.get("tools", {}).get("timeout", 30),
                             soul=soul, config=config)
    gateway   = Gateway(config)

    # Lazy factory so heavy LangGraph deps only import when actually needed
    def auto_pentest_factory():
        if args.no_agentic:
            raise RuntimeError("Autonomous engine disabled via --no-agentic")
        return AutonomousPentest(
            config=config, db=db, soul=soul,
            skill_mgr=skill_mgr, executor=executor,
            progress_cb=lambda msg: console.print(f"[dim]{msg}[/dim]"),
        )

    # ── Bootstrap test suite (so test file exists) ──
    bootstrap_test_suite()

    # ── Run test suite if requested ──
    if args.test:
        console.print("[bold cyan]Running polyglot test suite...[/bold cyan]")
        try:
            import pytest
            tests_dir = Path(__file__).parent / "tests"
            if not tests_dir.exists():
                console.print("[red]Tests directory not found.[/red]")
                sys.exit(1)
            result_code = pytest.main([str(tests_dir), "-v"])
            sys.exit(result_code)
        except ImportError:
            console.print("[red]pytest not installed. Run: pip install pytest[/red]")
            sys.exit(1)

    # ── Direct scrape mode ────────────────────────────────────────────────
    if args.scrape:
        console.print(f"[bold cyan]PHALANX web scrape: {args.scrape}[/bold cyan]")
        result = run_tool("scrape", target=args.scrape)
        if result.get("error"):
            console.print(f"[red]Error: {result['error']}[/red]")
            sys.exit(1)
        parsed = result.get("parsed", {})
        console.print(f"[green]Title:[/green] {parsed.get('title', 'N/A')}")
        console.print(f"[green]Emails:[/green] {', '.join(parsed.get('emails', []))}")
        console.print(f"[green]Links:[/green] {parsed.get('links_count', 0)} found")
        console.print(f"[green]Forms:[/green] {len(parsed.get('forms', []))}")
        console.print(f"[green]Tech hints:[/green] {', '.join(parsed.get('tech_hints', [])[:3])}")
        console.print(f"[green]robots.txt:[/green] {'Yes' if parsed.get('robots_txt') else 'No'}")
        console.print(f"[green]JS Rendered:[/green] {'Yes' if parsed.get('js_rendered') else 'No'}")
        sys.exit(0)

    # ── Direct scan mode ──────────────────────────────────────────────────
    if args.scan:
        console.print(f"[bold cyan]PHALANX scan: {args.scan} (type={args.scan_type})[/bold cyan]")
        try:
            ap = auto_pentest_factory()
            report = ap.run(args.scan, scan_type=args.scan_type)
            print(json.dumps(report, indent=2, default=str))
        except ImportError as e:
            console.print(f"[red]Autonomous engine requires extra packages: {e}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Scan error: {e}[/red]")
            sys.exit(1)
        return

    # ── Interactive mode ──────────────────────────────────────────────────
    print_logo()

    if args.tui:
        run_tui(soul, skill_mgr, gateway, executor, db, auto_pentest_factory)
    else:
        repl(soul, skill_mgr, gateway, executor, db, auto_pentest_factory)


if __name__ == "__main__":
    main()
