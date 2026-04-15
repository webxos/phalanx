#!/usr/bin/env python3
"""
PHALANX v3.2 Demo – Guided autonomous pentest against Metasploitable 2.
Automatically finds the container's IP address and tests TCP ports.
"""

import json
import subprocess
import socket
import time
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from phalanx_core import BASE_DIR, CONFIG_FILE, load_config, Soul, SkillManager, PentestDB, AutonomousPentest
from phalanx_tools import Gateway
from phalanx_engine import ToolExecutor

console = Console()

DEMO_CONTAINER_NAME = "phalanx-metasploitable2"
DEMO_PORTS_TO_TEST = [22, 80, 443, 445, 3306]   # Common Metasploitable 2 ports
DEMO_STEPS = [
    "🔍 Reconnaissance – discover open ports and services",
    "🌐 Web enumeration – scan for vulnerabilities (Nikto, Gobuster)",
    "💣 Exploitation – attempt to gain initial access",
    "📊 Reporting – generate final assessment",
]

def get_container_ip(container_name: str) -> str | None:
    """Get IP address of a running Docker container."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container_name],
            capture_output=True, text=True, check=True
        )
        ip = result.stdout.strip()
        return ip if ip else None
    except Exception:
        return None

def check_tcp_port(ip: str, port: int, timeout: float = 2) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def check_target_reachable(ip: str) -> bool:
    """Test reachability by checking common ports."""
    for port in DEMO_PORTS_TO_TEST:
        if check_tcp_port(ip, port, timeout=2):
            console.print(f"[dim]  → Port {port} is open[/dim]")
            return True
    return False

def wait_for_container(ip: str, max_attempts: int = 10, delay: int = 2) -> bool:
    """Wait until at least one service port becomes open."""
    console.print(f"[dim]Waiting for services on {ip}...[/dim]")
    for attempt in range(max_attempts):
        if check_target_reachable(ip):
            return True
        console.print(f"[dim]  Attempt {attempt+1}/{max_attempts} – no open ports yet[/dim]")
        time.sleep(delay)
    return False

def run_demo():
    """Run the guided demo."""
    console.print(Panel.fit("[bold cyan]PHALANX v3.2 Demo – Metasploitable 2[/bold cyan]", border_style="cyan"))
    console.print("\n[yellow]⚠️  This demo performs active security testing. Only run on systems you own or have permission to test.[/yellow]\n")

    # Find target IP
    target_ip = get_container_ip(DEMO_CONTAINER_NAME)
    if not target_ip:
        console.print(f"[red]ERROR: Could not find running container '{DEMO_CONTAINER_NAME}'.[/red]")
        console.print("Please start the sandbox first:\n")
        console.print("  [bold]docker compose up -d[/bold]\n")
        console.print("Then wait a few seconds and run /demo again.")
        return

    console.print(f"[green]✓ Found Metasploitable 2 container at IP: {target_ip}[/green]")

    # Wait for services to become available
    if not wait_for_container(target_ip):
        console.print(f"[red]ERROR: No services responded on {target_ip} within timeout.[/red]")
        console.print("The container may not have started properly. Try:\n")
        console.print(f"  [bold]docker restart {DEMO_CONTAINER_NAME}[/bold]")
        console.print("Then wait 10 seconds and run /demo again.")
        return

    console.print(f"[green]✓ Target {target_ip} is ready (open ports detected).[/green]\n")

    # Load configuration and bootstrap
    config = load_config(CONFIG_FILE)
    soul = Soul(BASE_DIR / "soul.db")
    skill_mgr = SkillManager(BASE_DIR / "skills.md")
    db = PentestDB(config)
    executor = ToolExecutor(timeout=config.get("tools", {}).get("timeout", 30), soul=soul, config=config)
    gateway = Gateway(config)

    # Ensure Ollama is running
    if not gateway.check_ollama():
        console.print("[red]Ollama is not reachable. Please start Ollama first:[/red]")
        console.print("  [bold]ollama serve[/bold]")
        return

    # Create autonomous pentest instance
    ap = AutonomousPentest(
        config=config,
        db=db,
        soul=soul,
        skill_mgr=skill_mgr,
        executor=executor,
        progress_cb=lambda msg: console.print(f"  [dim]{msg}[/dim]"),
        gateway=gateway
    )

    # Show demo steps
    console.print("[bold]Demo plan:[/bold]")
    for i, step in enumerate(DEMO_STEPS, 1):
        console.print(f"  {i}. {step}")
    console.print("\n[bold green]Starting autonomous scan...[/bold green]")

    # Run the autonomous scan with a progress spinner
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Executing kill chain...", total=None)
        try:
            report = ap.run(target_ip, scan_type="full")
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"\n[red]Demo failed: {e}[/red]")
            return

    # Display summary
    console.print("\n[bold green]✅ Demo completed![/bold green]\n")

    # Show key findings
    vulns = report.get("vulnerabilities", [])
    if vulns:
        table = Table(title="Key Vulnerabilities Found", box=None)
        table.add_column("Severity", style="bold")
        table.add_column("Name")
        table.add_column("Port/Service")
        for v in vulns[:5]:
            table.add_row(v.get("severity", "info"), v.get("name", "?"), f"{v.get('port', '')} {v.get('service', '')}")
        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities were identified. (May need more aggressive settings.)[/yellow]")

    # Show report location
    session_id = report.get("session", {}).get("session_id", "unknown")
    console.print(f"\n[dim]Full report saved in database with session ID: {session_id}[/dim]")
    console.print("[dim]Use [/dim][bold]/history[/bold][dim] to view past sessions.[/dim]")

    # Save JSON report
    report_file = BASE_DIR / "reports" / f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_file.write_text(json.dumps(report, indent=2, default=str))
    console.print(f"[green]JSON report saved to: {report_file}[/green]")

if __name__ == "__main__":
    run_demo()
