# PHALANX v3.6 – Autonomous Pentesting Framework

![Version](https://img.shields.io/badge/version-3.6-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

**PHALANX** is an autonomous, AI‑driven penetration testing framework that combines multi‑agent swarms, a looped reasoning engine (Raptor), low‑level Windows evasion (WinStealth), and a real‑time War Room dashboard. It is designed for red teams, bug bounty hunters, and security researchers who need scalable, adaptive, and intelligent offensive security tooling.

> ⚠️ **Only use on systems you own or have explicit written permission to test.**

---

## Key Features

- **Multi‑Agent Swarm** – 8‑operator T3MP3ST‑style kill chain (Recon, Scanner, Exploiter, Infiltrator, Exfiltrator, Ghost, Coordinator, Analyst) with ReAct reasoning.
- **Raptor Loop Engine** – Altitude‑aware (project → file → feature → function) generator/judge pipeline with coverage matrix, disposition ledger, and monotonic scrutiny knowledge base.
- **WinStealth Integration** – Reflective PE loading, syscall obfuscation, and profile switching for advanced Windows evasion (renamed from SindriKit).
- **Shadow Graph** – Persistent knowledge graph that tracks relationships between hosts, vulnerabilities, credentials, and loot across campaigns.
- **LavaWall Defense** – Active network monitoring, VPN control, Wi‑Fi environment scanning, and alerting with Raptor insight enrichment.
- **War Room Dashboard** – FastAPI‑based web UI with live system status, defense alerts, shell history, Raptor coverage, and OGhidra integration.
- **OGhidra Integration** – AI‑powered binary analysis (malware detection, smart renaming, conversational reverse engineering) using Ghidra headless.
- **verify‑claims Benchmark** – 11‑axis regression test suite (Recall, FP‑resistance, Coverage‑honesty, etc.) with golden outputs.
- **Rich Tool Arsenal** – 58+ built‑in tools (nmap, nuclei, subfinder, sqlmap, impacket, wpscan, feroxbuster, theHarvester, …) with structured parsing and egress‑scope containment.
- **Interactive CLI / TUI** – Full REPL with command history, auto‑suggest, rich tables, and a `/shell` (opt‑in) for arbitrary system commands.

## Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com) (for LLM capabilities) – optional, falls back to static planning.
- Docker (optional, for sandbox and Metasploitable2 target)
- System tools (nmap, nuclei, subfinder, etc.) – `run.sh` installs most.

## Installation

Place all files from this repo into a /phalanx/ folder on your system.

Then run:

```bash
cd ~/phalanx/ (The folder you put the files in)
chmod +x run.sh
./run.sh
```

The `run.sh` script will:
- Detect your OS (Kali, Linux, macOS, WSL)
- Install system dependencies and Go tools
- Set up a Python virtual environment (optional)
- Bootstrap PHALANX components (directories, agent stubs, config)
- Optionally pull Ollama models and start Docker containers


## Usage

Start the TUI (recommended):

```bash
python3 phalanx.py --tui
```

Or run a single command:

```bash
python3 phalanx.py scan 192.168.1.1
python3 phalanx.py agentic metasploitable2 --graph --guardrail
```

---

## Swarm & Agentic Modes

### Swarm (CTF / autonomous)

```text
/swarm scan metasploitable2 --mode ctf --follow --graph --raptor
```

Launches a multi‑agent campaign with 8 operators (T3MP3ST) or uses the Raptor loop for altitude‑aware reasoning. The `--follow` flag streams live progress; `--raptor` enables the generator/judge pipeline.

### Agentic (single‑target deep dive)

```text
/agentic 192.168.1.1 --guardrail --graph --windows
```

Uses an orchestrator and dedicated Recon/Exploit/Post‑Exploit agents (with RoE confirmation).

---

## Raptor Loop Engine

The Raptor loop performs iterative, altitude‑aware verification:

- **Altitudes**: `project` → `file` → `feature` → `function`
- **Generator** proposes actions (e.g., run a tool, inspect a file)
- **Judge** evaluates outcomes and updates:
  - **Coverage Matrix** (which altitudes are covered)
  - **Disposition Ledger** (confirm/reject/downgrade findings)
  - **Scrutiny KB** (monotonic suspicion scores for entities)

Commands:

```text
/loop start target --altitude whole
/loop stop
```

Status in War Room or via `/status`.

---

## Defense Monitor & War Room

### Defense Monitor

Start active monitoring:

```text
/defense start
/defense status
/defense standby off          # enable alerts
/defense wifi scan wlan0
/defense vpn on
```

Alerts are logged in SQLite and optionally enriched with Raptor insights if a campaign is active.

### War Room Dashboard

Start the FastAPI server:

```text
/warroom start
```

Then open `http://localhost:3333` for a live dashboard showing:
- System status (CPU, memory, disk)
- Defense alerts
- Shell command history
- Raptor coverage
- Graph visualisation

---

## Reverse Engineering with OGhidra

PHALANX integrates with Ghidra 11.3+ and the [OGhidraMCP](https://github.com/llnl/OGhidra) plugin for AI‑powered binary analysis.

```text
/reverse load /path/to/binary.exe
/reverse chat "What functions handle network input?"
/reverse malware
/reverse report
```

The `/reverse` command uses OGhidra’s headless mode and can detect malware patterns, suggest renames, and generate structured RE reports.

---

## WinStealth (Windows Evasion)

On Windows or WSL, after building the library (`python phalanx_extra.py --build-winstealth`), you can:

```text
/winstealth profile Win32
/winstealth load payload.exe
/winstealth exec reflect
```

This performs reflective PE loading and syscall obfuscation. All contexts are tracked in the database for later reuse.

---

## Verify‑claims Benchmark

Run the 11‑axis regression suite:

```text
/verify basic
```

The benchmark checks Recall, FP‑resistance, False‑rejection, Coverage‑honesty, Severity‑downgrade integrity, Evidence‑chain fidelity, Temporal consistency, Cross‑tool agreement, Adversarial resilience, Explainability, and Operational utility. Results are stored in the `benchmark_results` table.

---

## Configuration

Configuration is stored in `phalanx/config/config.json`. Key sections:

```json
{
  "ollama": {
    "url": "http://localhost:11434",
    "default_model": "qwen2.5:7b",
    "fast_model": "qwen2.5:1.5b"
  },
  "sandbox": {
    "enabled": true,
    "docker_network": "phalanx-net",
    "image": "kalilinux/kali-rolling"
  },
  "winstealth": {
    "enabled": false,
    "default_profile": "Win32"
  },
  "defense": {
    "standby": true,
    "detect_reverse_tools": true,
    "ledger_integration": true,
    "campaign_id": "defense"
  },
  "opsec": {
    "scope_strict": true,
    "max_detection_risk": 0.8
  }
}
```

Environment variables can override many settings (e.g., `PHALANX_DEFAULT_MODEL`, `PHALANX_SKIP_WINSTEALTH`, `PHALANX_ALLOW_SHELL`).

---


## License

This project is licensed under the MIT License
