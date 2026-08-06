# PHALANX v3.6 – Complete User Guide for Safe Bug Bounty Learning & Advanced Features

**Version:** 3.6  
**Last Updated:** August 2026  
**License:** MIT  
**Official Repo:** https://github.com/webxos/phalanx

## 1. LEGAL NOTICE

> ⚠️ **CRITICAL LEGAL & ETHICAL NOTICE**  
> PHALANX is a powerful offensive security framework.  
> **You may ONLY use it against systems you own or for which you have explicit, written authorization.**  
> Unauthorized testing is illegal under computer fraud and abuse laws in most jurisdictions (CFAA, Computer Misuse Act, etc.).  
> This guide focuses exclusively on **safe, verified, and legal** learning environments for bug bounty skill development.  
> The authors and maintainers accept no liability for misuse.

---

## 2. Table of Contents

1. [Introduction](#1-introduction)
2. [Prerequisites & Installation](#2-prerequisites--installation)
3. [Quick Start](#3-quick-start)
4. [Core Architecture & Deep Features](#4-core-architecture--deep-features)
5. [Safe & Verified Learning Environments](#5-safe--verified-learning-environments)
6. [Bug Bounty Learning Paths & Use Cases](#6-bug-bounty-learning-paths--use-cases)
7. [Advanced Feature Testing Ideas](#7-advanced-feature-testing-ideas)
8. [Recommended Workflows](#8-recommended-workflows)
9. [OPSEC, Guardrails & Best Practices](#9-opsec-guardrails--best-practices)
10. [Verification, Benchmarks & Troubleshooting](#10-verification-benchmarks--troubleshooting)
11. [Command Reference](#11-command-reference)

---

## 3. Introduction

**PHALANX** is an open-source, AI-driven autonomous penetration testing framework designed for Kali Linux (and compatible systems). It combines:

- Multi-agent swarm intelligence (T3MP3ST-style 8-operator kill chain)
- Altitude-aware reasoning via the **Raptor Loop Engine**
- Persistent knowledge graphs (**Shadow Graph**)
- Real-time defensive monitoring (**LavaWall**)
- Live **War Room** dashboard
- AI-powered reverse engineering (**OGhidra**)
- Advanced Windows evasion (**WinStealth**)
- 58+ integrated tools with structured parsing and scope containment

This guide is written specifically for **bug bounty hunters and security researchers** who want to master PHALANX’s deep and advanced capabilities in **completely safe, authorized environments**.

The goal is skill development, not live production hunting on unauthorized targets.

## 4. Core Architecture & Deep Features

### 4.1 Multi-Agent Swarm (T3MP3ST)
Eight specialized operators work cooperatively:
- **Recon** – information gathering
- **Scanner** – vulnerability discovery
- **Exploiter** – exploitation attempts
- **Infiltrator** – post-exploitation foothold expansion
- **Exfiltrator** – data extraction (within scope)
- **Ghost** – stealth / OPSEC / cleanup
- **Coordinator** – orchestration & prioritization
- **Analyst** – evidence evaluation & reporting

Agents use ReAct-style reasoning and share a common knowledge base.

### 4.2 Raptor Loop Engine
Altitude-aware iterative verification system:
- **Project** → **File** → **Feature** → **Function**
- Generator proposes actions
- Judge evaluates results and updates:
  - Coverage Matrix
  - Disposition Ledger (confirm / reject / downgrade)
  - Scrutiny Knowledge Base (monotonic suspicion scores)

Commands:
```text
/loop start <target> --altitude whole
/loop stop
/raptor status
/raptor coverage
/raptor ledger
```

### 4.3 Shadow Graph
Persistent knowledge graph that tracks relationships between:
- Hosts
- Services / ports
- Vulnerabilities
- Credentials
- Loot
- Attack paths

Enable with `--graph` or `/graph` commands.

### 4.4 LavaWall Defense + War Room
Active defensive monitoring of your own testing environment:
```text
/defense start
/defense status
/defense wifi scan wlan0
/defense vpn on
/warroom start          # then open http://localhost:3333
```

### 4.5 OGhidra (AI Reverse Engineering)
```text
/reverse load /path/to/binary
/reverse chat "What functions handle authentication?"
/reverse malware
/reverse report
```

### 4.6 WinStealth (Windows Evasion)
Reflective PE loading + syscall obfuscation (Windows/WSL only).  
**Use only on systems you own.**

### 4.7 Verify-Claims Benchmark
11-axis regression suite for testing the framework’s reliability:
```text
/verify basic
```

Axes include: Recall, FP-resistance, Coverage-honesty, Evidence-chain fidelity, Explainability, etc.

---

## 5. Safe & Verified Learning Environments

**Always prefer these over live internet targets while learning.**

| Environment              | How to Use with PHALANX                          | Notes                                      |
|--------------------------|--------------------------------------------------|--------------------------------------------|
| **Metasploitable2**      | Docker container `phalanx-target` (auto-setup)  | Classic intentionally vulnerable Linux VM |
| **Metasploitable3**      | Manual Docker / Vagrant                         | Windows + Linux variants                  |
| **DVWA / Juice Shop**    | Local Docker or VM                              | Web application focused                   |
| **Hack The Box (HTB)**   | Only machines you have active access to         | Respect HTB ToS                           |
| **TryHackMe**            | Only rooms you have started                     | Excellent guided learning                 |
| **Personal Lab VMs**     | Any OS you control                              | Best for custom scenarios                 |
| **Local Network Lab**    | Isolated VLAN / host-only network               | Ideal for multi-host campaigns            |
| **CTF Challenges**       | Platform-provided instances                     | Perfect for swarm + Raptor practice       |

**Docker Metasploitable2 example** (usually handled by `run.sh`):
```bash
docker network create phalanx-net 2>/dev/null || true
docker run -d --name phalanx-target --network phalanx-net tleemcjr/metasploitable2:latest
```

---

## 6. Bug Bounty Learning Paths & Use Cases

### Path A – Foundations (Recon + Scanning)
**Goal:** Master information gathering and structured output.

1. Start Metasploitable2 or a local web app.
2. Run basic scan → observe tool output parsing.
3. Enable Shadow Graph and explore relationships.
4. Practice `/finding` and evidence review.

**Commands to practice:**
```text
/scan <target>
/agentic <target> --guardrail
/graph status
```

### Path B – Autonomous Campaigns (Swarm)
**Goal:** Understand multi-agent coordination and kill-chain progression.

```text
/swarm scan metasploitable2 --mode ctf --follow --graph --raptor
```

Observe how the 8 operators hand off work, how the Coordinator prioritizes, and how the Analyst validates findings.

### Path C – Deep Verification (Raptor Loop)
**Goal:** Learn rigorous evidence-based vulnerability validation.

```text
/loop start metasploitable2 --altitude whole
# Let it run, then inspect:
/raptor coverage
/raptor ledger
```

This trains you to think like a senior bug bounty hunter who never reports unverified claims.

### Path D – Web Application Focus
**Targets:** DVWA, OWASP Juice Shop, local WordPress, etc.

Practice:
- Directory/file discovery (feroxbuster, ffuf)
- SQL injection (sqlmap integration)
- XSS pattern recognition (`/xss` command)
- Authentication / session analysis

### Path E – Binary & Reverse Engineering
**Safe binaries only** (your own compiled programs, CTF binaries, or public malware samples in isolated VMs).

```text
/reverse load ./my_binary
/reverse chat "Identify the main vulnerability class"
/reverse report
```

### Path F – OPSEC & Defensive Awareness
Run LavaWall while performing tests on your lab:
```text
/defense start
/warroom start
```
Learn how noisy tools appear on the defensive side — invaluable for real bug bounty OPSEC.

---

## 7. Advanced Feature Testing Ideas

All ideas below assume **authorized lab targets only**.

### 7.1 Swarm Resilience Testing
- Run the same swarm campaign multiple times with different Ollama models.
- Force network interruptions mid-campaign and observe recovery.
- Compare results with vs without `--raptor`.

### 7.2 Raptor Altitude Progression
- Start at `project` altitude, then force progressive tightening to `function`.
- Inject false positive findings and watch the Disposition Ledger reject them.
- Measure how the Scrutiny KB increases suspicion scores.

### 7.3 Shadow Graph Persistence
- Run multiple campaigns against related hosts.
- Restart PHALANX and verify the graph still contains previous relationships.
- Use the graph to drive subsequent agent decisions.

### 7.4 Guardrail & RoE Enforcement
- Always use `--guardrail` while learning.
- Intentionally try out-of-scope actions and confirm the RoE enforcer blocks them.
- Review the disposition ledger after each campaign.

### 7.5 Cross-Tool Agreement
- Use `/verify` after campaigns.
- Compare nmap vs nuclei vs custom tool findings on the same target.
- Study the Evidence-chain fidelity axis.

### 7.6 War Room Observability
- Start War Room + Defense simultaneously.
- Perform noisy scans and watch real-time alerts and metrics.
- Practice correlating defensive alerts with offensive actions.

### 7.7 Model Routing Experiments
- Switch between fast and reasoning models mid-session.
- Observe how tool selection and reasoning quality change.

### 7.8 Safe Post-Exploitation Practice
On Metasploitable2 only:
- Allow limited post-exploitation with guardrails enabled.
- Practice credential harvesting and lateral movement *inside the lab*.
- Always clean up afterwards (Ghost operator helps).

---

## 8. Recommended Workflows

### Beginner Safe Workflow
1. Start Docker Metasploitable2.
2. Launch PHALANX TUI.
3. `/defense start` + `/warroom start`.
4. `/agentic metasploitable2 --guardrail --graph`.
5. Review findings, graph, and War Room.
6. Run `/verify basic`.

### Intermediate Swarm Workflow
1. Same lab setup.
2. `/swarm scan metasploitable2 --mode ctf --follow --graph --raptor`.
3. Monitor live progress and War Room.
4. After completion, inspect Raptor coverage + ledger.
5. Export report / findings.

### Advanced Verification Workflow
1. Run agentic or swarm campaign.
2. Immediately start Raptor Loop on the same target.
3. Force altitude descent and watch disposition changes.
4. Cross-check with independent tools outside PHALANX.
5. Document the full evidence chain.

---

## 9. OPSEC, Guardrails & Best Practices

- **Always enable `--guardrail`** while learning.
- Keep `scope_strict: true` in config.
- Never set `PHALANX_ALLOW_SHELL=1` unless you fully understand the implications.
- Use isolated Docker networks or host-only lab networks.
- Prefer local Ollama models over any remote LLM for sensitive work.
- Log everything — the database and War Room make post-campaign review easy.
- After every lab session: stop defense monitors, clean containers if needed, review loot.

**Bug Bounty Mindset Translation:**
The habits you build here (evidence chains, coverage honesty, FP resistance, monotonic scrutiny) directly transfer to high-quality bug bounty reports that get paid.

---

## 10. Verification, Benchmarks & Troubleshooting

### Run the Official Benchmark Suite
```text
/verify basic
```
Review the 11 axes. This is excellent practice for understanding what “high-quality” findings look like.

### Common Issues
| Problem                        | Solution                                      |
|--------------------------------|-----------------------------------------------|
| Ollama connection failed       | Ensure `ollama serve` is running              |
| Tools missing                  | Re-run `./run.sh` or install manually         |
| Docker target not found        | `docker start phalanx-target`                 |
| Permission / scope errors      | Check RoE and `--guardrail`                   |
| High memory usage              | Use smaller models or disable swarm           |

### Health Check
```bash
python3 -c "from phalanx_library import run_health_check; run_health_check()"
```

---

## 11. Command Reference (Selected)

| Command                          | Purpose                                      |
|----------------------------------|----------------------------------------------|
| `/scan <target>`                 | Quick recon + scan                           |
| `/agentic <target> [flags]`      | Orchestrated deep dive                       |
| `/swarm scan <target> [flags]`   | Full multi-agent campaign                    |
| `/loop start <target>`           | Start Raptor Loop                            |
| `/raptor status\|coverage\|ledger` | Inspect Raptor state                      |
| `/graph ...`                     | Shadow Graph operations                      |
| `/defense start\|status\|...`    | LavaWall control                             |
| `/warroom start`                 | Launch dashboard (http://localhost:3333)     |
| `/reverse load\|chat\|malware\|report` | OGhidra RE workflow                   |
| `/verify basic`                  | Run regression suite                         |
| `/finding`, `/loot`, `/status`   | Evidence & session management                |
| `/shell`                         | Opt-in system shell (dangerous)              |

Full help is available via `help` or `/?` inside the REPL.

---
