#!/usr/bin/env python3
"""
PHALANX phalanx_tools.py – Ollama LLM gateway + all recon tool runners.
Includes web scraping (scrape) tool with Playwright for JS rendering.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional

import requests
# Web scraping imports
try:
    from bs4 import BeautifulSoup
    from fake_useragent import UserAgent
    _SCRAPE_AVAILABLE = True
except ImportError:
    _SCRAPE_AVAILABLE = False
    BeautifulSoup = None
    UserAgent = None

# Playwright for dynamic JS rendering
try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

# ================================
# SECTION 1: LLM GATEWAY
# ================================

PENTEST_SYSTEM = """You are PHALANX, an expert offensive security AI running locally via Ollama.
You perform authorized penetration testing. You are methodical, technical, and precise.

When analyzing scan results:
1. Identify CVEs, open ports, misconfigurations, and exposed services.
2. Prioritize by CVSS severity: Critical > High > Medium > Low > Info.
3. For each finding suggest concrete exploitation vectors AND remediation steps.
4. If you need more information, specify which tool to run next.

IMPORTANT: Only operate on systems for which you have explicit written authorization.
Output: Always respond with valid JSON when in analysis mode."""

AGENTIC_SYSTEM = """You are PHALANX, an autonomous penetration testing agent.
Available tools: {tool_list}

For each step respond ONLY with this JSON:
{{
  "needs_more_info": true|false,
  "tool_requests": [{{"tool": "name", "args": {{"target": "..."}}}}],
  "findings": ["..."],
  "vulnerabilities": [
    {{"name":"...","severity":"critical|high|medium|low|info",
      "description":"...","cve":"","evidence":"","port":"","service":""}}
  ],
  "exploits_suggested": [{{"name":"...","tool":"...","command":"...","notes":"..."}}],
  "fixes": [{{"vuln":"...","description":"...","commands":[],"priority":1}}],
  "summary": "one-paragraph assessment",
  "risk_score": 0.0
}}

If needs_more_info is true, tool_requests must be non-empty."""

QUERY_SYSTEM = """You are PHALANX, a concise local AI assistant on Debian Linux.
Answer in plain English. Be brief and technical. If unsure, say so."""


class Gateway:
    """Ollama HTTP client – streaming, chat, model switching."""

    PERSONALITY_PROMPTS = {
        "concise":  "Be brief and direct. Max 3 sentences unless code is needed.",
        "detailed": "Provide detailed step-by-step explanations.",
        "code":     "Focus on working code and technical accuracy. Skip pleasantries.",
        "pentest":  "You are a penetration tester. Give technical offensive security answers.",
    }

    def __init__(self, config: dict):
        self.config = config
        oc = config.get("ollama", {})
        self.ollama_url      = oc.get("url", "http://localhost:11434")
        self.default_model   = oc.get("default_model", "qwen2.5:7b")
        self.fast_model      = oc.get("fast_model", "qwen2.5:1.5b")
        self.analysis_model  = oc.get("analysis_model", "qwen2.5:7b")
        self.temperature     = oc.get("temperature", 0.1)
        self.timeout         = oc.get("timeout", 120)
        self.models_config   = config.get("models", {})
        self.current_personality = "concise"
        self._hb_thread: Optional[threading.Thread] = None

    def check_ollama(self) -> bool:
        try:
            r = requests.get(f"{self.ollama_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
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

    def stream_generate(self, prompt: str,
                        model: Optional[str] = None,
                        system: Optional[str] = None) -> Iterator[Dict]:
        model = model or self.default_model
        personality = self.PERSONALITY_PROMPTS.get(self.current_personality, "")
        sys_suffix = self.models_config.get(model, {}).get("system_prompt_suffix", "")
        full_system = " ".join(filter(None, [system or QUERY_SYSTEM, personality, sys_suffix]))
        payload = {
            "model": model,
            "prompt": prompt,
            "system": full_system,
            "stream": True,
            "options": {
                "temperature": self.temperature,
                **{k: v for k, v in self.models_config.get(model, {}).items()
                   if k != "system_prompt_suffix"},
            },
        }
        try:
            with requests.post(f"{self.ollama_url}/api/generate",
                               json=payload, stream=True, timeout=self.timeout) as r:
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

    def chat(self, messages: List[Dict],
             model: Optional[str] = None,
             json_mode: bool = False) -> str:
        model = model or self.default_model
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            r = requests.post(f"{self.ollama_url}/api/chat",
                              json=payload, timeout=self.timeout)
            if r.status_code == 200:
                return r.json()["message"]["content"]
            return f"[Error: Ollama HTTP {r.status_code}]"
        except Exception as e:
            return f"[Gateway error: {e}]"

    def generate(self, prompt: str,
                 model: Optional[str] = None,
                 system: Optional[str] = None,
                 json_mode: bool = False) -> str:
        full = ""
        for chunk in self.stream_generate(prompt, model=model, system=system):
            full += chunk.get("response", "")
            if chunk.get("done"):
                break
        return full

    def start_heartbeat(self, interval: int = 60):
        def _hb():
            while True:
                time.sleep(interval)
        self._hb_thread = threading.Thread(target=_hb, daemon=True)
        self._hb_thread.start()


class AgenticAnalyzer:
    """
    ReAct loop:
    1. Seed with initial recon data.
    2. LLM decides if more tool runs needed.
    3. Execute requested tools.
    4. Feed results back.
    5. Repeat until needs_more_info=false or max iterations.
    """

    MAX_ITERATIONS = 5

    def __init__(self, gateway: Gateway, tool_runner: Callable,
                 available_tools: List[str],
                 progress_cb: Optional[Callable[[str], None]] = None):
        self.gateway = gateway
        self.tool_runner = tool_runner
        self.available_tools = available_tools
        self.progress = progress_cb or (lambda msg: None)

    def _build_system(self) -> str:
        return AGENTIC_SYSTEM.format(tool_list=", ".join(self.available_tools))

    def _safe_parse_json(self, text: str) -> Optional[Dict]:
        text = text.strip()
        text = re.sub(r"^```(?:json)?", "", text, flags=re.MULTILINE)
        text = re.sub(r"```$", "", text, flags=re.MULTILINE)
        text = text.strip()
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    def _format_tool_output(self, results: List[Dict]) -> str:
        parts = []
        for r in results:
            tool = r.get("tool", "unknown")
            output = r.get("output", "")[:2000]
            parsed = r.get("parsed", {})
            err = r.get("error")
            if err:
                parts.append(f"[{tool}] ERROR: {err}")
            else:
                parts.append(
                    f"[{tool}] OUTPUT:\n{output}\nPARSED: {json.dumps(parsed, indent=2)[:500]}"
                )
        return "\n\n".join(parts)

    def analyze(self, target: str, initial_recon: Dict[str, Any]) -> Dict[str, Any]:
        context = "\n\n".join(
            self._format_tool_output([r]) for r in initial_recon.values()
        )
        messages = [
            {"role": "system", "content": self._build_system()},
            {"role": "user", "content": (
                f"Target: {target}\n\nInitial recon:\n{context}\n\n"
                "Analyze. Identify vulnerabilities, suggest exploits, recommend fixes. "
                "Request more tools if needed."
            )},
        ]
        last_analysis: Dict[str, Any] = {}
        for iteration in range(self.MAX_ITERATIONS):
            self.progress(f"[Agentic] Iteration {iteration + 1}/{self.MAX_ITERATIONS}…")
            raw = self.gateway.chat(messages, model=self.gateway.analysis_model, json_mode=True)
            parsed = self._safe_parse_json(raw)
            if not parsed:
                self.progress("[Agentic] Could not parse JSON, retrying…")
                messages.append({"role": "assistant", "content": raw})
                messages.append({"role": "user",
                                 "content": "Your response was not valid JSON. "
                                            "Respond with ONLY a valid JSON object."})
                continue
            last_analysis = parsed
            messages.append({"role": "assistant", "content": raw})
            if not parsed.get("needs_more_info", False):
                self.progress("[Agentic] Analysis complete.")
                break
            tool_reqs = parsed.get("tool_requests", [])
            if not tool_reqs:
                self.progress("[Agentic] needs_more_info=true but no tool_requests. Stopping.")
                break
            new_results = []
            for req in tool_reqs[:3]:
                tool_name = req.get("tool", "")
                args = req.get("args", {})
                if not tool_name:
                    continue
                self.progress(f"[Agentic] Running: {tool_name}({args})")
                try:
                    result = self.tool_runner(tool_name, **args)
                except Exception as e:
                    result = {"tool": tool_name, "output": "", "parsed": {},
                              "error": str(e), "rc": -1}
                new_results.append(result)
            messages.append({
                "role": "user",
                "content": (
                    f"Tool results:\n{self._format_tool_output(new_results)}\n\n"
                    "Update your analysis. Provide complete findings in JSON."
                ),
            })
        return last_analysis

    def quick_analysis(self, target: str, tool_results: List[Dict]) -> str:
        combined = self._format_tool_output(tool_results)
        prompt = (
            f"Target: {target}\n\nScan results:\n{combined}\n\n"
            "Give a concise security assessment: key findings, severity levels, "
            "and top 3 recommended actions. Plain text, max 400 words."
        )
        return self.gateway.generate(
            prompt, model=self.gateway.analysis_model, system=PENTEST_SYSTEM
        )


# ================================
# SECTION 2: PENTEST TOOL RUNNERS
# ================================

def _run(cmd: List[str], timeout: int = 120,
         input_data: Optional[str] = None) -> Dict[str, Any]:
    if not shutil.which(cmd[0]):
        return {
            "output": "",
            "error": f"Tool '{cmd[0]}' not found – install: sudo apt install {cmd[0]}",
            "rc": -1,
        }
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input_data,
        )
        return {
            "output": (result.stdout + result.stderr).strip(),
            "error": None if result.returncode == 0 else result.stderr.strip()[:500],
            "rc": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"output": "", "error": f"Timed out after {timeout}s", "rc": -1}
    except Exception as e:
        return {"output": "", "error": str(e), "rc": -1}


def _wrap(tool: str, target: str, run_result: Dict,
          parsed: Optional[Dict] = None) -> Dict[str, Any]:
    return {
        "tool": tool,
        "target": target,
        "output": run_result["output"],
        "parsed": parsed or {},
        "error": run_result["error"],
        "rc": run_result["rc"],
    }


# ---- parsers ----
def _parse_nmap(output: str) -> Dict:
    ports = []
    for line in output.splitlines():
        m = re.match(r"(\d+)/(\w+)\s+(\w+)\s+(.*)", line.strip())
        if m:
            ports.append({"port": m.group(1), "proto": m.group(2),
                          "state": m.group(3), "service": m.group(4).strip()})
    return {"open_ports": ports, "port_count": len(ports)}

def _parse_nikto(output: str) -> Dict:
    findings = [l.strip() for l in output.splitlines()
                if l.strip().startswith("+") and "Server" not in l[:20]]
    return {"findings": findings, "count": len(findings)}

def _parse_whois(output: str) -> Dict:
    fields: Dict[str, str] = {}
    for line in output.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower().replace(" ", "_")
            v = v.strip()
            if k and v and k not in fields:
                fields[k] = v
    return {"fields": fields}


# ---- existing tool functions (kept as before) ----
def run_nmap(target: str, ports: str = "1-65535",
             flags: str = "-sV -sC --open", timeout: int = 300) -> Dict:
    cmd = ["nmap"] + flags.split() + ["-p", ports, target]
    r = _run(cmd, timeout=timeout)
    return _wrap("nmap", target, r, _parse_nmap(r["output"]))

def run_nmap_quick(target: str, timeout: int = 60) -> Dict:
    r = _run(["nmap", "-sV", "--open", "--top-ports", "1000", target], timeout=timeout)
    return _wrap("nmap_quick", target, r, _parse_nmap(r["output"]))

def run_nikto(target: str, timeout: int = 300) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    r = _run(["nikto", "-h", url, "-Format", "txt", "-nointeractive"], timeout=timeout)
    return _wrap("nikto", target, r, _parse_nikto(r["output"]))

def run_whois(target: str, timeout: int = 30) -> Dict:
    r = _run(["whois", target], timeout=timeout)
    return _wrap("whois", target, r, _parse_whois(r["output"]))

def run_dig(target: str, record: str = "ANY", timeout: int = 15) -> Dict:
    r = _run(["dig", target, record, "+noall", "+answer"], timeout=timeout)
    records = [l.strip() for l in r["output"].splitlines() if l.strip() and not l.startswith(";")]
    return _wrap("dig", target, r, {"records": records})

def run_http_probe(target: str, timeout: int = 15) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    r = _run(["curl", "-s", "-I", "--max-time", "10", "--connect-timeout", "5", url], timeout=timeout)
    headers: Dict[str, str] = {}
    status = ""
    for line in r["output"].splitlines():
        if line.startswith("HTTP/"):
            status = line.strip()
        elif ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return _wrap("http_probe", target, r, {"status": status, "headers": headers})

def run_whatweb(target: str, timeout: int = 30) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    r = _run(["whatweb", "-a", "3", url], timeout=timeout)
    return _wrap("whatweb", target, r, {"raw": r["output"][:2000]})

def run_gobuster_dirs(target: str,
                      wordlist: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                      timeout: int = 300) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    r = _run(["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-progress", "-t", "20"], timeout=timeout)
    found = [l.strip() for l in r["output"].splitlines() if l.strip().startswith("/") or "(Status:" in l]
    return _wrap("gobuster", target, r, {"found_paths": found})

def run_subfinder(domain: str, timeout: int = 60) -> Dict:
    r = _run(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    subs = [l.strip() for l in r["output"].splitlines() if l.strip()]
    return _wrap("subfinder", domain, r, {"subdomains": subs, "count": len(subs)})

def run_theharvester(domain: str, sources: str = "all", timeout: int = 120) -> Dict:
    r = _run(["theHarvester", "-d", domain, "-b", sources, "-l", "200"], timeout=timeout)
    emails = re.findall(r"[\w.\-]+@[\w.\-]+", r["output"])
    hosts = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r["output"])
    return _wrap("theHarvester", domain, r, {"emails": list(set(emails)), "ips": list(set(hosts))})

def run_enum4linux(target: str, timeout: int = 180) -> Dict:
    r = _run(["enum4linux", "-a", target], timeout=timeout)
    users = re.findall(r"user:\[(\w+)\]", r["output"])
    shares = re.findall(r"Sharename\s+(\S+)", r["output"])
    return _wrap("enum4linux", target, r, {"users": list(set(users)), "shares": list(set(shares))})

def run_searchsploit(query: str, timeout: int = 20) -> Dict:
    cmd = (["searchsploit", "--nmap", query] if query.endswith(".xml") else ["searchsploit", "-t", query])
    r = _run(cmd, timeout=timeout)
    lines = [l.strip() for l in r["output"].splitlines() if "|" in l and "EDB-ID" not in l and "---" not in l]
    return _wrap("searchsploit", query, r, {"exploits": lines[:30]})

def run_ssl_check(target: str, port: int = 443, timeout: int = 15) -> Dict:
    r = _run(["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", target, "-brief"],
             timeout=timeout, input_data="")
    expiry = re.search(r"notAfter=(.*)", r["output"])
    issuer = re.search(r"issuer=(.*)", r["output"])
    subject = re.search(r"subject=(.*)", r["output"])
    return _wrap("ssl_check", target, r, {
        "expiry": expiry.group(1).strip() if expiry else "",
        "issuer": issuer.group(1).strip() if issuer else "",
        "subject": subject.group(1).strip() if subject else "",
    })

def run_banner_grab(target: str, port: int = 80, timeout: int = 10) -> Dict:
    r = _run(["nc", "-w", "3", "-v", target, str(port)], timeout=timeout, input_data="\r\n")
    return _wrap("banner_grab", f"{target}:{port}", r, {"banner": r["output"][:500]})

def run_ffuf(target: str,
             wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
             timeout: int = 300) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    r = _run(["ffuf", "-u", url, "-w", wordlist, "-s", "-mc", "200,301,302,403", "-t", "30"], timeout=timeout)
    found = [l.strip() for l in r["output"].splitlines() if l.strip()]
    return _wrap("ffuf", target, r, {"found": found})

def run_wpscan(target: str, timeout: int = 180) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    r = _run(["wpscan", "--url", url, "--no-update", "--format", "cli-no-color"], timeout=timeout)
    vulns = [l.strip() for l in r["output"].splitlines() if "[!]" in l or "[+]" in l]
    return _wrap("wpscan", target, r, {"findings": vulns})

def run_sqlmap_detect(target: str, timeout: int = 120) -> Dict:
    url = target if target.startswith("http") else f"http://{target}"
    r = _run(["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
              "--technique=B", "--no-cast", "--forms", "--crawl=1",
              "--output-dir=/tmp/phalanx_sqlmap"], timeout=timeout)
    injectable = "injectable" in r["output"].lower()
    return _wrap("sqlmap_detect", target, r, {"injectable": injectable})


# ---------- ENHANCED WEB SCRAPING TOOL (with Playwright fallback) ----------
def run_scrape(target: str, timeout: int = 30, use_js: bool = True) -> Dict:
    """
    Web scraper that uses Playwright for JavaScript rendering if available.
    Falls back to requests+BeautifulSoup when use_js=False or Playwright missing.
    """
    if not _SCRAPE_AVAILABLE:
        return {
            "tool": "scrape",
            "target": target,
            "output": "",
            "parsed": {},
            "error": "Missing scraping libraries: install beautifulsoup4, lxml, fake-useragent",
            "rc": -1,
        }

    # Normalize URL
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    # ---- JavaScript rendering mode (Playwright) ----
    if use_js and _PLAYWRIGHT_AVAILABLE:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(target, timeout=timeout * 1000)
                # Wait for network idle to let JS execute
                page.wait_for_load_state("networkidle")
                # Additional wait for dynamic content (adjust as needed)
                page.wait_for_timeout(2000)
                html = page.content()
                browser.close()
        except Exception as e:
            return {
                "tool": "scrape",
                "target": target,
                "output": "",
                "parsed": {},
                "error": f"Playwright error: {e}",
                "rc": -1,
            }
        soup = BeautifulSoup(html, "lxml")
        response_status = 200  # Playwright doesn't easily give status code, assume OK
    else:
        # Fallback to static requests
        if use_js and not _PLAYWRIGHT_AVAILABLE:
            print("[scrape] Playwright not installed, falling back to static requests.")
        try:
            ua = UserAgent()
            headers = {"User-Agent": ua.random}
            response = requests.get(target, headers=headers, timeout=timeout, allow_redirects=True)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "lxml")
            response_status = response.status_code
        except Exception as e:
            return {
                "tool": "scrape",
                "target": target,
                "output": "",
                "parsed": {},
                "error": str(e),
                "rc": -1,
            }

    # ----- Parse with BeautifulSoup (same for both modes) -----
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.get_text())
    links = [a.get('href') for a in soup.find_all('a', href=True)][:50]
    forms = [
        {"action": f.get('action', ''), "method": f.get('method', 'get')}
        for f in soup.find_all('form')
    ]
    tech_hints = [
        meta.get('content') for meta in soup.find_all('meta')
        if meta.get('name') and meta.get('content')
    ][:10]

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
    return {
        "tool": "scrape",
        "target": target,
        "output": output,
        "parsed": parsed,
        "error": None,
        "rc": 0,
    }


# ---------- Tool Registry ----------
TOOL_REGISTRY: Dict[str, Dict] = {
    "nmap":           {"fn": run_nmap,           "desc": "Full nmap -sV -sC scan",                "tags": ["recon", "network"]},
    "nmap_quick":     {"fn": run_nmap_quick,     "desc": "Fast top-1000 port scan",               "tags": ["recon", "network", "fast"]},
    "nikto":          {"fn": run_nikto,          "desc": "Web vulnerability scanner",             "tags": ["web", "vuln"]},
    "whois":          {"fn": run_whois,          "desc": "WHOIS domain/IP lookup",                "tags": ["recon", "osint"]},
    "dig":            {"fn": run_dig,            "desc": "DNS record lookup",                     "tags": ["recon", "dns"]},
    "http_probe":     {"fn": run_http_probe,     "desc": "HTTP header grab + status",             "tags": ["web", "recon"]},
    "whatweb":        {"fn": run_whatweb,        "desc": "Web technology fingerprint",            "tags": ["web", "recon"]},
    "gobuster":       {"fn": run_gobuster_dirs,  "desc": "Web directory brute-force",             "tags": ["web", "bruteforce"]},
    "subfinder":      {"fn": run_subfinder,      "desc": "Passive subdomain enumeration",         "tags": ["recon", "dns", "osint"]},
    "theharvester":   {"fn": run_theharvester,   "desc": "Email/domain OSINT harvester",          "tags": ["osint", "recon"]},
    "enum4linux":     {"fn": run_enum4linux,     "desc": "SMB/NetBIOS enumeration",               "tags": ["network", "smb"]},
    "searchsploit":   {"fn": run_searchsploit,   "desc": "Search exploit-db for known exploits",  "tags": ["exploit", "cve"]},
    "ssl_check":      {"fn": run_ssl_check,      "desc": "TLS/SSL certificate audit",             "tags": ["web", "crypto"]},
    "banner_grab":    {"fn": run_banner_grab,    "desc": "TCP banner grab",                       "tags": ["recon", "network"]},
    "ffuf":           {"fn": run_ffuf,           "desc": "Fast web fuzzer",                       "tags": ["web", "bruteforce"]},
    "wpscan":         {"fn": run_wpscan,         "desc": "WordPress vulnerability scanner",       "tags": ["web", "cms"]},
    "sqlmap_detect":  {"fn": run_sqlmap_detect,  "desc": "SQL injection detection (safe)",        "tags": ["web", "sqli"]},
    "scrape":         {"fn": run_scrape,         "desc": "Web scraping (emails, links, forms)",    "tags": ["web", "recon", "osint"]},
}


def run_tool(name: str, **kwargs) -> Dict[str, Any]:
    entry = TOOL_REGISTRY.get(name)
    if not entry:
        return {"tool": name, "output": "", "parsed": {}, "error": f"Unknown tool: {name}", "rc": -1}
    try:
        return entry["fn"](**kwargs)
    except TypeError as e:
        return {"tool": name, "output": "", "parsed": {}, "error": f"Bad arguments: {e}", "rc": -1}


def list_tools() -> List[Dict]:
    return [{"name": k, "desc": v["desc"], "tags": v["tags"]} for k, v in TOOL_REGISTRY.items()]
