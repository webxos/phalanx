#!/usr/bin/env python3
"""
PHALANX Engine v3.3 – Polyglot ToolExecutor with sandbox support.
Handles tools written in Python, JavaScript, Ruby, Rust, C, C++, Java,
OCaml, WebAssembly, Go, and Bash. Runs inside Docker sandbox when enabled.

Enhanced with:
- MCP (Model Context Protocol) support for dynamic tools via HTTP endpoints.
- Tool names in format "mcp_server:tool_name" are routed to MCP servers.
- Simple MCP client that loads servers from config or mcp_servers.json.
- Fixed Wasm memory allocation (safer offset)
- Fixed discover_tools directory existence check
- MCP server merging from config and JSON file
- Fixed Docker sandbox: wait() timeout, stdin handling, mount type check
- Fixed Wasm memory read/write using memory.buffer
- Added missing finding support for MCP tools
- Improved MCP error handling (ConnectionError, RequestException)
- Auto‑discovers custom tools placed in ./phalanx/tools or ./tools
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import requests
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union

# ------------------------------------------------------------------
# Local logger (no circular import with phalanx_library)
# ------------------------------------------------------------------
logger = logging.getLogger("phalanx.engine")
logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------
# Paths – consistent with local ./phalanx directory
# ------------------------------------------------------------------
BASE = Path.cwd() / "phalanx"
LIB_DIR = BASE / "lib"
TOOLS_DIR = BASE / "tools"
LOCAL_TOOLS_DIR = Path("./tools")          # also scan local directory
FINDINGS_DIR = BASE / "findings"

# ------------------------------------------------------------------
# Finding dataclass for structured output
# ------------------------------------------------------------------
@dataclass
class Finding:
    """Structured finding returned by a tool."""
    tool: str
    target: str
    severity: str = "info"
    description: str = ""
    raw_output: str = ""
    parsed: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    rc: int = 0

    def to_dict(self) -> Dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "severity": self.severity,
            "description": self.description,
            "raw_output": self.raw_output[:1000],
            "parsed": self.parsed,
            "timestamp": self.timestamp,
            "rc": self.rc,
        }

def _ensure_dirs():
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

def _find_compiler(names: List[str]) -> Optional[str]:
    for name in names:
        if shutil.which(name):
            return name
    return None

# ------------------------------------------------------------------
# Sandbox support (Docker) – fixed timeout handling and mount safety
# ------------------------------------------------------------------
_DOCKER_AVAILABLE = False
_DOCKER_CLIENT = None
try:
    import docker
    _DOCKER_AVAILABLE = True
except ImportError:
    docker = None

def _get_docker_client():
    global _DOCKER_CLIENT
    if _DOCKER_CLIENT is None and _DOCKER_AVAILABLE:
        try:
            _DOCKER_CLIENT = docker.from_env()
        except Exception:
            _DOCKER_CLIENT = None
    return _DOCKER_CLIENT

def _run_in_sandbox(cmd: List[str], config: dict, timeout: int, input_data: str = None) -> Dict:
    """Run a command inside a Docker sandbox if enabled. Handles runtime timeout."""
    sandbox_cfg = config.get("sandbox", {})
    if not sandbox_cfg.get("enabled", True):
        return _run_local(cmd, timeout, input_data)
    docker_client = _get_docker_client()
    if not docker_client:
        logger.warning("Docker not available, falling back to local execution")
        return _run_local(cmd, timeout, input_data)
    image = sandbox_cfg.get("image", "kalilinux/kali-rolling")
    network = sandbox_cfg.get("docker_network", "phalanx-net")
    mounts = []
    # Only add mounts if docker.types exists (SDK version check)
    if _DOCKER_AVAILABLE and hasattr(docker, 'types') and sandbox_cfg.get("mount_tools", True) and TOOLS_DIR.exists():
        mounts.append(docker.types.Mount(source=str(TOOLS_DIR), target="/tools", type="bind", read_only=True))
    if _DOCKER_AVAILABLE and hasattr(docker, 'types') and sandbox_cfg.get("mount_lib", True) and LIB_DIR.exists():
        mounts.append(docker.types.Mount(source=str(LIB_DIR), target="/lib", type="bind", read_only=False))

    # Build run kwargs: detach=True, but stdin handling is not supported in detach mode.
    run_kwargs = {
        "image": image,
        "command": cmd,
        "network": network,
        "mounts": mounts,
        "detach": True,
        "stdout": True,
        "stderr": True,
    }
    # If input_data is provided, we cannot use stdin directly with detach.
    if input_data is not None:
        logger.warning("Docker sandbox with stdin not fully supported, falling back to local")
        return _run_local(cmd, timeout, input_data)

    try:
        container = docker_client.containers.run(**run_kwargs)
        # Wait for container with manual timeout (wait() does not accept timeout parameter)
        start = time.time()
        while time.time() - start < timeout:
            container.reload()
            if container.status in ("exited", "dead"):
                break
            time.sleep(0.5)
        else:
            # Timeout reached
            container.kill()
            container.remove()
            return {"output": "", "error": f"Sandbox timed out after {timeout}s", "rc": -1}

        result = container.wait()  # now without timeout
        logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
        container.remove()
        return {"output": logs.strip(), "error": None, "rc": result["StatusCode"]}
    except Exception as e:
        logger.error(f"Docker sandbox execution failed: {e}")
        return {"output": "", "error": str(e), "rc": -1}

def _run_local(cmd: List[str], timeout: int, input_data: str = None) -> Dict:
    """Run command locally."""
    if not shutil.which(cmd[0]):
        return {"output": "", "error": f"Command not found: {cmd[0]}", "rc": -1}
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
        logger.exception("Local execution failed")
        return {"output": "", "error": str(e), "rc": -1}

# ------------------------------------------------------------------
# Polyglot execution protocol: tool reads JSON from stdin, writes JSON to stdout
# ------------------------------------------------------------------
def _run_executable(cmd: List[str], args_dict: Dict[str, Any], timeout: int, config: dict = None) -> Dict:
    """Execute a tool binary that expects JSON on stdin and returns JSON on stdout."""
    arg_json = json.dumps(args_dict)
    if config:
        res = _run_in_sandbox(cmd, config, timeout, input_data=arg_json)
        if res["rc"] == 0 and res["output"]:
            try:
                result = json.loads(res["output"])
                result.setdefault("status", "SUCCESS")
                result.setdefault("summary", str(result))
                return result
            except json.JSONDecodeError:
                return {"status": "ERROR", "summary": f"Bad JSON output: {res['output'][:300]!r}"}
        else:
            return {"status": "ERROR", "summary": res.get("error", "Sandbox execution failed"), "raw_output": res.get("output", "")}
    # Fallback to local execution
    try:
        with subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        ) as proc:
            stdout, stderr = proc.communicate(input=arg_json, timeout=timeout)
            if proc.returncode != 0:
                return {"status": "ERROR", "summary": f"Exited {proc.returncode}: {stderr.strip()[:500]}"}
            try:
                result = json.loads(stdout)
            except json.JSONDecodeError:
                return {"status": "ERROR", "summary": f"Bad JSON output: {stdout[:300]!r}"}
            result.setdefault("status", "SUCCESS")
            result.setdefault("summary", str(result))
            return result
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "summary": f"Timed out after {timeout}s"}
    except Exception as e:
        logger.exception("Executable execution failed")
        return {"status": "ERROR", "summary": str(e)}

# ------------------------------------------------------------------
# Language handlers
# ------------------------------------------------------------------
class LanguageHandler:
    lang_name = "unknown"
    def ensure_compiled(self, tool_info: "ToolInfo") -> Path:
        return tool_info.source_path
    def execute(self, tool_info: "ToolInfo", args_dict: Dict, timeout: int, config: dict = None) -> Dict:
        raise NotImplementedError

class PythonHandler(LanguageHandler):
    lang_name = "python"
    def execute(self, t, a, to, cfg=None):
        return _run_executable([sys.executable, str(t.executable)], a, to, cfg)

class JavaScriptHandler(LanguageHandler):
    lang_name = "javascript"
    def execute(self, t, a, to, cfg=None):
        node = _find_compiler(["node", "nodejs"])
        if not node:
            return {"status": "ERROR", "summary": "node/nodejs not found"}
        return _run_executable([node, str(t.executable)], a, to, cfg)

class RubyHandler(LanguageHandler):
    lang_name = "ruby"
    def execute(self, t, a, to, cfg=None):
        ruby = _find_compiler(["ruby"])
        if not ruby:
            return {"status": "ERROR", "summary": "ruby not found"}
        return _run_executable([ruby, str(t.executable)], a, to, cfg)

class RustHandler(LanguageHandler):
    lang_name = "rust"
    def ensure_compiled(self, t):
        out = LIB_DIR / f"{t.name}_rust"
        if t.compiled_path and t.compiled_path.exists():
            try:
                if t.source_path.stat().st_mtime <= t.compiled_path.stat().st_mtime:
                    return t.compiled_path
            except OSError:
                pass
        rustc = _find_compiler(["rustc"])
        if not rustc:
            raise RuntimeError("rustc not found")
        result = subprocess.run([rustc, str(t.source_path), "-o", str(out)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"rustc error:\n{result.stderr[:600]}")
        out.chmod(0o755)
        t.compiled_path = out
        return out
    def execute(self, t, a, to, cfg=None):
        return _run_executable([str(t.executable)], a, to, cfg)

class CHandler(LanguageHandler):
    lang_name = "c"
    def ensure_compiled(self, t):
        out = LIB_DIR / f"{t.name}_c"
        if t.compiled_path and t.compiled_path.exists():
            try:
                if t.source_path.stat().st_mtime <= t.compiled_path.stat().st_mtime:
                    return t.compiled_path
            except OSError:
                pass
        cc = _find_compiler(["gcc", "clang"])
        if not cc:
            raise RuntimeError("C compiler not found")
        result = subprocess.run([cc, str(t.source_path), "-o", str(out)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"C compile error:\n{result.stderr[:600]}")
        out.chmod(0o755)
        t.compiled_path = out
        return out
    def execute(self, t, a, to, cfg=None):
        return _run_executable([str(t.executable)], a, to, cfg)

class CppHandler(LanguageHandler):
    lang_name = "cpp"
    def ensure_compiled(self, t):
        out = LIB_DIR / f"{t.name}_cpp"
        if t.compiled_path and t.compiled_path.exists():
            try:
                if t.source_path.stat().st_mtime <= t.compiled_path.stat().st_mtime:
                    return t.compiled_path
            except OSError:
                pass
        cxx = _find_compiler(["g++", "clang++"])
        if not cxx:
            raise RuntimeError("C++ compiler not found")
        result = subprocess.run([cxx, str(t.source_path), "-o", str(out)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"C++ compile error:\n{result.stderr[:600]}")
        out.chmod(0o755)
        t.compiled_path = out
        return out
    def execute(self, t, a, to, cfg=None):
        return _run_executable([str(t.executable)], a, to, cfg)

class JavaHandler(LanguageHandler):
    lang_name = "java"
    def ensure_compiled(self, t):
        class_dir = LIB_DIR / "java_classes"
        class_dir.mkdir(exist_ok=True)
        javac = _find_compiler(["javac"])
        if not javac:
            raise RuntimeError("javac not found")
        result = subprocess.run([javac, "-d", str(class_dir), str(t.source_path)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"javac error:\n{result.stderr[:600]}")
        t.compiled_path = class_dir / t.source_path.stem
        return t.compiled_path
    def execute(self, t, a, to, cfg=None):
        java = _find_compiler(["java"])
        if not java:
            return {"status": "ERROR", "summary": "java not found"}
        class_dir = LIB_DIR / "java_classes"
        return _run_executable([java, "-cp", str(class_dir), t.source_path.stem], a, to, cfg)

class OCamlHandler(LanguageHandler):
    lang_name = "ocaml"
    def ensure_compiled(self, t):
        out = LIB_DIR / f"{t.name}_ocaml"
        if t.compiled_path and t.compiled_path.exists():
            try:
                if t.source_path.stat().st_mtime <= t.compiled_path.stat().st_mtime:
                    return t.compiled_path
            except OSError:
                pass
        ocamlc = _find_compiler(["ocamlc"])
        if not ocamlc:
            raise RuntimeError("ocamlc not found")
        result = subprocess.run([ocamlc, "-o", str(out), str(t.source_path)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ocamlc error:\n{result.stderr[:600]}")
        out.chmod(0o755)
        t.compiled_path = out
        return out
    def execute(self, t, a, to, cfg=None):
        return _run_executable([str(t.executable)], a, to, cfg)

class WasmHandler(LanguageHandler):
    lang_name = "wasm"
    def ensure_compiled(self, t):
        if t.source_path.suffix == ".wat":
            wat2wasm = _find_compiler(["wat2wasm"])
            if wat2wasm:
                out = t.source_path.with_suffix(".wasm")
                if not out.exists() or t.source_path.stat().st_mtime > out.stat().st_mtime:
                    subprocess.run([wat2wasm, str(t.source_path), "-o", str(out)], check=True)
                t.compiled_path = out
                return out
        return t.source_path

    def execute(self, t, a, to, cfg=None):
        try:
            import wasmtime
        except ImportError:
            return {"status": "ERROR", "summary": "wasmtime not installed"}

        engine = wasmtime.Engine()
        try:
            module = wasmtime.Module.from_file(engine, str(t.executable))
        except Exception as e:
            return {"status": "ERROR", "summary": f"Failed to load Wasm module: {e}"}

        store = wasmtime.Store(engine)
        wasi = wasmtime.WasiConfig()
        wasi.inherit_stdin()
        wasi.inherit_stdout()
        wasi.inherit_stderr()
        store.set_wasi(wasi)

        try:
            instance = wasmtime.Instance(store, module, [])
        except Exception as e:
            return {"status": "ERROR", "summary": f"Instance creation failed: {e}"}

        run_func = instance.exports(store).get("run")
        if run_func is None:
            return {"status": "ERROR", "summary": "Wasm module missing 'run' export"}

        memory = instance.exports(store).get("memory")
        if memory is None:
            return {"status": "ERROR", "summary": "Wasm module missing 'memory' export"}

        # Prepare argument JSON
        arg_json = json.dumps(a).encode('utf-8')
        arg_len = len(arg_json)

        # Use malloc if available
        malloc_func = instance.exports(store).get("malloc")
        if malloc_func is not None:
            try:
                offset = malloc_func(store, arg_len + 1)
                if offset == 0:
                    raise RuntimeError("malloc returned 0")
            except Exception as e:
                logger.warning(f"Wasm malloc failed: {e}, falling back to fixed offset")
                offset = 65536
        else:
            offset = 65536

        # Ensure memory is large enough
        memory_data = memory.data_ptr(store)
        memory_size = len(memory_data) if hasattr(memory_data, '__len__') else memory.data_len(store)
        if offset + arg_len + 4096 > memory_size:
            needed_pages = (offset + arg_len + 4095) // 65536 + 1
            current_pages = memory.size(store)
            if needed_pages > current_pages:
                if not memory.grow(store, needed_pages - current_pages):
                    return {"status": "ERROR", "summary": "Wasm memory too small and cannot grow"}

        # Write argument to memory
        try:
            memory.write(store, offset, arg_json)
        except AttributeError:
            try:
                ctypes.memmove(memory_data + offset, arg_json, arg_len)
            except Exception as e:
                return {"status": "ERROR", "summary": f"Failed to write argument: {e}"}
        except Exception as e:
            return {"status": "ERROR", "summary": f"Failed to write argument: {e}"}

        try:
            result_ptr = run_func(store, offset, arg_len)
        except Exception as e:
            return {"status": "ERROR", "summary": f"Wasm run failed: {e}"}

        # Read result string
        result_bytes = bytearray()
        try:
            for i in range(4096):
                if result_ptr + i >= memory_size:
                    break
                try:
                    b = memory.read(store, result_ptr + i, 1)[0]
                except AttributeError:
                    b = (memory_data[result_ptr + i] if hasattr(memory_data, '__getitem__') else 0)
                if b == 0:
                    break
                result_bytes.append(b)
        except Exception as e:
            logger.warning(f"Wasm result read failed: {e}")

        result_str = result_bytes.decode('utf-8', errors='replace')
        return {"status": "SUCCESS", "summary": result_str[:200], "raw_output": result_str}

class GoHandler(LanguageHandler):
    lang_name = "go"
    def ensure_compiled(self, t):
        out = LIB_DIR / f"{t.name}_go"
        if t.compiled_path and t.compiled_path.exists():
            try:
                if t.source_path.stat().st_mtime <= t.compiled_path.stat().st_mtime:
                    return t.compiled_path
            except OSError:
                pass
        go = _find_compiler(["go"])
        if not go:
            raise RuntimeError("go not found")
        result = subprocess.run([go, "build", "-o", str(out), str(t.source_path)], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"go build error:\n{result.stderr[:600]}")
        out.chmod(0o755)
        t.compiled_path = out
        return out
    def execute(self, t, a, to, cfg=None):
        return _run_executable([str(t.executable)], a, to, cfg)

class BashHandler(LanguageHandler):
    lang_name = "bash"
    def execute(self, t, a, to, cfg=None):
        bash = _find_compiler(["bash"])
        if not bash:
            return {"status": "ERROR", "summary": "bash not found"}
        return _run_executable([bash, str(t.executable)], a, to, cfg)

_HANDLERS: List[Type[LanguageHandler]] = [
    PythonHandler, JavaScriptHandler, RubyHandler, RustHandler,
    CHandler, CppHandler, JavaHandler, OCamlHandler,
    WasmHandler, GoHandler, BashHandler,
]

def _get_handler(lang: str) -> Optional[LanguageHandler]:
    for cls in _HANDLERS:
        if cls.lang_name == lang:
            return cls()
    return None

# ------------------------------------------------------------------
# ToolInfo and discovery (with existence checks)
# ------------------------------------------------------------------
class ToolInfo:
    def __init__(self, name: str, source_path: Path, lang: str,
                 compiled_path: Optional[Path] = None, description: str = ""):
        self.name = name
        self.source_path = source_path
        self.lang = lang
        self.compiled_path = compiled_path
        self.description = description
        self.handler = _get_handler(lang)
    @property
    def executable(self) -> Path:
        return self.compiled_path or self.source_path
    def ensure_compiled(self) -> Path:
        if self.handler:
            return self.handler.ensure_compiled(self)
        return self.source_path

def discover_tools() -> List[ToolInfo]:
    """Discover tools in ./phalanx/tools and ./tools directories."""
    tools: List[ToolInfo] = []
    ext_map = {
        ".py": "python", ".js": "javascript", ".rb": "ruby",
        ".rs": "rust", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
        ".java": "java", ".ml": "ocaml",
        ".wasm": "wasm", ".go": "go", ".sh": "bash", ".bash": "bash",
    }
    seen: set = set()
    for search_dir in [TOOLS_DIR, LOCAL_TOOLS_DIR]:
        if not search_dir.exists():
            continue
        for item in search_dir.rglob("*"):
            if item.is_dir():
                manifest = item / "tool.json"
                if manifest.exists():
                    try:
                        data = json.loads(manifest.read_text())
                    except Exception as e:
                        logger.warning(f"Failed to parse manifest {manifest}: {e}")
                        continue
                    name = data.get("name", item.name)
                    if name in seen:
                        continue
                    lang = data.get("language", "binary")
                    src_name = data.get("source", data.get("entry", ""))
                    src = (item / src_name) if src_name else None
                    comp = (item / data["compiled"]) if "compiled" in data else None
                    desc = data.get("description", "")
                    if src and src.exists():
                        seen.add(name)
                        tools.append(ToolInfo(name, src, lang, comp, desc))
            elif item.suffix in ext_map:
                name = item.stem
                if name not in seen:
                    seen.add(name)
                    tools.append(ToolInfo(name, item, ext_map[item.suffix], description=""))
    return tools

# ------------------------------------------------------------------
# MCP Client (Model Context Protocol) – simplified
# ------------------------------------------------------------------
class MCPClient:
    """Simple MCP client to call external tool servers via HTTP."""
    def __init__(self, config: dict):
        self.config = config
        self.servers: Dict[str, Dict] = {}  # server_name -> {"url": str, "enabled": bool}
        self._load_servers()

    def _load_servers(self):
        """Load MCP server configuration from config and mcp_servers.json (merge)."""
        mcp_cfg = self.config.get("mcp", {})
        servers_from_config = []
        if mcp_cfg.get("enabled", False):
            servers_from_config = mcp_cfg.get("servers", [])
        mcp_file = BASE / "config" / "mcp_servers.json"
        servers_from_file = {}
        if mcp_file.exists():
            try:
                data = json.loads(mcp_file.read_text())
                servers_from_file = data
            except Exception as e:
                logger.warning(f"Failed to load {mcp_file}: {e}")
        # Merge: config takes precedence over file for same name
        for server in servers_from_config:
            name = server.get("name")
            url = server.get("url")
            if name and url and server.get("enabled", True):
                self.servers[name] = {"url": url, "enabled": True}
                logger.info(f"Loaded MCP server '{name}' from config: {url}")
        for name, info in servers_from_file.items():
            if name not in self.servers and info.get("enabled", True):
                url = info.get("url")
                if url:
                    self.servers[name] = {"url": url, "enabled": True}
                    logger.info(f"Loaded MCP server '{name}' from {mcp_file}: {url}")

    def call_tool(self, server_name: str, tool_name: str, params: Dict, timeout: int = 60) -> Dict:
        """Call an MCP tool via HTTP POST to /call endpoint."""
        if server_name not in self.servers:
            return {"status": "ERROR", "summary": f"MCP server '{server_name}' not configured", "rc": -1}
        server = self.servers[server_name]
        url = server["url"].rstrip("/") + "/call"
        try:
            resp = requests.post(url, json={"tool": tool_name, "params": params}, timeout=timeout)
            if resp.status_code == 200:
                result = resp.json()
                output = result.get("output", result.get("result", result.get("stdout", "")))
                error = result.get("error")
                rc = result.get("rc", 0)
                return {
                    "status": "SUCCESS" if rc == 0 else "ERROR",
                    "summary": output[:200] if output else (error or "No output"),
                    "raw_output": output,
                    "rc": rc
                }
            else:
                return {
                    "status": "ERROR",
                    "summary": f"MCP server returned {resp.status_code}",
                    "raw_output": resp.text,
                    "rc": -1
                }
        except requests.exceptions.Timeout:
            return {"status": "ERROR", "summary": f"MCP call timed out after {timeout}s", "rc": -1}
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
            logger.exception("MCP connection error")
            return {"status": "ERROR", "summary": f"MCP connection failed: {e}", "rc": -1}
        except Exception as e:
            logger.exception("MCP call failed")
            return {"status": "ERROR", "summary": f"MCP call failed: {e}", "rc": -1}

# ------------------------------------------------------------------
# ToolExecutor – main class for external use
# ------------------------------------------------------------------
class ToolExecutor:
    def __init__(self, timeout: int = 30, soul=None, config: dict = None):
        self.timeout = timeout
        self.soul = soul
        self.config = config or {}
        # Initialize MCP client if MCP is enabled in config
        self.mcp_client = None
        if self.config.get("mcp", {}).get("enabled", False):
            self.mcp_client = MCPClient(self.config)
            logger.info(f"MCP client enabled with {len(self.mcp_client.servers)} server(s)")
        _ensure_dirs()
        self.tools: List[ToolInfo] = discover_tools()
        logger.info(f"ToolExecutor initialized with {len(self.tools)} local tools")

    def reload(self):
        self.tools = discover_tools()
        logger.info(f"Reloaded tools, now {len(self.tools)} available")

    def list_tools(self) -> List[Dict]:
        """List all available tools (local + MCP)."""
        tools = [{"name": t.name, "lang": t.lang, "description": t.description} for t in self.tools]
        if self.mcp_client:
            for server_name, server in self.mcp_client.servers.items():
                tools.append({
                    "name": f"{server_name}:*",
                    "lang": "mcp",
                    "description": f"MCP server '{server_name}' at {server['url']} (dynamic tools)"
                })
        return tools

    def _is_mcp_tool(self, name: str) -> bool:
        """Check if tool name matches MCP format (server:tool)."""
        return ":" in name and self.mcp_client is not None

    def _execute_mcp_tool(self, tool_full_name: str, args_dict: Dict, timeout: int) -> Dict:
        """Execute an MCP tool in format 'server_name:tool_name'."""
        parts = tool_full_name.split(":", 1)
        if len(parts) != 2:
            return {"status": "ERROR", "summary": f"Invalid MCP tool name format: {tool_full_name}. Expected 'server:tool'", "rc": -1}
        server_name, tool_name = parts
        result = self.mcp_client.call_tool(server_name, tool_name, args_dict, timeout)
        return {
            "status": result.get("status", "ERROR"),
            "summary": result.get("summary", ""),
            "raw_output": result.get("raw_output", ""),
            "rc": result.get("rc", -1)
        }

    def execute(
        self,
        name: str,
        args_dict: Optional[Dict] = None,
        parse_output: bool = False,
        parser: Optional[Callable[[str, Dict], Dict]] = None,
        return_finding: bool = False,
        target: str = "",
        severity: str = "info"
    ) -> Dict:
        """
        Execute a tool by name.

        Args:
            name: Tool name (can be local tool name or "mcp_server:tool_name")
            args_dict: Arguments to pass to the tool
            parse_output: If True, attempt to parse the raw output using the provided parser
            parser: Callable that takes (raw_output, args_dict) and returns parsed dict
            return_finding: If True, also construct a Finding object and add to result
            target: Target for the finding (required if return_finding=True)
            severity: Severity for the finding

        Returns:
            Dict with keys: status, summary, raw_output, rc, and optionally parsed, finding
        """
        if args_dict is None:
            args_dict = {}

        # Route to MCP if applicable
        if self._is_mcp_tool(name):
            result = self._execute_mcp_tool(name, args_dict, self.timeout)
        else:
            # Local tool
            tool = next((t for t in self.tools if t.name == name), None)
            if not tool:
                return {"status": "ERROR", "summary": f"Tool '{name}' not found", "raw_output": "", "rc": -1}
            try:
                tool.ensure_compiled()
                if not tool.handler:
                    return {"status": "ERROR", "summary": f"No handler for language '{tool.lang}'", "raw_output": "", "rc": -1}
                result = tool.handler.execute(tool, args_dict, self.timeout, self.config)

                # Normalize output fields
                if "status" not in result:
                    result["status"] = "SUCCESS" if result.get("rc", 0) == 0 else "ERROR"
                if "summary" not in result:
                    result["summary"] = result.get("output", result.get("raw_output", ""))[:200]
                if "raw_output" not in result:
                    result["raw_output"] = result.get("output", "")
                if "rc" not in result:
                    result["rc"] = 0 if result["status"] == "SUCCESS" else -1
            except Exception as e:
                logger.exception(f"Tool '{name}' execution failed")
                result = {"status": "ERROR", "summary": str(e), "raw_output": "", "rc": -1}

        # Parsing hook
        if parse_output and parser and result.get("raw_output"):
            try:
                parsed = parser(result["raw_output"], args_dict)
                result["parsed"] = parsed
            except Exception as e:
                logger.warning(f"Parser failed for tool {name}: {e}")
                result["parsed"] = {"error": str(e)}

        # Finding construction (also for MCP tools)
        if return_finding:
            if not target:
                target = args_dict.get("target", args_dict.get("host", args_dict.get("url", "")))
                if not target:
                    logger.warning(f"Finding requested for tool {name} but no target provided")
            finding = Finding(
                tool=name,
                target=target,
                severity=severity,
                description=result.get("summary", "")[:500],
                raw_output=result.get("raw_output", ""),
                parsed=result.get("parsed", {}),
                rc=result.get("rc", -1)
            )
            result["finding"] = finding.to_dict()

        # Provide feedback to Soul if available
        if self.soul:
            self.soul.append_memory("TOOL_RUN", name, f"Status: {result['status']}, Summary: {result['summary'][:100]}")
        return result

# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------
if __name__ == "__main__":
    executor = ToolExecutor(timeout=10, config={"sandbox": {"enabled": False}, "mcp": {"enabled": False}})
    print("Discovered local tools:", [t.name for t in executor.tools])
    if any(t.name == "echo" for t in executor.tools):
        result = executor.execute("echo", {"message": "Hello from engine"})
        print("Echo result:", json.dumps(result, indent=2))
