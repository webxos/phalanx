#!/usr/bin/env python3
"""
PHALANX Engine v3.6 – Polyglot ToolExecutor with sandbox support.
Handles tools written in Python, JavaScript, Ruby, Rust, C, C++, Java,
OCaml, WebAssembly, Go, and Bash. Runs inside Docker sandbox when enabled.

ENHANCEMENTS (v3.6 – Raptor‑inspired):
- ReActToolAgent promoted to isolated generator + judge pair.
  - Generator receives raw source (not summaries) and produces candidate actions.
  - Judge evaluates the generator’s output against the same raw source and a separate context; history is not shared.
- Altitude‑aware context injection: each altitude (whole‑project → file → feature → function) can have its own context window.
- Fixed WinStealthExecutor and OGhidraExecutor to never return None.
- Fixed ToolExecutor.react_loop to handle missing gateway gracefully.
- Fixed OGhidra command construction: now uses a list safely without shell injection.
- Fixed sandbox fallback: respects timeout and input_data even when falling back to local.

REQUIRED DEPENDENCIES FOR INTERACTIVE SESSIONS:
- tmux (recommended) or pexpect (optional) for interactive tool sessions.
  Install: sudo apt install tmux   or   pip install pexpect
- For sandbox: Docker and docker-py (pip install docker)
- For WebAssembly: wasmtime (pip install wasmtime)
- For scraping: beautifulsoup4, lxml, fake-useragent, playwright (optional)
- For OGhidra: Ghidra 11.3+ with OGhidraMCP plugin installed.

NEW (v3.6.2):
- ToolExecutor now handles the "shell" tool directly, using run_shell_command from phalanx_tools.
- ReActToolAgent can invoke shell commands via the gateway, as the "shell" tool is now registered.
"""

import os
import json
import logging
import shutil
import subprocess
import sys
import requests
import tempfile
import time
import threading
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union, Tuple

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

def _ensure_dirs():
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)

_ensure_dirs()

# ------------------------------------------------------------------
# Finding dataclass for structured output (local version)
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

def _find_compiler(names: List[str]) -> Optional[str]:
    for name in names:
        if shutil.which(name):
            return name
    return None

# ------------------------------------------------------------------
# Sandbox support – try to reuse phalanx_tools sandbox if available
# ------------------------------------------------------------------
_SANDBOX_FUNC = None
try:
    from phalanx_tools import _execute_in_sandbox as _sandbox_exec
    _SANDBOX_FUNC = _sandbox_exec
except ImportError:
    _SANDBOX_FUNC = None

def _run_in_sandbox(cmd: List[str], config: dict, timeout: int, input_data: str = None) -> Dict:
    """
    Run a command inside a Docker sandbox if enabled.
    Note: stdin (input_data) is not supported in sandbox mode;
    if input_data is provided, execution falls back to local.
    """
    if _SANDBOX_FUNC:
        try:
            # Try keyword arguments first (preferred)
            return _SANDBOX_FUNC(cmd, timeout=timeout, input_data=input_data, config=config)
        except TypeError:
            # Fallback to positional arguments (legacy signature)
            return _SANDBOX_FUNC(cmd, timeout, input_data, config)

    # Fallback local execution – ensure timeout and input_data are respected
    try:
        result = subprocess.run(cmd, input=input_data, capture_output=True, text=True, timeout=timeout)
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
# InteractiveSession – full tmux + pexpect support (safe imports)
# ------------------------------------------------------------------
_TMUX_AVAILABLE = shutil.which("tmux") is not None
_PEXPECT_AVAILABLE = False
try:
    import pexpect
    _PEXPECT_AVAILABLE = True
except ImportError:
    pexpect = None
    # pexpect not installed – will fall back to subprocess

class InteractiveSession:
    """
    Manage an interactive session (e.g., shell, debugger, exploit console).
    Uses tmux if available, otherwise pexpect.
    """

    def __init__(self, command: str, name: Optional[str] = None, timeout: int = 60):
        self.command = command
        self.timeout = timeout
        self.name = name or f"phalanx_{int(time.time())}"
        self._tmux = _TMUX_AVAILABLE
        self._pexpect = _PEXPECT_AVAILABLE and not self._tmux
        self._proc = None
        self._output_buffer = ""
        self._lock = threading.RLock()

        # Warn if neither tmux nor pexpect is available
        if not _TMUX_AVAILABLE and not _PEXPECT_AVAILABLE:
            logger.warning(
                "Neither tmux nor pexpect is installed. "
                "Interactive sessions will fall back to subprocess (non-interactive). "
                "Install tmux (sudo apt install tmux) or pexpect (pip install pexpect)."
            )

    def start(self) -> bool:
        with self._lock:
            if self.is_running():
                return True
            if self._tmux:
                try:
                    subprocess.run(
                        ["tmux", "new-session", "-d", "-s", self.name, self.command],
                        check=True, capture_output=True
                    )
                    return True
                except subprocess.CalledProcessError as e:
                    logger.error(f"tmux session start failed: {e}")
                    return False
            elif self._pexpect:
                try:
                    self._proc = pexpect.spawn(self.command, timeout=self.timeout)
                    return True
                except Exception as e:
                    logger.error(f"pexpect spawn failed: {e}")
                    return False
            else:
                logger.error("No interactive backend (tmux or pexpect) available")
                return False

    def send(self, data: str, expect_prompt: Optional[str] = None, timeout: Optional[int] = None) -> str:
        timeout = timeout or self.timeout
        with self._lock:
            if not self.is_running():
                raise RuntimeError(f"Session {self.name} not running")
            if self._tmux:
                subprocess.run(["tmux", "send-keys", "-t", self.name, data], check=True)
                subprocess.run(["tmux", "send-keys", "-t", self.name, "Enter"], check=True)
                if expect_prompt:
                    start = time.time()
                    while time.time() - start < timeout:
                        output = self.recv()
                        if re.search(expect_prompt, output):
                            return output
                        time.sleep(0.2)
                    raise TimeoutError(f"Prompt '{expect_prompt}' not seen within {timeout}s")
                return ""
            elif self._pexpect and self._proc:
                self._proc.sendline(data)
                if expect_prompt:
                    try:
                        self._proc.expect(expect_prompt, timeout=timeout)
                        return self._proc.before.decode('utf-8', errors='ignore')
                    except pexpect.TIMEOUT:
                        raise TimeoutError(f"Prompt '{expect_prompt}' not seen within {timeout}s")
                return ""
            return ""

    def recv(self) -> str:
        with self._lock:
            if self._tmux:
                result = subprocess.run(
                    ["tmux", "capture-pane", "-t", self.name, "-p"],
                    capture_output=True, text=True
                )
                return result.stdout
            elif self._pexpect and self._proc:
                try:
                    idx = self._proc.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=0.1)
                    if idx == 0:
                        return self._proc.before.decode('utf-8', errors='ignore')
                    else:
                        return self._proc.before.decode('utf-8', errors='ignore') + (self._proc.after.decode() if self._proc.after else "")
                except Exception:
                    return ""
            return ""

    def close(self) -> None:
        with self._lock:
            if self._tmux:
                subprocess.run(["tmux", "kill-session", "-t", self.name], capture_output=True)
            elif self._pexpect and self._proc:
                self._proc.terminate(force=True)
                self._proc = None

    def is_running(self) -> bool:
        if self._tmux:
            result = subprocess.run(["tmux", "has-session", "-t", self.name], capture_output=True)
            return result.returncode == 0
        elif self._pexpect and self._proc:
            return self._proc.isalive()
        return False

    def get_output(self) -> str:
        return self.recv()

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
                return {"status": "ERROR", "summary": f"Bad JSON output: {res['output'][:300]!r}", "raw_output": res["output"]}
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
# Language handlers (complete)
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
        class_dir = LIB_DIR / f"java_classes_{t.name}"
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
        class_dir = LIB_DIR / f"java_classes_{t.name}"
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
        # Safe import of wasmtime
        try:
            import wasmtime
        except ImportError:
            return {"status": "ERROR", "summary": "wasmtime not installed (pip install wasmtime)"}

        try:
            engine = wasmtime.Engine()
            module = wasmtime.Module.from_file(engine, str(t.executable))
        except Exception as e:
            return {"status": "ERROR", "summary": f"Failed to load Wasm module: {e}"}

        # Create temporary files to capture stdout/stderr
        stdout_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".stdout")
        stderr_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".stderr")

        store = wasmtime.Store(engine)
        wasi = wasmtime.WasiConfig()
        wasi.inherit_stdin()
        wasi.set_stdout_file(stdout_file.name)
        wasi.set_stderr_file(stderr_file.name)
        store.set_wasi(wasi)

        try:
            instance = wasmtime.Instance(store, module, [])
        except Exception as e:
            stdout_file.close()
            stderr_file.close()
            return {"status": "ERROR", "summary": f"Instance creation failed: {e}"}

        # Look for '_start' or 'run' export
        start_func = None
        for export_name in ["_start", "run"]:
            func = instance.exports(store).get(export_name)
            if func is not None:
                start_func = func
                break
        if start_func is None:
            stdout_file.close()
            stderr_file.close()
            return {"status": "ERROR", "summary": "Wasm module missing '_start' or 'run' export"}

        try:
            start_func(store)
        except Exception as e:
            stdout_file.close()
            stderr_file.close()
            return {"status": "ERROR", "summary": f"Wasm execution failed: {e}"}

        # Read captured output
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout_data = stdout_file.read()
        stderr_data = stderr_file.read()
        stdout_file.close()
        stderr_file.close()

        raw_output = stdout_data + stderr_data
        return {
            "status": "SUCCESS",
            "summary": "Wasm execution completed",
            "raw_output": raw_output.strip()
        }

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
        go_bin = _find_compiler(["go"])
        if not go_bin:
            raise RuntimeError("go not found")
        result = subprocess.run([go_bin, "build", "-o", str(out), str(t.source_path)], capture_output=True, text=True)
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

# Additional placeholders for languages that may be added in the future
class SwiftHandler(LanguageHandler):
    lang_name = "swift"
    def ensure_compiled(self, t):
        # Placeholder: swiftc not typically used for tool execution in PHALANX
        return t.source_path
    def execute(self, t, a, to, cfg=None):
        swift = _find_compiler(["swift"])
        if not swift:
            return {"status": "ERROR", "summary": "swift not found"}
        return _run_executable([swift, str(t.executable)], a, to, cfg)

class ZigHandler(LanguageHandler):
    lang_name = "zig"
    def ensure_compiled(self, t):
        out = LIB_DIR / f"{t.name}_zig"
        if t.compiled_path and t.compiled_path.exists():
            try:
                if t.source_path.stat().st_mtime <= t.compiled_path.stat().st_mtime:
                    return t.compiled_path
            except OSError:
                pass
        zig = _find_compiler(["zig"])
        if not zig:
            raise RuntimeError("zig not found")
        result = subprocess.run([zig, "build-exe", str(t.source_path), "--name", out.stem, "--cache", "none"], capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"zig build error:\n{result.stderr[:600]}")
        out.chmod(0o755)
        t.compiled_path = out
        return out
    def execute(self, t, a, to, cfg=None):
        return _run_executable([str(t.executable)], a, to, cfg)

_HANDLERS: List[Type[LanguageHandler]] = [
    PythonHandler, JavaScriptHandler, RubyHandler, RustHandler,
    CHandler, CppHandler, JavaHandler, OCamlHandler,
    WasmHandler, GoHandler, BashHandler,
    SwiftHandler, ZigHandler,  # additional
]

def _get_handler(lang: str) -> Optional[LanguageHandler]:
    for cls in _HANDLERS:
        if cls.lang_name == lang:
            return cls()
    return None

# ------------------------------------------------------------------
# ToolInfo and discovery (with manifest validation)
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
        if self.handler is None:
            raise RuntimeError(f"No language handler for '{self.lang}'")
        return self.handler.ensure_compiled(self)

    def __str__(self):
        return f"ToolInfo(name={self.name}, lang={self.lang}, src={self.source_path})"

def discover_tools() -> List[ToolInfo]:
    """
    Discover tools in ./phalanx/tools and ./tools directories.
    Scans for:
      1) Any file with a known extension (.py, .js, .rb, etc.) - treated as standalone tool.
      2) Subdirectories containing a tool.json manifest.
    Returns a list of ToolInfo objects.
    """
    tools: List[ToolInfo] = []
    ext_map = {
        ".py": "python", ".js": "javascript", ".rb": "ruby",
        ".rs": "rust", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
        ".java": "java", ".ml": "ocaml",
        ".wasm": "wasm", ".go": "go", ".sh": "bash", ".bash": "bash",
        ".swift": "swift", ".zig": "zig",
    }
    seen = set()

    for search_dir in [TOOLS_DIR, LOCAL_TOOLS_DIR]:
        if not search_dir.exists():
            logger.debug(f"Tools directory does not exist: {search_dir}")
            continue
        # Walk the directory tree
        for root, dirs, files in os.walk(search_dir):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            # Check for tool.json in current directory
            manifest_path = Path(root) / "tool.json"
            if manifest_path.exists():
                try:
                    data = json.loads(manifest_path.read_text())
                    name = data.get("name", Path(root).name)
                    if name in seen:
                        continue
                    lang = data.get("language")
                    if not lang:
                        logger.warning(f"Manifest {manifest_path} missing 'language' field, skipping")
                        continue
                    src_name = data.get("source", data.get("entry", ""))
                    if not src_name:
                        logger.warning(f"Manifest {manifest_path} missing source/entry, skipping")
                        continue
                    src = Path(root) / src_name
                    comp = Path(root) / data["compiled"] if "compiled" in data else None
                    desc = data.get("description", "")
                    if src.exists():
                        seen.add(name)
                        tools.append(ToolInfo(name, src, lang, comp, desc))
                    else:
                        logger.warning(f"Manifest source file missing: {src}")
                except Exception as e:
                    logger.warning(f"Failed to parse manifest {manifest_path}: {e}")
            else:
                # No manifest – scan for standalone files with known extensions
                for file in Path(root).iterdir():
                    if file.is_file() and file.suffix in ext_map:
                        name = file.stem
                        if name in seen:
                            continue
                        lang = ext_map[file.suffix]
                        # Only add if not already added via manifest
                        seen.add(name)
                        tools.append(ToolInfo(name, file, lang, description=""))
    logger.info(f"Discovered {len(tools)} tools: {[t.name for t in tools]}")
    return tools

# ------------------------------------------------------------------
# Parser registry – complete mapping
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
    if "parsed" in args:
        parsed = args["parsed"]
        emails = parsed.get("emails", [])
        links_count = parsed.get("links_count", 0)
        forms = parsed.get("forms", [])
    else:
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_output)
        links_count = len(re.findall(r'href=[\'"]?([^\'" >]+)', raw_output))
        forms = re.findall(r'<form.*?>', raw_output)
    return {
        "findings": [{"email": e} for e in emails[:10]],
        "evidence": emails[:5],
        "next_hints": ["Look for login forms", "Check for XSS"],
        "confidence": 0.9 if emails else 0.5,
        "emails": emails,
        "links_count": links_count,
        "forms": forms
    }

# Registry mapping tool name -> parser function
PARSER_REGISTRY = {
    "nmap": parse_nmap_output,
    "nuclei": parse_nuclei_output,
    "sqlmap": parse_sqlmap_output,
    "subfinder": parse_subfinder_output,
    "httpx": parse_httpx_output,
    "naabu": parse_naabu_output,
    "ghidra": parse_ghidra_output,
    "scrape": parse_scrape_output,
}

# ------------------------------------------------------------------
# MCP Client (Model Context Protocol) – with retry logic
# ------------------------------------------------------------------
class MCPClient:
    """Simple MCP client to call external tool servers via HTTP."""
    def __init__(self, config: dict):
        self.config = config
        self.servers: Dict[str, Dict] = {}
        self._load_servers()

    def _load_servers(self):
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

    def call_tool(self, server_name: str, tool_name: str, params: Dict, timeout: int = 60, retries: int = 2) -> Dict:
        """
        Call an MCP tool with retry logic.
        Retries up to `retries` times on failure (except 4xx client errors).
        """
        if server_name not in self.servers:
            return {"status": "ERROR", "summary": f"MCP server '{server_name}' not configured", "rc": -1}
        server = self.servers[server_name]
        url = server["url"].rstrip("/") + "/call"

        last_exception = None
        for attempt in range(retries + 1):
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
                elif 400 <= resp.status_code < 500:
                    # Client error – do not retry
                    return {
                        "status": "ERROR",
                        "summary": f"MCP client error {resp.status_code}: {resp.text[:200]}",
                        "raw_output": resp.text,
                        "rc": -1
                    }
                else:
                    # Server error – retry if attempts left
                    if attempt < retries:
                        wait = (attempt + 1) * 0.5  # 0.5, 1.0 seconds
                        logger.warning(f"MCP server returned {resp.status_code}, retrying in {wait}s...")
                        time.sleep(wait)
                        continue
                    return {
                        "status": "ERROR",
                        "summary": f"MCP server returned {resp.status_code} after {retries} retries",
                        "raw_output": resp.text,
                        "rc": -1
                    }
            except requests.exceptions.Timeout:
                last_exception = TimeoutError(f"Timeout after {timeout}s")
                if attempt < retries:
                    wait = (attempt + 1) * 0.5
                    logger.warning(f"MCP call timeout, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    return {"status": "ERROR", "summary": str(last_exception), "rc": -1}
            except Exception as e:
                last_exception = e
                if attempt < retries:
                    wait = (attempt + 1) * 0.5
                    logger.warning(f"MCP call failed: {e}, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    logger.exception("MCP call failed after retries")
                    return {"status": "ERROR", "summary": f"MCP call failed: {e}", "rc": -1}

        return {"status": "ERROR", "summary": "MCP call failed after retries", "rc": -1}

# ------------------------------------------------------------------
# WinStealthExecutor – Windows reflective PE loading via WinStealth (renamed from SindriExecutor)
# ------------------------------------------------------------------
class WinStealthExecutor:
    """Executor for WinStealth-based Windows low-level evasion techniques."""
    def __init__(self, config: dict):
        # Guard against None config
        self.config = config or {}
        self.wrapper = None
        self.enabled = False
        # Check both old and new config keys for backward compatibility
        winstealth_cfg = self.config.get("winstealth", {})
        sindri_cfg = self.config.get("sindri", {})
        enabled = winstealth_cfg.get("enabled", False) or sindri_cfg.get("enabled", False)
        if enabled:
            try:
                from phalanx_winstealth import WinStealthWrapper
                self.wrapper = WinStealthWrapper()
                self.enabled = True
                logger.info("WinStealthExecutor initialized and enabled.")
            except ImportError as e:
                logger.warning(f"WinStealth not available: {e}")
            except Exception as e:
                logger.warning(f"Failed to initialize WinStealthExecutor: {e}")

    def execute_pe(self, pe_path: Union[str, Path], profile: str = "Win32") -> Dict:
        """
        Reflectively load a PE file using WinStealth.

        Args:
            pe_path: Path to the PE file.
            profile: Execution profile (e.g., "Win32", "Native", "Custom").

        Returns:
            dict: Always returns a dict with 'success' and either 'output' or 'error'.
        """
        if not self.enabled or not self.wrapper:
            return {"success": False, "error": "WinStealth not available or disabled"}
        try:
            with open(pe_path, "rb") as f:
                pe_bytes = f.read()
            result = self.wrapper.reflective_load_pe(pe_bytes, profile)
            if result["success"]:
                # Clean up context
                self.wrapper.destroy_context(result["context"])
                return {"success": True, "output": f"PE loaded reflectively with context {result['context']}"}
            else:
                return {"success": False, "error": result.get("error", "Unknown error")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_bytes(self, pe_bytes: bytes, profile: str = "Win32") -> Dict:
        """
        Reflectively load a PE from raw bytes.

        Args:
            pe_bytes: Raw PE image bytes.
            profile: Execution profile.

        Returns:
            dict: same as execute_pe.
        """
        if not self.enabled or not self.wrapper:
            return {"success": False, "error": "WinStealth not available or disabled"}
        try:
            result = self.wrapper.reflective_load_pe(pe_bytes, profile)
            if result["success"]:
                self.wrapper.destroy_context(result["context"])
                return {"success": True, "output": "PE loaded reflectively"}
            else:
                return {"success": False, "error": result.get("error", "Unknown error")}
        except Exception as e:
            return {"success": False, "error": str(e)}

# ------------------------------------------------------------------
# NEW: ReAct Tool Agent (T3MP3ST) – enhanced with generator/judge and altitude awareness
# ------------------------------------------------------------------
class ReActToolAgent:
    """
    ReAct (Reasoning + Acting) loop wrapper with isolated generator/judge pair.
    Generator produces actions; judge evaluates them against raw source.
    Altitude-aware context injection: each altitude has its own context window.
    """

    def __init__(self, gateway, tool_name: str, max_iterations: int = 5,
                 altitude_context: Optional[Dict[str, Any]] = None):
        """
        Args:
            gateway: The Gateway instance for LLM calls and tool execution.
            tool_name: Name of the tool to use.
            max_iterations: Maximum number of ReAct cycles.
            altitude_context: Dict with keys 'project', 'file', 'feature', 'function'
                              each containing a context string.
        """
        if gateway is None:
            raise ValueError("ReActToolAgent: gateway cannot be None")
        self.gateway = gateway
        self.tool_name = tool_name
        self.max_iterations = max_iterations
        self.altitude_context = altitude_context or {}
        # Generator history (shared)
        self.generator_history = []
        # Judge history (isolated)
        self.judge_history = []

    def run(self, query: str, **kwargs) -> Dict:
        """
        Execute ReAct loop: Generator → Action → Observation → Judge → Repeat.
        """
        context = {"query": query, "tool": self.tool_name, "kwargs": kwargs, "thoughts": []}

        for i in range(self.max_iterations):
            # 1. Generator: produce thought/action plan
            thought = self._generate_thought(context)
            self.generator_history.append({"step": i, "type": "thought", "content": thought})
            context["thoughts"] = self.generator_history

            # 2. Action: extract tool call from thought
            action = self._plan_action(thought, context)
            self.generator_history.append({"step": i, "type": "action", "content": action})

            # 3. Observation (execute tool)
            observation = ""
            rc = -1
            if action and action.get("tool"):
                try:
                    result = self.gateway.run_tool(action["tool"], action.get("params", {}))
                    observation = result.get("output", "")
                    rc = result.get("rc", -1)
                    self.generator_history.append({"step": i, "type": "observation", "content": observation[:500], "rc": rc})
                except Exception as e:
                    observation = f"Error: {str(e)}"
                    self.generator_history.append({"step": i, "type": "observation", "content": observation})
            else:
                self.generator_history.append({"step": i, "type": "observation", "content": "No action taken"})

            context["last_observation"] = observation

            # 4. Judge: evaluate generator's output and decide next step
            judge_result = self._judge(context, observation)
            self.judge_history.append({"step": i, "type": "judge", "content": judge_result})

            # If judge says complete, break
            if judge_result.get("complete", False):
                return {
                    "success": True,
                    "history": self.generator_history,
                    "judge_history": self.judge_history,
                    "final": observation,
                    "rc": rc
                }

        return {
            "success": False,
            "history": self.generator_history,
            "judge_history": self.judge_history,
            "reason": "Max iterations reached",
            "rc": -1
        }

    def _generate_thought(self, context: Dict) -> str:
        """Generate a reasoning step using the LLM, with altitude context injected."""
        # Build altitude-aware context
        alt_prompt = ""
        for level, ctx in self.altitude_context.items():
            if ctx:
                alt_prompt += f"\n[{level.upper()} CONTEXT]: {ctx[:200]}..."

        prompt = f"""You are a ReAct agent using the tool '{self.tool_name}'.
Task: {context['query']}
Previous steps: {json.dumps(self.generator_history[-3:], indent=2) if self.generator_history else 'None'}
{alt_prompt}

Based on the task, previous steps, and the altitude context, what is your thought about what to do next?
Be concise and specific."""
        return self.gateway.generate(prompt, model=self.gateway.fast_model)

    def _plan_action(self, thought: str, context: Dict) -> Dict:
        """Parse thought to extract tool action."""
        if not thought:
            return {"tool": self.tool_name, "params": context.get("kwargs", {})}

        prompt = f"""From the following thought, extract the tool action to take.
Thought: {thought}
Available tool: {self.tool_name}
Expected parameters: {json.dumps(context.get('kwargs', {}))}

Output a JSON object with keys: "tool" (string, always "{self.tool_name}") and "params" (dict of parameters).
If no specific parameters are mentioned, use the defaults.
Example: {{"tool": "{self.tool_name}", "params": {{"target": "example.com", "options": "-sV"}}}}
Return only the JSON, no explanation."""
        try:
            response = self.gateway.generate(prompt, model=self.gateway.fast_model, json_mode=True)
            action = json.loads(response)
            if action.get("tool") == self.tool_name:
                return action
            else:
                return {"tool": self.tool_name, "params": context.get("kwargs", {})}
        except Exception:
            return {"tool": self.tool_name, "params": context.get("kwargs", {})}

    def _judge(self, context: Dict, observation: str) -> Dict:
        """
        Judge evaluates the generator's action and observation against raw source
        and decides if the goal is complete or requires further actions.
        """
        # Include altitude context and separate judge history (not shared with generator)
        alt_prompt = ""
        for level, ctx in self.altitude_context.items():
            if ctx:
                alt_prompt += f"\n[{level.upper()} CONTEXT]: {ctx[:200]}..."

        prompt = f"""You are a judge for a ReAct agent.
Task: {context['query']}
Raw source (altitude context): {alt_prompt}
Generator's latest thought: {self.generator_history[-2]['content'] if len(self.generator_history)>=2 else 'N/A'}
Generator's latest action: {self.generator_history[-1]['content'] if self.generator_history else 'N/A'}
Observation: {observation[:300]}

Judge whether the task is fully accomplished, or if the agent should continue.
Output JSON: {{"complete": bool, "reason": "..."}}.
Be strict: only set complete=True if the task is clearly achieved."""
        response = self.gateway.generate(prompt, model=self.gateway.fast_model, json_mode=True)
        try:
            return json.loads(response)
        except:
            return {"complete": False, "reason": "Judge could not parse response"}

    def _get_task_from_context(self) -> str:
        """Extract original task from history."""
        if self.generator_history:
            for entry in self.generator_history:
                if entry.get("type") == "thought" and "Task:" in entry.get("content", ""):
                    pass
        return "unknown"

# ------------------------------------------------------------------
# NEW: OGhidra Headless Executor (fixed command construction)
# ------------------------------------------------------------------
class OGhidraExecutor:
    """
    Execute Ghidra headless with OGhidra plugin for AI‑powered binary analysis.
    Requires Ghidra 11.3+ and OGhidraMCP plugin installed.
    """

    def __init__(self, config: dict):
        # Guard against None config
        self.config = config or {}
        self.ghidra_path = self._find_ghidra()
        self.oghidra_plugin = self._find_oghidra_plugin()
        self.enabled = self.ghidra_path is not None and self.oghidra_plugin is not None
        if not self.enabled:
            logger.warning("OGhidraExecutor not fully enabled: Ghidra or OGhidra plugin not found.")
            logger.warning("Set GHIDRA_INSTALL_DIR environment variable and install OGhidraMCP plugin.")
        else:
            logger.info(f"OGhidraExecutor initialized with Ghidra at {self.ghidra_path}")

    def _find_ghidra(self) -> Optional[Path]:
        """Locate Ghidra installation from environment or common paths."""
        ghidra_env = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_env:
            path = Path(ghidra_env)
            if path.exists():
                return path

        common_paths = [
            Path("/opt/ghidra"),
            Path("/usr/local/ghidra"),
            Path.home() / "ghidra",
            Path.home() / "tools" / "ghidra"
        ]
        for base in [Path("/opt"), Path("/usr/local")]:
            if base.exists():
                for item in base.iterdir():
                    if item.is_dir() and item.name.startswith("ghidra"):
                        common_paths.append(item)

        for path in common_paths:
            if path.exists() and (path / "support" / "analyzeHeadless").exists():
                return path

        headless = shutil.which("analyzeHeadless")
        if headless:
            headless_path = Path(headless).resolve()
            if "support" in headless_path.parts:
                ghidra_root = headless_path.parent.parent
                if ghidra_root.exists():
                    return ghidra_root

        logger.warning("Could not find Ghidra installation. Set GHIDRA_INSTALL_DIR environment variable.")
        return None

    def _find_oghidra_plugin(self) -> Optional[Path]:
        """Locate the OGhidraMCP plugin."""
        if not self.ghidra_path:
            return None

        ext_dirs = [
            self.ghidra_path / "Extensions" / "GHIDRA",
            Path.home() / ".ghidra" / "Extensions",
        ]
        for base in ext_dirs:
            if base.exists():
                for item in base.iterdir():
                    if item.is_dir() and "OGhidra" in item.name:
                        if (item / "OGhidraMCP.py").exists() or (item / "OGhidraMCP.jar").exists():
                            return item
                        for sub in item.iterdir():
                            if sub.is_dir() and "OGhidra" in sub.name:
                                if (sub / "OGhidraMCP.py").exists():
                                    return sub

        plugin_path = Path.home() / ".ghidra" / "Extensions" / "OGhidraMCP"
        if plugin_path.exists():
            return plugin_path

        logger.warning("Could not find OGhidraMCP plugin. Ensure it is installed in Ghidra extensions.")
        return None

    def analyze_binary(self, binary_path: str, task_mode: str = "smart",
                       output_format: str = "json") -> Dict:
        """
        Run headless Ghidra with OGhidra analysis.

        Returns a dict with rc, output, and parsed (if JSON).
        Never returns None; always returns a dict with error key on failure.
        """
        if not self.enabled:
            return {"error": "OGhidraExecutor not enabled (Ghidra or plugin missing)", "rc": -1}
        if not Path(binary_path).exists():
            return {"error": f"Binary not found: {binary_path}", "rc": -1}

        output_dir = Path("/tmp/oghidra_output")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"{Path(binary_path).stem}_result.{'json' if output_format == 'json' else 'txt'}"

        project_dir = output_dir / "project"
        project_dir.mkdir(exist_ok=True)

        # Build command as a list – safe from shell injection
        cmd = [
            str(self.ghidra_path / "support" / "analyzeHeadless"),
            str(project_dir),
            "OGhidraProject",
            "-import", str(binary_path),
            "-scriptPath", str(self.oghidra_plugin),
            "-postScript", "OGhidraMCP.py",
            "-scriptArgs", f"task={task_mode},output={str(output_file)}"
        ]

        quoted_cmd = " ".join(shlex.quote(arg) for arg in cmd)
        logger.info(f"Running OGhidra analysis: {quoted_cmd}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if output_file.exists():
                if output_format == "json":
                    try:
                        parsed = json.loads(output_file.read_text())
                        return {
                            "rc": result.returncode,
                            "output": result.stdout + result.stderr,
                            "parsed": parsed
                        }
                    except Exception as e:
                        logger.error(f"Failed to parse OGhidra output JSON: {e}")
                        return {"rc": result.returncode, "output": result.stdout + result.stderr}
                else:
                    return {
                        "rc": result.returncode,
                        "output": result.stdout + result.stderr + "\n" + output_file.read_text()
                    }
            else:
                return {"rc": result.returncode, "output": result.stdout + result.stderr}
        except subprocess.TimeoutExpired:
            return {"error": "OGhidra analysis timed out after 600s", "rc": -1}
        except Exception as e:
            logger.exception("OGhidra analysis failed")
            return {"error": str(e), "rc": -1}

# ------------------------------------------------------------------
# ToolExecutor – main class for external use
# ------------------------------------------------------------------
class ToolExecutor:
    def __init__(self, timeout: int = 30, soul=None, config: dict = None):
        self.timeout = timeout
        self.soul = soul
        self.config = config or {}
        self.mcp_client = None
        if self.config.get("mcp", {}).get("enabled", False):
            self.mcp_client = MCPClient(self.config)
            logger.info(f"MCP client enabled with {len(self.mcp_client.servers)} server(s)")
        self.tools: List[ToolInfo] = discover_tools()
        logger.info(f"ToolExecutor initialized with {len(self.tools)} local tools")
        # Initialize WinStealthExecutor if enabled
        self.winstealth_executor = WinStealthExecutor(self.config)
        # Initialize OGhidraExecutor
        self.oghidra_executor = OGhidraExecutor(self.config)
        if self.oghidra_executor.enabled:
            logger.info("OGhidraExecutor enabled")
        # Internal gateway reference for ReAct loop
        self._gateway = None

    def reload(self):
        self.tools = discover_tools()
        logger.info(f"Reloaded tools, now {len(self.tools)} available")

    def list_tools(self) -> List[Dict]:
        tools = [{"name": t.name, "lang": t.lang, "description": t.description} for t in self.tools]
        if self.mcp_client:
            for server_name, server in self.mcp_client.servers.items():
                tools.append({
                    "name": f"{server_name}:*",
                    "lang": "mcp",
                    "description": f"MCP server '{server_name}' at {server['url']} (dynamic tools)"
                })
        if self.winstealth_executor.enabled:
            tools.append({
                "name": "winstealth_load",
                "lang": "winstealth",
                "description": "Reflectively load a PE using WinStealth (Windows evasion)"
            })
        if self.oghidra_executor.enabled:
            tools.append({
                "name": "oghidra_analyze",
                "lang": "oghidra",
                "description": "OGhidra AI-powered binary analysis (malware, smart, full)"
            })
        # Add shell tool entry if it's allowed in config
        if self.config.get("allow_shell", False) or os.environ.get("PHALANX_ALLOW_SHELL", "0") == "1":
            tools.append({
                "name": "shell",
                "lang": "shell",
                "description": "Execute arbitrary shell command (dangerous, opt-in)"
            })
        return tools

    def _is_mcp_tool(self, name: str) -> bool:
        return "__" in name and self.mcp_client is not None

    def _execute_mcp_tool(self, tool_full_name: str, args_dict: Dict, timeout: int) -> Dict:
        parts = tool_full_name.split("__", 1)
        if len(parts) != 2:
            return {"status": "ERROR", "summary": f"Invalid MCP tool name format: {tool_full_name}. Expected 'server__tool'", "rc": -1}
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
        if args_dict is None:
            args_dict = {}

        # ------------------------------------------------------------------
        # Special case: shell command
        # ------------------------------------------------------------------
        if name == "shell":
            # Check opt-in
            if not (self.config.get("allow_shell", False) or os.environ.get("PHALANX_ALLOW_SHELL", "0") == "1"):
                return {
                    "status": "ERROR",
                    "summary": "Shell execution not allowed. Set PHALANX_ALLOW_SHELL=1 or config['allow_shell']=True",
                    "rc": -1
                }
            try:
                from phalanx_tools import run_shell_command
                command = args_dict.get("command", "")
                if not command:
                    return {"status": "ERROR", "summary": "Missing 'command' argument for shell", "rc": -1}
                timeout = args_dict.get("timeout", self.timeout)
                result = run_shell_command(command, timeout=timeout, config=self.config)
                # Normalize result
                if "rc" not in result:
                    result["rc"] = result.get("returncode", -1)
                if "output" not in result:
                    result["output"] = result.get("raw_output", "")
                return {
                    "status": "SUCCESS" if result.get("rc", -1) == 0 else "ERROR",
                    "summary": result.get("output", "")[:200],
                    "raw_output": result.get("output", ""),
                    "rc": result.get("rc", -1)
                }
            except ImportError:
                return {"status": "ERROR", "summary": "run_shell_command not available", "rc": -1}
            except Exception as e:
                return {"status": "ERROR", "summary": str(e), "rc": -1}

        # Special case: winstealth_load (renamed from sindri_load)
        if name == "winstealth_load" or name == "sindri_load":
            pe_path = args_dict.get("pe_path")
            profile = args_dict.get("profile", "Win32")
            if not pe_path:
                return {"status": "ERROR", "summary": "Missing 'pe_path' argument for winstealth_load", "rc": -1}
            result = self.winstealth_executor.execute_pe(pe_path, profile)
            # Guard against None result
            if result is None:
                result = {"success": False, "error": "Executor returned None"}
            if result.get("success", False):
                return {
                    "status": "SUCCESS",
                    "summary": result.get("output", "PE loaded successfully"),
                    "raw_output": result.get("output", ""),
                    "rc": 0
                }
            else:
                return {
                    "status": "ERROR",
                    "summary": result.get("error", "Unknown error"),
                    "raw_output": "",
                    "rc": -1
                }

        # Special case: oghidra_analyze
        if name == "oghidra_analyze":
            binary_path = args_dict.get("binary_path")
            task_mode = args_dict.get("task_mode", "smart")
            if not binary_path:
                return {"status": "ERROR", "summary": "Missing 'binary_path' for oghidra_analyze", "rc": -1}
            result = self.oghidra_executor.analyze_binary(binary_path, task_mode)
            if result is None:
                result = {"error": "Executor returned None", "rc": -1}
            if result.get("rc", -1) == 0:
                return {
                    "status": "SUCCESS",
                    "summary": "OGhidra analysis completed",
                    "raw_output": result.get("output", ""),
                    "parsed": result.get("parsed", {}),
                    "rc": result.get("rc", 0)
                }
            else:
                return {
                    "status": "ERROR",
                    "summary": result.get("error", "OGhidra analysis failed"),
                    "raw_output": result.get("output", ""),
                    "rc": result.get("rc", -1)
                }

        if self._is_mcp_tool(name):
            result = self._execute_mcp_tool(name, args_dict, self.timeout)
        else:
            tool = next((t for t in self.tools if t.name == name), None)
            if not tool:
                return {"status": "ERROR", "summary": f"Tool '{name}' not found", "raw_output": "", "rc": -1}
            try:
                tool.ensure_compiled()
                if not tool.handler:
                    return {"status": "ERROR", "summary": f"No handler for language '{tool.lang}'", "raw_output": "", "rc": -1}
                result = tool.handler.execute(tool, args_dict, self.timeout, self.config)
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

        # Normalise output and rc keys for Gateway compatibility
        if "rc" not in result:
            result["rc"] = result.get("returncode", -1)
        if "output" not in result:
            result["output"] = result.get("raw_output", result.get("stdout", ""))

        if parse_output:
            if parser is None:
                parser = PARSER_REGISTRY.get(name)
            if parser and result.get("raw_output"):
                try:
                    parsed = parser(result["raw_output"], args_dict)
                    result["parsed"] = parsed
                except Exception as e:
                    logger.warning(f"Parser failed for tool {name}: {e}")
                    result["parsed"] = {"error": str(e)}
            elif parser is None and name in PARSER_REGISTRY:
                pass

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

        if self.soul:
            self.soul.append_memory("TOOL_RUN", name, f"Status: {result['status']}, Summary: {result['summary'][:100]}")
        return result

    def execute_script(self, script_path: Path, args: List[str], timeout: Optional[int] = None) -> Dict:
        """
        Run an external script directly (bypassing tool discovery).
        Script is executed with Python interpreter (assumes .py) – for other languages, user must provide interpreter.
        Returns dict with status, summary, raw_output, rc.
        """
        if not script_path.exists():
            return {"status": "ERROR", "summary": f"Script not found: {script_path}", "raw_output": "", "rc": -1}
        ext = script_path.suffix.lower()
        if ext == ".py":
            cmd = [sys.executable, str(script_path)] + args
        elif ext in (".sh", ".bash"):
            bash = shutil.which("bash")
            if not bash:
                return {"status": "ERROR", "summary": "bash not found", "raw_output": "", "rc": -1}
            cmd = [bash, str(script_path)] + args
        elif ext == ".js":
            node = shutil.which("node")
            if not node:
                return {"status": "ERROR", "summary": "node not found", "raw_output": "", "rc": -1}
            cmd = [node, str(script_path)] + args
        else:
            cmd = [str(script_path)] + args
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout or self.timeout)
            return {
                "status": "SUCCESS" if res.returncode == 0 else "ERROR",
                "summary": (res.stdout + res.stderr)[:200],
                "raw_output": res.stdout + res.stderr,
                "rc": res.returncode
            }
        except subprocess.TimeoutExpired:
            return {"status": "ERROR", "summary": f"Script timed out after {timeout or self.timeout}s", "raw_output": "", "rc": -1}
        except Exception as e:
            logger.exception(f"Script execution failed: {script_path}")
            return {"status": "ERROR", "summary": str(e), "raw_output": "", "rc": -1}

    # ------------------------------------------------------------------
    # ReAct Tool Agent integration (with gateway guard)
    # ------------------------------------------------------------------
    def react_loop(self, tool_name: str, query: str, max_iterations: int = 5,
                   altitude_context: Optional[Dict[str, Any]] = None,
                   **kwargs) -> Dict:
        """
        Run a ReAct loop for a given tool and query, using the enhanced generator/judge agent.
        If gateway is missing, handles gracefully.
        """
        from phalanx_tools import Gateway  # avoid circular import at top
        # Ensure we have a gateway; if not, try to create one.
        gateway = getattr(self, '_gateway', None)
        if gateway is None:
            try:
                gateway = Gateway(self.config, {})
                self._gateway = gateway
            except Exception as e:
                logger.error(f"Failed to create Gateway for ReAct loop: {e}")
                return {"status": "ERROR", "summary": f"ReAct loop unavailable: {e}", "rc": -1}
        # Guard against gateway being None after creation
        if gateway is None:
            return {"status": "ERROR", "summary": "Gateway is None; cannot run ReAct loop", "rc": -1}

        try:
            agent = ReActToolAgent(gateway, tool_name, max_iterations, altitude_context)
            return agent.run(query, **kwargs)
        except ValueError as e:
            # ReActToolAgent raises ValueError for missing gateway (already handled)
            return {"status": "ERROR", "summary": str(e), "rc": -1}
        except Exception as e:
            logger.exception(f"ReAct loop failed for {tool_name}")
            return {"status": "ERROR", "summary": str(e), "rc": -1}

# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------
if __name__ == "__main__":
    executor = ToolExecutor(timeout=10, config={"sandbox": {"enabled": False}, "mcp": {"enabled": False}})
    print("Discovered local tools:", [t.name for t in executor.tools])
    if any(t.name == "echo" for t in executor.tools):
        result = executor.execute("echo", {"message": "Hello from engine"})
        print("Echo result:", json.dumps(result, indent=2))

    # Test InteractiveSession
    if _TMUX_AVAILABLE or _PEXPECT_AVAILABLE:
        session = InteractiveSession("bash", name="test_session")
        if session.start():
            session.send("echo hello world", expect_prompt="hello world")
            output = session.get_output()
            print("Interactive output:", output[:200])
            session.close()

    # Test OGhidra if available
    if executor.oghidra_executor.enabled:
        print("OGhidraExecutor enabled, testing with /bin/ls (if exists)")
        test_binary = "/bin/ls"
        if Path(test_binary).exists():
            result = executor.oghidra_executor.analyze_binary(test_binary, task_mode="smart")
            print("OGhidra result:", json.dumps(result, indent=2, default=str))

    # Test ReAct loop (requires gateway)
    from phalanx_tools import Gateway
    g = Gateway({"ollama": {"url": "http://localhost:11434", "default_model": "qwen2.5:0.5b"}}, {})
    executor._gateway = g
    # Provide a dummy altitude context
    alt_ctx = {"project": "Test project", "file": "main.c", "feature": "vulnerable function", "function": "strcpy"}
    result = executor.react_loop("nmap", "Scan localhost for open ports", altitude_context=alt_ctx)
    print("ReAct result:", json.dumps(result, indent=2, default=str))