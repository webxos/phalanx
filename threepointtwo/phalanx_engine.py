#!/usr/bin/env python3
"""
PHALANX phalanx_engine.py – Polyglot ToolExecutor with support for:
Python, JavaScript, Ruby, Rust, C, C++, Java, OCaml, WebAssembly, Go, Bash.
Handlers only – bootstrapping moved to phalanx_library.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from phalanx_library import get_logger, log_error

logger = get_logger("phalanx.engine")

BASE = Path.home() / ".phalanx"
LIB_DIR = BASE / "lib"
TOOLS_DIR = BASE / "tools"

def _ensure_dirs():
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

def _find_compiler(names: List[str]) -> Optional[str]:
    for name in names:
        if shutil.which(name):
            return name
    return None

def _run_executable(cmd: List[str], args_dict: Dict[str, Any], timeout: int) -> Dict:
    arg_json = json.dumps(args_dict)
    try:
        with subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        ) as proc:
            stdout, stderr = proc.communicate(input=arg_json, timeout=timeout)
            if proc.returncode != 0:
                return {"status": "ERROR",
                        "summary": f"Exited {proc.returncode}: {stderr.strip()[:500]}"}
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
        return {"status": "ERROR", "summary": str(e)}

class LanguageHandler:
    lang_name = "unknown"
    def ensure_compiled(self, tool_info: "ToolInfo") -> Path:
        return tool_info.source_path
    def execute(self, tool_info: "ToolInfo", args_dict: Dict, timeout: int) -> Dict:
        raise NotImplementedError

# ----- Handlers -----
class PythonHandler(LanguageHandler):
    lang_name = "python"
    def execute(self, t, a, to):
        return _run_executable([sys.executable, str(t.executable)], a, to)

class JavaScriptHandler(LanguageHandler):
    lang_name = "javascript"
    def execute(self, t, a, to):
        node = _find_compiler(["node", "nodejs"])
        if not node:
            return {"status": "ERROR", "summary": "node/nodejs not found"}
        return _run_executable([node, str(t.executable)], a, to)

class RubyHandler(LanguageHandler):
    lang_name = "ruby"
    def execute(self, t, a, to):
        ruby = _find_compiler(["ruby"])
        if not ruby:
            return {"status": "ERROR", "summary": "ruby not found"}
        return _run_executable([ruby, str(t.executable)], a, to)

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
    def execute(self, t, a, to):
        return _run_executable([str(t.executable)], a, to)

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
    def execute(self, t, a, to):
        return _run_executable([str(t.executable)], a, to)

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
    def execute(self, t, a, to):
        return _run_executable([str(t.executable)], a, to)

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
    def execute(self, t, a, to):
        java = _find_compiler(["java"])
        if not java:
            return {"status": "ERROR", "summary": "java not found"}
        class_dir = LIB_DIR / "java_classes"
        return _run_executable([java, "-cp", str(class_dir), t.source_path.stem], a, to)

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
    def execute(self, t, a, to):
        return _run_executable([str(t.executable)], a, to)

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
    def execute(self, t, a, to):
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
        arg_json = json.dumps(a)
        arg_bytes = arg_json.encode('utf-8')
        arg_len = len(arg_bytes)
        offset = 4096
        try:
            if offset + arg_len + 4096 > memory.data_len(store):
                return {"status": "ERROR", "summary": "Wasm memory too small"}
            memory.write(store, offset, arg_bytes)
        except Exception as e:
            return {"status": "ERROR", "summary": f"Failed to write argument: {e}"}
        try:
            result_ptr = run_func(store, offset, arg_len)
        except Exception as e:
            return {"status": "ERROR", "summary": f"Wasm run failed: {e}"}
        result_bytes = bytearray()
        try:
            for i in range(4096):
                b = memory.read(store, result_ptr + i, 1)[0]
                if b == 0:
                    break
                result_bytes.append(b)
        except Exception:
            pass
        result_str = result_bytes.decode('utf-8', errors='replace')
        return {"status": "SUCCESS", "summary": result_str[:200], "echo": result_str}

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
    def execute(self, t, a, to):
        return _run_executable([str(t.executable)], a, to)

class BashHandler(LanguageHandler):
    lang_name = "bash"
    def execute(self, t, a, to):
        bash = _find_compiler(["bash"])
        if not bash:
            return {"status": "ERROR", "summary": "bash not found"}
        return _run_executable([bash, str(t.executable)], a, to)

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
    tools: List[ToolInfo] = []
    ext_map = {
        ".py": "python", ".js": "javascript", ".rb": "ruby",
        ".rs": "rust", ".c": "c", ".cpp": "cpp", ".cc": "cpp",
        ".java": "java", ".ml": "ocaml",
        ".wasm": "wasm", ".go": "go", ".sh": "bash", ".bash": "bash",
    }
    seen: set = set()
    if not TOOLS_DIR.exists():
        return tools
    for item in TOOLS_DIR.rglob("*"):
        if item.is_dir():
            manifest = item / "tool.json"
            if manifest.exists():
                try:
                    data = json.loads(manifest.read_text())
                except Exception:
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

class ToolExecutor:
    def __init__(self, timeout: int = 30, soul=None, config=None):
        self.timeout = timeout
        self.soul = soul
        self.config = config or {}
        _ensure_dirs()
        self.tools: List[ToolInfo] = discover_tools()
    def reload(self):
        self.tools = discover_tools()
    def list_tools(self) -> List[Dict]:
        return [{"name": t.name, "lang": t.lang, "description": t.description}
                for t in self.tools]
    def execute(self, name: str, args_dict: Optional[Dict] = None) -> Dict:
        if args_dict is None:
            args_dict = {}
        tool = next((t for t in self.tools if t.name == name), None)
        if not tool:
            return {"status": "ERROR", "summary": f"Tool '{name}' not found"}
        try:
            tool.ensure_compiled()
            if not tool.handler:
                return {"status": "ERROR",
                        "summary": f"No handler for language '{tool.lang}'"}
            result = tool.handler.execute(tool, args_dict, self.timeout)
            if self.soul:
                self.soul.append("TOOL_RUN", result.get("status", "UNKNOWN"), name)
            return result
        except Exception as e:
            if self.soul:
                self.soul.append("TOOL_RUN", "ERROR", name)
            logger.error(f"Tool '{name}' execution failed")
            return {"status": "ERROR", "summary": str(e)}

__all__ = ["ToolExecutor", "discover_tools", "ToolInfo"]
