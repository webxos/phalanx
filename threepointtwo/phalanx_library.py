#!/usr/bin/env python3
"""
PHALANX v3.2 – Backend Library: directory setup, full polyglot tool bootstrap,
and centralised logger.
"""

import json
import shutil
import subprocess
import sys
import logging
import logging.handlers
import traceback
from pathlib import Path
from typing import List, Optional
from rich.console import Console

console = Console(stderr=True)

# --------------------------- Logger ---------------------------
class PhalanxLogger:
    _instance = None
    def __new__(cls, name: str = "phalanx"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_logger(name)
        return cls._instance

    def _init_logger(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s", datefmt="%H:%M:%S"))
        self.logger.addHandler(ch)
        BASE = Path.home() / ".phalanx"
        log_dir = BASE / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "phalanx.log"
        fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(module)s:%(lineno)d | %(message)s\n----------------------------------------", datefmt="%Y-%m-%d %H:%M:%S"))
        self.logger.addHandler(fh)
        self.log_file = log_file
        self.info("PHALANX Logger initialized")
    def debug(self, msg):   self.logger.debug(msg)
    def info(self, msg):    self.logger.info(msg)
    def warning(self, msg): self.logger.warning(msg)
    def error(self, msg, exc_info=True):
        if exc_info:
            console.print(f"[bold red]ERROR[/] {msg}", style="red")
            console.print(traceback.format_exc(), style="dim")
        self.logger.error(msg, exc_info=exc_info)
    def exception(self, msg="Exception occurred"): self.error(msg, exc_info=True)
    def get_log_path(self): return self.log_file

def get_logger(name="phalanx"): return PhalanxLogger(name)
def log_info(msg):    get_logger().info(msg)
def log_warning(msg): get_logger().warning(msg)
def log_error(msg):   get_logger().error(msg)

# --------------------------- Paths ---------------------------
BASE = Path.home() / ".phalanx"
LIB_DIR = BASE / "lib"
TOOLS_DIR = BASE / "tools"
LOGS_DIR = BASE / "logs"
REPORTS_DIR = BASE / "reports"
SKINS_DIR = BASE / "skins"
SOUL_DIR = BASE / "soul"
ENGAGEMENTS_DIR = BASE / "engagements"
AUDIT_DIR = BASE / "audits"
SKILLS_DIR = BASE / "skills"
_BOOTSTRAP_SENTINEL = BASE / ".full_bootstrap_done"

def ensure_dirs():
    for d in (LIB_DIR, TOOLS_DIR, LOGS_DIR, REPORTS_DIR, SKINS_DIR, SOUL_DIR,
              ENGAGEMENTS_DIR, AUDIT_DIR, SKILLS_DIR, BASE / "chroma_db"):
        d.mkdir(parents=True, exist_ok=True)

def _find_compiler(names: List[str]) -> Optional[str]:
    for name in names:
        if shutil.which(name): return name
    return None

# --------------------------- Polyglot stub generators ---------------------------
def _write_python_tools(tools_dir: Path):
    def w(name: str, src: str):
        p = tools_dir / name
        if not p.exists():
            p.write_text(src)
            p.chmod(0o755)

    w("echo.py", """#!/usr/bin/env python3
import sys, json
def run(args):
    return {'status': 'SUCCESS', 'summary': args.get('message', 'echo')}
if __name__ == '__main__':
    print(json.dumps(run(json.loads(sys.stdin.read() or '{}'))))
""")
    w("date.py", """#!/usr/bin/env python3
import sys, json
from datetime import datetime, timezone
def run(args):
    return {'status': 'SUCCESS', 'summary': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
if __name__ == '__main__':
    print(json.dumps(run(json.loads(sys.stdin.read() or '{}'))))
""")
    w("shell.py", """#!/usr/bin/env python3
import sys, json, subprocess, shlex
def run(args):
    cmd = args.get('command', '')
    if not cmd: return {'status': 'ERROR', 'summary': 'No command provided'}
    try:
        out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT, timeout=15, text=True)
        return {'status': 'SUCCESS', 'summary': out.strip()[:2000]}
    except subprocess.TimeoutExpired:
        return {'status': 'ERROR', 'summary': 'Timed out (15s)'}
    except subprocess.CalledProcessError as e:
        return {'status': 'ERROR', 'summary': (e.output or str(e))[:2000]}
    except Exception as e:
        return {'status': 'ERROR', 'summary': str(e)}
if __name__ == '__main__':
    print(json.dumps(run(json.loads(sys.stdin.read() or '{}'))))
""")
    w("file_read.py", """#!/usr/bin/env python3
import sys, json
from pathlib import Path
def run(args):
    p = args.get('path')
    if not p: return {'status': 'ERROR', 'summary': 'Missing path'}
    try:
        return {'status': 'SUCCESS', 'summary': Path(p).expanduser().read_text(encoding='utf-8', errors='replace')[:2000]}
    except Exception as e:
        return {'status': 'ERROR', 'summary': str(e)}
if __name__ == '__main__':
    print(json.dumps(run(json.loads(sys.stdin.read() or '{}'))))
""")
    w("web_fetch.py", """#!/usr/bin/env python3
import sys, json
try: import requests as _req
except ImportError: _req = None
def run(args):
    if _req is None: return {'status': 'ERROR', 'summary': 'requests not installed'}
    url = args.get('url')
    if not url: return {'status': 'ERROR', 'summary': 'Missing url'}
    try:
        r = _req.get(url, timeout=10, headers={'User-Agent': 'PHALANX/3.2'})
        if r.status_code == 200: return {'status': 'SUCCESS', 'summary': r.text[:3000]}
        return {'status': 'ERROR', 'summary': f'HTTP {r.status_code}'}
    except Exception as e:
        return {'status': 'ERROR', 'summary': str(e)}
if __name__ == '__main__':
    print(json.dumps(run(json.loads(sys.stdin.read() or '{}'))))
""")

def _write_wasm_tool(tools_dir: Path):
    wasm_dir = tools_dir / "wasm" / "echo_wasm"
    wasm_dir.mkdir(parents=True, exist_ok=True)
    wat_content = '''(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (global $next_free (mut i32) i32.const 8192)
  (func (export "run") (param $offset i32) (param $len i32) (result i32)
    (local $result_ptr i32) (local $i i32)
    (local.set $result_ptr (global.get $next_free))
    (global.set $next_free (i32.add (global.get $next_free) (i32.const 4096)))
    (i32.store8 (local.get $result_ptr) (i32.const 69))   ; 'E'
    (i32.store8 (i32.add (local.get $result_ptr) (i32.const 1)) (i32.const 99))   ; 'c'
    (i32.store8 (i32.add (local.get $result_ptr) (i32.const 2)) (i32.const 104))  ; 'h'
    (i32.store8 (i32.add (local.get $result_ptr) (i32.const 3)) (i32.const 111))  ; 'o'
    (i32.store8 (i32.add (local.get $result_ptr) (i32.const 4)) (i32.const 58))   ; ':'
    (i32.store8 (i32.add (local.get $result_ptr) (i32.const 5)) (i32.const 32))   ; ' '
    (local.set $i (i32.const 0))
    (block $done
      (loop $copy
        (br_if $done (i32.eq (local.get $i) (local.get $len)))
        (i32.store8 (i32.add (local.get $result_ptr) (i32.add (i32.const 6) (local.get $i)))
                    (i32.load8_u (i32.add (local.get $offset) (local.get $i))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $copy)))
    (i32.store8 (i32.add (local.get $result_ptr) (i32.add (i32.const 6) (local.get $i))) (i32.const 0))
    (local.get $result_ptr))
)'''
    wat_file = wasm_dir / "echo_wasm.wat"
    wat_file.write_text(wat_content)
    # compile if wat2wasm available
    if shutil.which("wat2wasm"):
        subprocess.run(["wat2wasm", str(wat_file), "-o", str(wasm_dir / "echo_wasm.wasm")], capture_output=True)
    else:
        # minimal pre‑compiled wasm stub (placeholder)
        import base64
        stub = "AGFzbQEAAAABDQJgAAF/YAF/AGADf39/AAIDBQEBAQIHBgEDBQsBBQMBAAEBBhIDBQAAAR8RBApjdXN0b21fY2FsbF9pbmRpY2F0b3IBA2ZkX3dyaXRlAAADBwIGAAIMAA0BAAEDDEVjaG86IAAuLi4P"
        (wasm_dir / "echo_wasm.wasm").write_bytes(base64.b64decode(stub))
    manifest = wasm_dir / "tool.json"
    manifest.write_text(json.dumps({"name": "echo_wasm", "language": "wasm", "source": "echo_wasm.wasm", "description": "Wasm echo stub"}, indent=2))

def _write_polyglot_tools(tools_dir: Path):
    # JS
    js_dir = tools_dir / "js"
    js_dir.mkdir(exist_ok=True)
    (js_dir / "echo.js").write_text('''#!/usr/bin/env node
const fs = require('fs');
let input = '';
fs.readFile(0, 'utf8', (err, data) => {
    if (err) return console.log(JSON.stringify({status: "ERROR", summary: err.message}));
    try { let args = JSON.parse(data || '{}'); console.log(JSON.stringify({status: "SUCCESS", summary: args.message || "echo"})); }
    catch(e) { console.log(JSON.stringify({status: "ERROR", summary: e.message})); }
});''')
    (js_dir / "echo.js").chmod(0o755)
    # Ruby
    rb_dir = tools_dir / "ruby"
    rb_dir.mkdir(exist_ok=True)
    (rb_dir / "echo.rb").write_text('''#!/usr/bin/env ruby
require 'json'
input = STDIN.read
args = input.empty? ? {} : JSON.parse(input)
puts JSON.generate({status: "SUCCESS", summary: args["message"] || "echo"})''')
    (rb_dir / "echo.rb").chmod(0o755)
    # Rust (source)
    rust_dir = tools_dir / "rust"
    rust_dir.mkdir(exist_ok=True)
    (rust_dir / "echo.rs").write_text('''use std::io::{self, Read};
fn main() {
    let mut input = String::new(); io::stdin().read_to_string(&mut input).unwrap();
    let args: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();
    let msg = args.get("message").and_then(|m| m.as_str()).unwrap_or("echo");
    println!("{}", serde_json::json!({"status": "SUCCESS", "summary": msg}).to_string());
}''')
    # C
    c_dir = tools_dir / "c"
    c_dir.mkdir(exist_ok=True)
    (c_dir / "echo.c").write_text('''#include <stdio.h>
#include <json-c/json.h>
int main() {
    char buf[4096]; fread(buf, 1, sizeof(buf)-1, stdin);
    struct json_object *parsed = json_tokener_parse(buf);
    const char *msg = "echo";
    json_object *msg_obj;
    if (json_object_object_get_ex(parsed, "message", &msg_obj)) msg = json_object_get_string(msg_obj);
    struct json_object *result = json_object_new_object();
    json_object_object_add(result, "status", json_object_new_string("SUCCESS"));
    json_object_object_add(result, "summary", json_object_new_string(msg));
    printf("%s\\n", json_object_to_json_string(result));
    json_object_put(result); json_object_put(parsed);
    return 0;
}''')
    # Go
    go_dir = tools_dir / "go"
    go_dir.mkdir(exist_ok=True)
    (go_dir / "echo.go").write_text('''package main
import ("encoding/json"; "fmt"; "os")
func main() {
    var args map[string]interface{}
    json.NewDecoder(os.Stdin).Decode(&args)
    msg, ok := args["message"].(string)
    if !ok { msg = "echo" }
    out, _ := json.Marshal(map[string]string{"status": "SUCCESS", "summary": msg})
    fmt.Println(string(out))
}''')
    # Bash
    bash_dir = tools_dir / "bash"
    bash_dir.mkdir(exist_ok=True)
    (bash_dir / "echo.sh").write_text('''#!/bin/bash
read input
msg=$(echo "$input" | jq -r '.message // "echo"')
echo "{\\"status\\":\\"SUCCESS\\",\\"summary\\":\\"$msg\\"}"''')
    (bash_dir / "echo.sh").chmod(0o755)

def bootstrap_all(force: bool = False):
    if _BOOTSTRAP_SENTINEL.exists() and not force:
        log_info("Bootstrap already done. Use force=True to re-run.")
        print("PHALANX: Bootstrap already done. Use force=True to re-run.")
        return
    ensure_dirs()
    log_info("Starting full PHALANX bootstrap...")
    try:
        _write_python_tools(TOOLS_DIR)
        _write_wasm_tool(TOOLS_DIR)
        _write_polyglot_tools(TOOLS_DIR)
        _BOOTSTRAP_SENTINEL.write_text("ok")
        log_info("Full bootstrap completed successfully")
        print("PHALANX: Full bootstrap complete – all tools, directories, and support files created.")
    except Exception as e:
        log_error(f"Bootstrap failed: {e}")
        print(f"[ERROR] Bootstrap failed: {e}")
        raise

def bootstrap_tools(force: bool = False):
    bootstrap_all(force)

if __name__ == "__main__":
    bootstrap_all(force=True)
