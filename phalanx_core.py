#!/usr/bin/env python3
"""
PHALANX v3.1 – Core (Enhanced):
- Structured OPPLAN with objectives list
- Orchestrator iterates over objectives, tracks PASS/FAIL
- Per‑objective agent spawning (clean context)
- Sandboxed tool execution (Docker by default)
- Advanced RoE with human confirmation gates
- MITRE tagging & reporting integration
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Callable

from phalanx_library import get_logger, log_error

logger = get_logger("phalanx.core")

BASE_DIR = Path.home() / ".phalanx"
CONFIG_FILE = BASE_DIR / "config.json"
HISTORY_FILE = BASE_DIR / "history.txt"
AUDIT_DIR = BASE_DIR / "audits"
ENGAGEMENTS_DIR = BASE_DIR / "engagements"
REPORTS_DIR = BASE_DIR / "reports"

def _default_config() -> dict:
    return {
        "phalanx": {"version": "3.1", "agent_name": "PHALANX"},
        "ollama": {"url": "http://localhost:11434", "default_model": "qwen2.5:7b",
                   "fast_model": "qwen2.5:1.5b", "analysis_model": "qwen2.5:7b",
                   "embedding_model": "nomic-embed-text", "timeout": 120, "temperature": 0.1},
        "database": {"backend": "sqlite", "sqlite_path": "~/.phalanx/phalanx.db"},
        "pentest": {"max_steps": 50, "docker_image": "instrumentisto/nmap:latest",
                    "auto_searchsploit": True, "sandbox_required": True},
        "tools": {"timeout": 30, "require_confirm_sudo": True},
        "engagement": {"default_roe": {"allowed_targets": [], "forbidden_actions": ["data_exfiltration", "destruction"],
                                       "require_human_confirm": ["data_exfiltration", "destruction", "privilege_escalation"]},
                       "time_window": None},
        "profiles": {
            "eco": {"orchestrator": "qwen2.5:7b", "planner": "qwen2.5:7b", "recon": "qwen2.5:1.5b",
                    "exploit": "qwen2.5:7b", "post_exploit": "qwen2.5:7b"},
            "max": {"orchestrator": "llama3:70b", "planner": "llama3:70b", "recon": "llama3:70b",
                    "exploit": "llama3:70b", "post_exploit": "llama3:70b"},
            "test": {"orchestrator": "qwen2.5:1.5b", "planner": "qwen2.5:1.5b", "recon": "qwen2.5:1.5b",
                     "exploit": "qwen2.5:1.5b", "post_exploit": "qwen2.5:1.5b"},
        },
        "sandbox": {"enabled": True, "docker_network": "sandbox-net", "image": "kalilinux/kali-rolling",
                    "mount_tools": True, "mount_db": True},
        "reporting": {"pdf_enabled": False, "html_template": "default"},
        "c2": {"sliver_server_addr": "127.0.0.1:31337", "auto_start": False},
    }

def load_config(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return _default_config()

def _ensure_dirs():
    for d in (BASE_DIR, AUDIT_DIR, ENGAGEMENTS_DIR, REPORTS_DIR, BASE_DIR / "skills",
              BASE_DIR / "soul", BASE_DIR / "logs", BASE_DIR / "tools", BASE_DIR / "lib"):
        d.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

def bootstrap():
    _ensure_dirs()
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(_default_config(), indent=2))
    try:
        from phalanx_library import bootstrap_tools
        bootstrap_tools()
        logger.info("Engine tools bootstrapped")
    except Exception as e:
        logger.error(f"Engine bootstrap failed: {e}")
        print(f"[bootstrap] engine not ready: {e}")

# ---- Soul ----
class Soul:
    def __init__(self, path: Path = BASE_DIR / "soul.db", name: str = "PHALANX"):
        self.path = path
        self.name = name
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._lock = threading.Lock()
        self.conn.execute("CREATE TABLE IF NOT EXISTS memory (id INTEGER PRIMARY KEY, ts TEXT, category TEXT, subtype TEXT, content TEXT)")
        try:
            self.conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS fts_memory USING fts5(content, category, subtype)")
        except sqlite3.OperationalError:
            pass
        self.conn.commit()
    def append(self, category: str, subtype: str, text: str):
        ts = datetime.now().isoformat()
        with self._lock:
            self.conn.execute("INSERT INTO memory (ts,category,subtype,content) VALUES (?,?,?,?)", (ts, category, subtype, text))
            try:
                self.conn.execute("INSERT INTO fts_memory (content,category,subtype) VALUES (?,?,?)", (text, category, subtype))
            except Exception:
                pass
            self.conn.commit()
    def search(self, query: str, limit=6) -> List[Dict]:
        try:
            with self._lock:
                cur = self.conn.execute("SELECT ts, category, subtype, content, snippet(fts_memory,-1,'[',']','...',64) as summary FROM fts_memory WHERE fts_memory MATCH ? ORDER BY rank LIMIT ?", (query, limit))
                return [{"ts": r[0], "type": f"{r[1]}/{r[2]}", "summary": r[4] or r[3][:100]} for r in cur.fetchall()]
        except Exception:
            return []
    def recent(self, limit=20) -> List[Dict]:
        cur = self.conn.execute("SELECT ts, category, subtype, content FROM memory ORDER BY id DESC LIMIT ?", (limit,))
        return [{"ts": r[0], "type": f"{r[1]}/{r[2]}", "content": r[3]} for r in cur.fetchall()]

# ---- SkillManager ----
class SkillManager:
    def __init__(self, path: Path = BASE_DIR / "skills.md"):
        self.path = path
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("# PHALANX Skill Log\n")
    def list_skills(self) -> List[Dict]:
        skills = []
        if not self.path.exists():
            return skills
        try:
            for line in self.path.read_text().splitlines():
                if line.strip() and not line.startswith("#"):
                    parts = line.split("|")
                    if len(parts) >= 4:
                        skills.append({"name": parts[0].strip(), "success": int(parts[1].strip()), "fail": int(parts[2].strip()), "last_used": parts[3].strip()})
        except Exception:
            pass
        return skills
    def update_skill(self, name: str, success: bool = True):
        with self._lock:
            skills = self.list_skills()
            found = False
            for s in skills:
                if s["name"] == name:
                    if success: s["success"] += 1
                    else: s["fail"] += 1
                    s["last_used"] = datetime.now().isoformat()
                    found = True
                    break
            if not found:
                skills.append({"name": name, "success": 1 if success else 0, "fail": 0 if success else 1, "last_used": datetime.now().isoformat()})
            lines = ["# PHALANX Skill Log"]
            for s in skills:
                lines.append(f"{s['name']}|{s['success']}|{s['fail']}|{s['last_used']}")
            self.path.write_text("\n".join(lines) + "\n")

# ---- PentestDB (extended with objectives and MITRE) ----
_SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, target TEXT NOT NULL, scan_type TEXT DEFAULT 'full', tools_used TEXT, started_at TEXT, finished_at TEXT, status TEXT DEFAULT 'running', notes TEXT);
CREATE TABLE IF NOT EXISTS vulnerabilities (vuln_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(session_id), name TEXT, severity TEXT, cve TEXT, description TEXT, evidence TEXT, port TEXT, service TEXT, discovered_at TEXT, mitre_id TEXT);
CREATE TABLE IF NOT EXISTS fixes (fix_id TEXT PRIMARY KEY, vuln_id TEXT NOT NULL REFERENCES vulnerabilities(vuln_id), session_id TEXT NOT NULL REFERENCES sessions(session_id), description TEXT, commands TEXT, priority INTEGER DEFAULT 5, created_at TEXT);
CREATE TABLE IF NOT EXISTS exploits (exploit_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(session_id), name TEXT, tool TEXT, command TEXT, result TEXT, success INTEGER DEFAULT 0, attempted_at TEXT, mitre_techniques TEXT);
CREATE TABLE IF NOT EXISTS summaries (summary_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(session_id), raw_output TEXT, ai_analysis TEXT, risk_score REAL DEFAULT 0.0, created_at TEXT);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS objectives (obj_id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(session_id), description TEXT, status TEXT, started_at TEXT, finished_at TEXT, mitre_tags TEXT);
"""

class PentestDB:
    def __init__(self, config: dict):
        self.config = config
        self._lock = threading.Lock()
        db_cfg = config.get("database", {})
        db_path = Path(db_cfg.get("sqlite_path", "~/.phalanx/phalanx.db")).expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()
    def _init_schema(self):
        with self._lock:
            cur = self.conn.cursor()
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    cur.execute(s)
            cur.execute("SELECT value FROM meta WHERE key='schema_version'")
            row = cur.fetchone()
            if row is None:
                cur.execute("INSERT INTO meta (key,value) VALUES (?,?)", ("schema_version", str(_SCHEMA_VERSION)))
            elif int(row[0]) != _SCHEMA_VERSION:
                print(f"[DB] Warning: schema version mismatch (found {row[0]}, expected {_SCHEMA_VERSION})")
            self.conn.commit()
    def _uid(self) -> str: return str(uuid.uuid4())[:16]
    def create_session(self, target: str, scan_type="full", tools_used=None) -> str:
        sid = self._uid()
        now = datetime.now().isoformat()
        with self._lock:
            self.conn.execute("INSERT INTO sessions (session_id,target,scan_type,tools_used,started_at,status) VALUES (?,?,?,?,?,?)",
                               (sid, target, scan_type, json.dumps(tools_used or []), now, "running"))
            self.conn.commit()
        return sid
    def finish_session(self, session_id: str, status="completed"):
        with self._lock:
            self.conn.execute("UPDATE sessions SET finished_at=?, status=? WHERE session_id=?", (datetime.now().isoformat(), status, session_id))
            self.conn.commit()
    def get_session(self, session_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    def list_sessions(self, limit=20) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    def add_vulnerability(self, session_id: str, name: str, severity: str, description: str, cve="", evidence="", port="", service="", mitre_id="") -> str:
        vid = self._uid()
        with self._lock:
            self.conn.execute("INSERT INTO vulnerabilities (vuln_id,session_id,name,severity,cve,description,evidence,port,service,discovered_at,mitre_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               (vid, session_id, name, severity, cve, description, evidence, port, service, datetime.now().isoformat(), mitre_id))
            self.conn.commit()
        return vid
    def get_vulnerabilities(self, session_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM vulnerabilities WHERE session_id=? ORDER BY severity", (session_id,))
        return [dict(r) for r in cur.fetchall()]
    def add_fix(self, session_id: str, vuln_id: str, description: str, commands=None, priority=5) -> str:
        fid = self._uid()
        with self._lock:
            self.conn.execute("INSERT INTO fixes (fix_id,vuln_id,session_id,description,commands,priority,created_at) VALUES (?,?,?,?,?,?,?)",
                               (fid, vuln_id, session_id, description, json.dumps(commands or []), priority, datetime.now().isoformat()))
            self.conn.commit()
        return fid
    def add_exploit(self, session_id: str, name: str, tool: str, command: str, result: str, success=False, mitre_techniques=None) -> str:
        eid = self._uid()
        with self._lock:
            self.conn.execute("INSERT INTO exploits (exploit_id,session_id,name,tool,command,result,success,attempted_at,mitre_techniques) VALUES (?,?,?,?,?,?,?,?,?)",
                               (eid, session_id, name, tool, command, result, 1 if success else 0, datetime.now().isoformat(), json.dumps(mitre_techniques or [])))
            self.conn.commit()
        return eid
    def save_summary(self, session_id: str, raw_output: str, ai_analysis: str, risk_score=0.0) -> str:
        sid = self._uid()
        with self._lock:
            self.conn.execute("INSERT INTO summaries (summary_id,session_id,raw_output,ai_analysis,risk_score,created_at) VALUES (?,?,?,?,?,?)",
                               (sid, session_id, raw_output, ai_analysis, risk_score, datetime.now().isoformat()))
            self.conn.commit()
        return sid
    def full_report(self, session_id: str) -> Dict:
        session = self.get_session(session_id)
        if not session:
            return {}
        return {"session": session, "vulnerabilities": self.get_vulnerabilities(session_id),
                "exploits": self.get_exploits(session_id), "summary": self.get_summary(session_id),
                "objectives": self.get_objectives(session_id)}
    def get_exploits(self, session_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM exploits WHERE session_id=?", (session_id,))
        return [dict(r) for r in cur.fetchall()]
    def get_summary(self, session_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM summaries WHERE session_id=? ORDER BY created_at DESC LIMIT 1", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    def add_objective(self, session_id: str, description: str, mitre_tags: List[str] = None) -> str:
        obj_id = self._uid()
        with self._lock:
            self.conn.execute("INSERT INTO objectives (obj_id,session_id,description,status,started_at,mitre_tags) VALUES (?,?,?,?,?,?)",
                               (obj_id, session_id, description, "pending", datetime.now().isoformat(), json.dumps(mitre_tags or [])))
            self.conn.commit()
        return obj_id
    def update_objective_status(self, obj_id: str, status: str):
        with self._lock:
            self.conn.execute("UPDATE objectives SET status=?, finished_at=? WHERE obj_id=?", (status, datetime.now().isoformat() if status in ("passed","failed") else None, obj_id))
            self.conn.commit()
    def get_objectives(self, session_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM objectives WHERE session_id=? ORDER BY started_at", (session_id,))
        return [dict(r) for r in cur.fetchall()]
    def close(self):
        try: self.conn.close()
        except: pass

# ---- RoEEnforcer (Advanced with Human Confirmation) ----
class RoEEnforcer:
    def __init__(self, config: dict, confirm_callback: Optional[Callable[[str, Dict], bool]] = None):
        self.config = config
        self.active_plan = None
        self.confirm_callback = confirm_callback or self._default_confirm

    def load_plan(self, plan: dict):
        self.active_plan = plan

    def check_action(self, action: str, target: str, details: Dict = None) -> Tuple[bool, str, bool]:
        if not self.active_plan:
            return True, "No active RoE plan", False
        roe = self.active_plan.get("roe", {})
        allowed = roe.get("allowed_targets", [])
        if allowed and target not in allowed:
            return False, f"Target {target} not in RoE allowed list", False
        forbidden = roe.get("forbidden_actions", [])
        for f in forbidden:
            if f in action.lower():
                return False, f"Action '{action}' matches forbidden pattern '{f}'", False
        require_confirm = roe.get("require_human_confirm", self.config.get("engagement", {}).get("default_roe", {}).get("require_human_confirm", []))
        for risk in require_confirm:
            if risk in action.lower() or (details and details.get("category") == risk):
                return True, f"Action '{action}' is high-risk – requires human confirmation", True
        return True, "Allowed", False

    def enforce(self, tool_name: str, target: str, details: Dict = None) -> bool:
        allowed, reason, need_confirm = self.check_action(tool_name, target, details)
        if not allowed:
            raise PermissionError(f"RoE violation: {reason}")
        if need_confirm:
            if not self.confirm_callback(f"Confirm high‑risk action: {tool_name} on {target}? Details: {details}", details):
                raise PermissionError(f"Human denied action: {tool_name}")
        return True

    def _default_confirm(self, prompt: str, details: Dict) -> bool:
        print(f"\n⚠️  {prompt}")
        resp = input("Confirm? (y/N): ").strip().lower()
        return resp == "y"

# ---- AuditLogger ----
class AuditLogger:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.log_path = AUDIT_DIR / f"{engagement_id}.json"
        self._lock = threading.Lock()
        self._ensure_file()
    def _ensure_file(self):
        if not self.log_path.exists():
            with open(self.log_path, "w") as f:
                json.dump({"engagement_id": self.engagement_id, "events": []}, f)
    def log(self, event_type: str, details: Dict):
        with self._lock:
            with open(self.log_path, "r") as f:
                data = json.load(f)
            data["events"].append({"timestamp": datetime.now().isoformat(), "type": event_type, **details})
            with open(self.log_path, "w") as f:
                json.dump(data, f, indent=2)

# ---- Multi‑Agent LangGraph Orchestrator (Objective‑Driven) ----
def _require_langgraph():
    try:
        from pydantic import BaseModel, Field, ConfigDict
        from langgraph.graph import StateGraph, END
        from langchain_ollama import ChatOllama, OllamaEmbeddings
        from langchain_core.messages import HumanMessage
        import chromadb
        return BaseModel, Field, ConfigDict, StateGraph, END, ChatOllama, OllamaEmbeddings, HumanMessage, chromadb
    except ImportError as e:
        raise ImportError(f"Autonomous engine requires: langgraph langchain-ollama chromadb\nInstall: pip install -U langgraph langchain-ollama chromadb\nOriginal: {e}")

class AgentRegistry:
    def __init__(self, gateway, llm, embeddings, chroma_client, skill_mgr):
        self.gateway = gateway
        self.llm = llm
        self.embeddings = embeddings
        self.chroma = chroma_client
        self.skill_mgr = skill_mgr
        self.memory_collection = chroma_client.get_or_create_collection(name="agent_memory", embedding_function=None)
        from phalanx_tools import get_tool_list_for_llm, TOOL_CAPABILITIES_PROMPT
        self.tool_prompt = TOOL_CAPABILITIES_PROMPT
        self.tool_list_str = get_tool_list_for_llm()

    def _get_prompt(self, agent_name: str) -> str:
        prompts = {
            "orchestrator": """You are PHALANX-Orchestrator. Manage the kill chain by iterating over objectives.
Decide which agent (recon, exploit, post_exploit) should handle the current objective.
Output JSON: {"next_agent": "name", "reason": "...", "suggested_tools": [{"tool": "name", "args": {...}}]}""",
            "planner": """You are PHALANX-Planner. Generate a structured OPPLAN with a list of objectives.
Output JSON with keys: "objectives" (list of dicts with "description" and "mitre_tags"), "roe" (allowed_targets, forbidden_actions, require_human_confirm).""",
            "recon": """You are PHALANX-Recon. Choose reconnaissance tools for the current objective.
Output JSON: {"tools_to_run": ["tool1", "tool2"], "args": {"tool1": {...}}}""",
            "exploit": """You are PHALANX-Exploit. Suggest specific exploits for the objective.
Output JSON: {"exploits": [{"name": "...", "tool": "...", "args": {...}}], "ghidra_needed": true/false}""",
            "post_exploit": """You are PHALANX-PostExploit. Plan lateral movement, persistence, data collection.
Output JSON: {"c2_framework": "...", "tools": ["..."]}""",
        }
        base = prompts.get(agent_name, "You are a PHALANX assistant.")
        skill_context = ""
        if agent_name in ("recon", "exploit", "post_exploit"):
            skills = self.skill_mgr.list_skills()
            high_success = [s["name"] for s in skills if s["success"] > s["fail"] and s["success"] > 0]
            if high_success:
                skill_context = f"\nPrefer these high‑success tools: {', '.join(high_success[:5])}\n"
        return base + skill_context + "\n\n" + self.tool_prompt.format(tool_list=self.tool_list_str)

    def invoke(self, agent_name: str, state: Dict) -> Dict:
        system_prompt = self._get_prompt(agent_name)
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps(state, indent=2)}]
        response = self.gateway.chat(messages, model=self.gateway.get_model_for_agent(agent_name), json_mode=True)
        try:
            return json.loads(response)
        except:
            return {"error": "Invalid JSON", "raw": response}

class AutonomousPentest:
    def __init__(self, config: dict, db: PentestDB, soul: Soul, skill_mgr: SkillManager,
                 executor, progress_cb=None, gateway=None, confirm_callback=None):
        (BaseModel, Field, ConfigDict, StateGraph, END, ChatOllama, OllamaEmbeddings, HumanMessage, chromadb) = _require_langgraph()
        self.config = config
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.executor = executor
        self.progress = progress_cb or print
        self.gateway = gateway
        if not self.gateway:
            from phalanx_tools import Gateway
            self.gateway = Gateway(config)
        ollama_cfg = config.get("ollama", {})
        self.llm = ChatOllama(model=ollama_cfg.get("analysis_model", "qwen2.5:7b"), base_url=ollama_cfg.get("url", "http://localhost:11434"), temperature=ollama_cfg.get("temperature", 0.1), num_ctx=8192)
        self.embeddings = OllamaEmbeddings(model=ollama_cfg.get("embedding_model", "nomic-embed-text"), base_url=ollama_cfg.get("url", "http://localhost:11434"))
        chroma_path = BASE_DIR / "chroma_db"
        chroma_path.mkdir(exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(path=str(chroma_path))
        self.memory_collection = self.chroma_client.get_or_create_collection(name="pentest_memory", embedding_function=None)
        self.agent_registry = AgentRegistry(self.gateway, self.llm, self.embeddings, self.chroma_client, self.skill_mgr)
        self.roe_enforcer = RoEEnforcer(config, confirm_callback)
        self.audit_logger = None
        try:
            import docker
            self.docker = docker.from_env()
        except:
            self.docker = None
        self._StateGraph = StateGraph
        self._END = END
        self._HumanMessage = HumanMessage
        self._BaseModel = BaseModel
        self._Field = Field
        self._ConfigDict = ConfigDict
        self.graph = self._build_graph()

    def _make_state_class(self):
        BaseModel = self._BaseModel
        Field = self._Field
        ConfigDict = self._ConfigDict
        class PentestState(BaseModel):
            target: str
            session_id: str = ""
            user_input: str = ""
            engagement_plan: Dict = Field(default_factory=dict)
            research: str = ""
            plan: List[str] = Field(default_factory=list)
            results: List[Dict] = Field(default_factory=list)
            memory_ids: List[str] = Field(default_factory=list)
            step_count: int = 0
            max_steps: int = 50
            finished: bool = False
            current_agent: str = "orchestrator"
            consecutive_failures: int = 0
            current_objective: Optional[Dict] = None
            objective_ids: List[str] = Field(default_factory=list)
            objective_passed: bool = False
            model_config = ConfigDict(arbitrary_types_allowed=True)
        return PentestState

    def _embed_and_store(self, text: str, metadata: Dict) -> str:
        try:
            embedding = self.embeddings.embed_query(text)
            doc_id = f"mem_{datetime.now().timestamp()}_{hash(text) % 10000}"
            self.memory_collection.add(ids=[doc_id], embeddings=[embedding], documents=[text], metadatas=[metadata])
            return doc_id
        except Exception:
            return ""

    def _run_with_error_handling(self, node_func, state):
        try:
            return node_func(state)
        except Exception as e:
            self.progress(f"[ERROR] Node failed: {e}\n{traceback.format_exc()}")
            self.soul.append("NODE_ERROR", node_func.__name__, str(e))
            state.step_count += 1
            state.consecutive_failures += 1
            return state

    def _orchestrator(self, state):
        self.progress("[Orchestrator] Reviewing objectives...")
        objectives = self.db.get_objectives(state.session_id)
        current_obj = None
        for obj in objectives:
            if obj["status"] == "pending":
                current_obj = obj
                break
        if not current_obj:
            state.finished = True
            return state
        state.current_objective = current_obj
        self.progress(f"  → Working on objective: {current_obj['description']}")
        decision = self.agent_registry.invoke("orchestrator", {
            "objective": current_obj["description"],
            "target": state.target,
            "previous_results": state.results[-5:]
        })
        next_agent = decision.get("next_agent", "recon")
        state.current_agent = next_agent
        state.results.append({"step": "orchestrator", "objective": current_obj["obj_id"], "decision": next_agent})
        return state

    def _planner(self, state):
        self.progress("[Planner] Generating structured OPPLAN with objectives...")
        plan = self.agent_registry.invoke("planner", {"target": state.target, "user_input": state.user_input or ""})
        objectives = plan.get("objectives", [])
        if not objectives:
            objectives = [{"description": f"Penetration test of {state.target}", "mitre_tags": []}]
        for obj in objectives:
            obj_id = self.db.add_objective(state.session_id, obj["description"], obj.get("mitre_tags", []))
            state.objective_ids.append(obj_id)
        plan_path = ENGAGEMENTS_DIR / f"{state.session_id}_plan.json"
        with open(plan_path, "w") as f:
            json.dump(plan, f, indent=2)
        self.roe_enforcer.load_plan(plan)
        self.audit_logger = AuditLogger(state.session_id)
        self.audit_logger.log("plan_generated", {"plan": plan})
        state.results.append({"step": "planner", "plan": plan})
        return state

    def _recon(self, state):
        obj = state.current_objective
        self.progress(f"[Recon] For objective: {obj['description']}")
        from phalanx_tools import run_tool_sandboxed
        recon_result = self.agent_registry.invoke("recon", {"objective": obj["description"], "target": state.target})
        combined = []
        for tool_name in recon_result.get("tools_to_run", []):
            args = recon_result.get("args", {}).get(tool_name, {"target": state.target})
            try:
                self.roe_enforcer.enforce(tool_name, state.target, details={"category": "recon", "objective": obj["obj_id"]})
                result = run_tool_sandboxed(tool_name, self.config, **args)
                combined.append(f"[{tool_name}]\n{result.get('output', '')[:2000]}")
                self.skill_mgr.update_skill(tool_name, success=(result.get("rc", 0) == 0))
                self.audit_logger.log("tool_execution", {"tool": tool_name, "output": result.get("output", "")[:500]})
            except Exception as e:
                self.progress(f"  Tool {tool_name} failed: {e}")
        state.research = "\n\n".join(combined)
        self._embed_and_store(state.research, {"type": "recon", "objective": obj["obj_id"]})
        return state

    def _exploit(self, state):
        obj = state.current_objective
        self.progress(f"[Exploit] For objective: {obj['description']}")
        from phalanx_tools import run_tool_sandboxed
        exploit_plan = self.agent_registry.invoke("exploit", {"objective": obj["description"], "recon_data": state.research[:2000]})
        for exp in exploit_plan.get("exploits", [])[:2]:
            tool = exp.get("tool")
            if not tool: continue
            try:
                self.roe_enforcer.enforce(tool, state.target, details={"category": "exploit", "objective": obj["obj_id"]})
                result = run_tool_sandboxed(tool, self.config, **exp.get("args", {}))
                success = (result.get("rc", 0) == 0)
                self.db.add_exploit(state.session_id, exp.get("name"), tool, exp.get("command", ""), result.get("output", ""), success, exp.get("mitre_techniques"))
                if success:
                    self.progress(f"  Exploit succeeded: {exp.get('name')}")
                    self.db.update_objective_status(obj["obj_id"], "passed")
                    state.objective_passed = True
                else:
                    self.progress(f"  Exploit failed: {exp.get('name')}")
            except Exception as e:
                self.progress(f"  Exploit {tool} error: {e}")
        return state

    def _post_exploit(self, state):
        obj = state.current_objective
        self.progress(f"[PostExploit] For objective: {obj['description']}")
        from phalanx_tools import run_tool_sandboxed, run_sliver_auto_config, run_sliver_session_cmd
        post_plan = self.agent_registry.invoke("post_exploit", {"objective": obj["description"], "target": state.target})
        if post_plan.get("c2_framework") == "sliver":
            run_sliver_auto_config(self.config.get("c2", {}).get("sliver_server_addr", "127.0.0.1:31337"))
            result = run_tool_sandboxed("sliver_generate", self.config, target_ip=state.target)
            self.db.add_exploit(state.session_id, "sliver_implant", "sliver_generate", "", result.get("output", ""), result.get("rc", 0) == 0)
        for tool in post_plan.get("tools", []):
            result = run_tool_sandboxed(tool, self.config, target=state.target)
            self.skill_mgr.update_skill(tool, success=(result.get("rc", 0) == 0))
        return state

    def _reflector(self, state) -> str:
        if state.objective_passed:
            self.db.update_objective_status(state.current_objective["obj_id"], "passed")
            state.results.append({"step": "reflector", "objective": state.current_objective["obj_id"], "status": "passed"})
            state.current_objective = None
            state.objective_passed = False
            return "orchestrator"
        state.step_count += 1
        if state.step_count >= state.max_steps:
            return "reporter"
        recent_rcs = [r.get("rc", -1) for r in state.results[-3:] if "rc" in r]
        if recent_rcs and all(rc != 0 for rc in recent_rcs):
            state.consecutive_failures += 1
        else:
            state.consecutive_failures = 0
        if state.consecutive_failures >= 3:
            self.db.update_objective_status(state.current_objective["obj_id"], "failed")
            return "reporter"
        return state.current_agent

    def _reporter(self, state):
        self.progress("[Reporter] Generating final report...")
        from phalanx_reporting import generate_report
        report_data = self.db.full_report(state.session_id)
        report_path = generate_report(report_data, self.config, output_dir=REPORTS_DIR)
        self.progress(f"Report saved: {report_path}")
        self.db.finish_session(state.session_id, "completed")
        state.finished = True
        return state

    def _route_after_orchestrator(self, state) -> str:
        return state.current_agent

    def _build_graph(self):
        StateGraph = self._StateGraph
        END = self._END
        PentestState = self._make_state_class()
        workflow = StateGraph(PentestState)

        workflow.add_node("planner", lambda s: self._run_with_error_handling(self._planner, s))
        workflow.add_node("orchestrator", lambda s: self._run_with_error_handling(self._orchestrator, s))
        workflow.add_node("recon", lambda s: self._run_with_error_handling(self._recon, s))
        workflow.add_node("exploit", lambda s: self._run_with_error_handling(self._exploit, s))
        workflow.add_node("post_exploit", lambda s: self._run_with_error_handling(self._post_exploit, s))
        workflow.add_node("reporter", lambda s: self._run_with_error_handling(self._reporter, s))

        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "orchestrator")
        workflow.add_conditional_edges("orchestrator", self._route_after_orchestrator, {
            "recon": "recon", "exploit": "exploit", "post_exploit": "post_exploit", "reporter": "reporter"
        })
        workflow.add_edge("recon", "orchestrator")
        workflow.add_edge("exploit", "orchestrator")
        workflow.add_conditional_edges("post_exploit", self._reflector, {"orchestrator": "orchestrator", "reporter": "reporter"})
        workflow.add_edge("reporter", END)
        return workflow.compile()

    def run(self, target: str, scan_type="full", user_input: str = "") -> Dict:
        session_id = self.db.create_session(target, scan_type, [])
        PentestState = self._make_state_class()
        initial_state = PentestState(target=target, session_id=session_id, max_steps=self.config.get("pentest", {}).get("max_steps", 50), user_input=user_input)
        self.graph.invoke(initial_state)
        return self.db.full_report(session_id)

# ---- Engagement planning helper (extended) ----
def generate_engagement_plan(target: str, user_input: str, gateway) -> Dict:
    prompt = f"Target: {target}\nUser requirements: {user_input}\nGenerate a structured OPPLAN with a list of objectives. Output JSON with keys: 'objectives' (list of dicts each with 'description' and 'mitre_tags'), 'roe' (allowed_targets, forbidden_actions, require_human_confirm)."
    model = gateway.get_model_for_agent("planner")
    response = gateway.generate(prompt, model=model, json_mode=True)
    try:
        plan = json.loads(response)
    except:
        plan = {"error": "Invalid JSON from planner", "raw": response}
    if "objectives" not in plan:
        plan["objectives"] = [{"description": f"Penetration test of {target}", "mitre_tags": []}]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    plan_path = ENGAGEMENTS_DIR / f"{target}_{ts}_plan.json"
    with open(plan_path, "w") as f:
        json.dump(plan, f, indent=2)
    return plan
