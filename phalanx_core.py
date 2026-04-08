#!/usr/bin/env python3
"""
PHALANX v3 – Core: config, Soul memory, SkillManager, PentestDB, and
AutonomousPentest LangGraph orchestrator.

Heavy optional deps (langgraph, langchain-ollama, chromadb, docker) are
imported lazily so the module still loads when they are absent – useful
for testing without the full ML stack.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional

# ── Paths & bootstrap ──────────────────────────────────────────────────────

BASE_DIR    = Path.home() / ".phalanx"
CONFIG_FILE = BASE_DIR / "config.json"
HISTORY_FILE = BASE_DIR / "history.txt"
LIB_DIR     = BASE_DIR / "lib"


def _default_config() -> dict:
    return {
        "phalanx": {"version": "3.0", "agent_name": "PHALANX"},
        "ollama": {
            "url": "http://localhost:11434",
            "default_model": "qwen2.5:7b",
            "fast_model": "qwen2.5:1.5b",
            "analysis_model": "qwen2.5:7b",
            "embedding_model": "nomic-embed-text",
            "timeout": 120,
            "temperature": 0.1,
        },
        "database": {
            "backend": "sqlite",
            "sqlite_path": "~/.phalanx/phalanx.db",
        },
        "pentest": {
            "max_steps": 30,
            "docker_image": "instrumentisto/nmap:latest",
            "auto_searchsploit": True,
        },
        "tools": {"timeout": 30, "require_confirm_sudo": True},
    }


def load_config(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return _default_config()


def _ensure_dirs():
    for d in (
        BASE_DIR, LIB_DIR,
        BASE_DIR / "skills", BASE_DIR / "soul", BASE_DIR / "logs",
        BASE_DIR / "skins", BASE_DIR / "reports", BASE_DIR / "tools",
    ):
        d.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)


def bootstrap():
    """One-time setup: create dirs, write default config, bootstrap tools."""
    _ensure_dirs()
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(_default_config(), indent=2))
    # Bootstrap polyglot tool stubs (engine handles the sentinel guard)
    try:
        from phalanx_engine import bootstrap_tools
        bootstrap_tools()
    except Exception as e:
        print(f"[bootstrap] engine not ready: {e}")


# ── Soul – SQLite FTS5 memory ──────────────────────────────────────────────

class Soul:
    def __init__(self, path: Path, name: str = "PHALANX"):
        self.path = path
        self.name = name
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._lock = threading.Lock()
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id INTEGER PRIMARY KEY,
                ts TEXT, category TEXT, subtype TEXT, content TEXT
            )
        """)
        try:
            self.conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS fts_memory "
                "USING fts5(content, category, subtype)"
            )
        except sqlite3.OperationalError:
            pass
        self.conn.commit()

    def append(self, category: str, subtype: str, text: str):
        ts = datetime.now().isoformat()
        with self._lock:
            self.conn.execute(
                "INSERT INTO memory (ts,category,subtype,content) VALUES (?,?,?,?)",
                (ts, category, subtype, text),
            )
            try:
                self.conn.execute(
                    "INSERT INTO fts_memory (content,category,subtype) VALUES (?,?,?)",
                    (text, category, subtype),
                )
            except Exception:
                pass
            self.conn.commit()

    def search(self, query: str, limit: int = 6) -> List[Dict]:
        try:
            with self._lock:
                cur = self.conn.execute(
                    """SELECT ts, category, subtype, content,
                              snippet(fts_memory,-1,'[',']','...',64) as summary
                       FROM fts_memory WHERE fts_memory MATCH ?
                       ORDER BY rank LIMIT ?""",
                    (query, limit),
                )
                return [
                    {"ts": r[0], "type": f"{r[1]}/{r[2]}", "summary": r[4] or r[3][:100]}
                    for r in cur.fetchall()
                ]
        except Exception:
            return []

    def recent(self, limit: int = 20) -> List[Dict]:
        cur = self.conn.execute(
            "SELECT ts, category, subtype, content FROM memory "
            "ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [{"ts": r[0], "type": f"{r[1]}/{r[2]}", "content": r[3]} for r in cur.fetchall()]


# ── SkillManager ────────────────────────────────────────────────────────────

class SkillManager:
    def __init__(self, path: Path):
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
                        skills.append({
                            "name": parts[0].strip(),
                            "success": int(parts[1].strip()),
                            "fail": int(parts[2].strip()),
                            "last_used": parts[3].strip(),
                        })
        except Exception:
            pass
        return skills

    def update_skill(self, name: str, success: bool = True):
        with self._lock:
            skills = self.list_skills()
            found = False
            for s in skills:
                if s["name"] == name:
                    if success:
                        s["success"] += 1
                    else:
                        s["fail"] += 1
                    s["last_used"] = datetime.now().isoformat()
                    found = True
                    break
            if not found:
                skills.append({
                    "name": name,
                    "success": 1 if success else 0,
                    "fail": 0 if success else 1,
                    "last_used": datetime.now().isoformat(),
                })
            lines = ["# PHALANX Skill Log"]
            for s in skills:
                lines.append(f"{s['name']}|{s['success']}|{s['fail']}|{s['last_used']}")
            self.path.write_text("\n".join(lines) + "\n")


# ── PentestDB ───────────────────────────────────────────────────────────────

def _db_connection(config: dict):
    """Return (connection, placeholder) for SQLite or MariaDB."""
    db_cfg = config.get("database", {})
    if db_cfg.get("backend") == "mariadb":
        try:
            import mariadb  # type: ignore
            conn = mariadb.connect(
                host=db_cfg.get("host", "127.0.0.1"),
                port=db_cfg.get("port", 3306),
                user=db_cfg.get("user", "phalanx"),
                password=db_cfg.get("password", ""),
                database=db_cfg.get("name", "phalanx"),
            )
            conn.autocommit = False
            return conn, "?"
        except Exception as e:
            print(f"[DB] MariaDB unavailable ({e}), falling back to SQLite.")
    db_path = Path(db_cfg.get("sqlite_path", "~/.phalanx/phalanx.db")).expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn, "?"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    scan_type    TEXT DEFAULT 'full',
    tools_used   TEXT,
    started_at   TEXT,
    finished_at  TEXT,
    status       TEXT DEFAULT 'running',
    notes        TEXT
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id      TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    name         TEXT,
    severity     TEXT,
    cve          TEXT,
    description  TEXT,
    evidence     TEXT,
    port         TEXT,
    service      TEXT,
    discovered_at TEXT
);
CREATE TABLE IF NOT EXISTS fixes (
    fix_id       TEXT PRIMARY KEY,
    vuln_id      TEXT NOT NULL REFERENCES vulnerabilities(vuln_id),
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    description  TEXT,
    commands     TEXT,
    priority     INTEGER DEFAULT 5,
    created_at   TEXT
);
CREATE TABLE IF NOT EXISTS exploits (
    exploit_id   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    name         TEXT,
    tool         TEXT,
    command      TEXT,
    result       TEXT,
    success      INTEGER DEFAULT 0,
    attempted_at TEXT
);
CREATE TABLE IF NOT EXISTS summaries (
    summary_id   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(session_id),
    raw_output   TEXT,
    ai_analysis  TEXT,
    risk_score   REAL DEFAULT 0.0,
    created_at   TEXT
);
"""


class PentestDB:
    def __init__(self, config: dict):
        self.config = config
        self._lock = threading.Lock()
        self._conn, self._ph = _db_connection(config)
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            cur = self._conn.cursor()
            for stmt in _SCHEMA.strip().split(";"):
                s = stmt.strip()
                if s:
                    cur.execute(s)
            self._conn.commit()

    def _uid(self) -> str:
        return str(uuid.uuid4())[:16]

    # Sessions
    def create_session(self, target: str, scan_type: str = "full",
                       tools_used: Optional[List[str]] = None) -> str:
        sid = self._uid()
        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (session_id,target,scan_type,tools_used,started_at,status)"
                " VALUES (?,?,?,?,?,?)",
                (sid, target, scan_type, json.dumps(tools_used or []), now, "running"),
            )
            self._conn.commit()
        return sid

    def finish_session(self, session_id: str, status: str = "completed"):
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET finished_at=?, status=? WHERE session_id=?",
                (datetime.now().isoformat(), status, session_id),
            )
            self._conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict]:
        cur = self._conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_sessions(self, limit: int = 20) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def update_session_notes(self, session_id: str, notes: str):
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET notes=? WHERE session_id=?", (notes, session_id)
            )
            self._conn.commit()

    def delete_session(self, session_id: str):
        with self._lock:
            for tbl in ("summaries", "exploits", "fixes", "vulnerabilities", "sessions"):
                self._conn.execute(f"DELETE FROM {tbl} WHERE session_id=?", (session_id,))
            self._conn.commit()

    # Vulnerabilities
    def add_vulnerability(self, session_id: str, name: str, severity: str,
                          description: str, cve: str = "", evidence: str = "",
                          port: str = "", service: str = "") -> str:
        vid = self._uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO vulnerabilities"
                " (vuln_id,session_id,name,severity,cve,description,evidence,port,service,discovered_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (vid, session_id, name, severity, cve, description, evidence,
                 port, service, datetime.now().isoformat()),
            )
            self._conn.commit()
        return vid

    def get_vulnerabilities(self, session_id: str) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT * FROM vulnerabilities WHERE session_id=? ORDER BY severity", (session_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    # Fixes
    def add_fix(self, session_id: str, vuln_id: str, description: str,
                commands: Optional[List[str]] = None, priority: int = 5) -> str:
        fid = self._uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO fixes (fix_id,vuln_id,session_id,description,commands,priority,created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (fid, vuln_id, session_id, description,
                 json.dumps(commands or []), priority, datetime.now().isoformat()),
            )
            self._conn.commit()
        return fid

    def get_fixes(self, session_id: str) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT * FROM fixes WHERE session_id=? ORDER BY priority", (session_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    # Exploits
    def add_exploit(self, session_id: str, name: str, tool: str,
                    command: str, result: str, success: bool = False) -> str:
        eid = self._uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO exploits"
                " (exploit_id,session_id,name,tool,command,result,success,attempted_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (eid, session_id, name, tool, command, result,
                 1 if success else 0, datetime.now().isoformat()),
            )
            self._conn.commit()
        return eid

    def get_exploits(self, session_id: str) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT * FROM exploits WHERE session_id=? ORDER BY attempted_at", (session_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    # Summaries
    def save_summary(self, session_id: str, raw_output: str,
                     ai_analysis: str, risk_score: float = 0.0) -> str:
        sid = self._uid()
        with self._lock:
            self._conn.execute(
                "INSERT INTO summaries"
                " (summary_id,session_id,raw_output,ai_analysis,risk_score,created_at)"
                " VALUES (?,?,?,?,?,?)",
                (sid, session_id, raw_output, ai_analysis,
                 risk_score, datetime.now().isoformat()),
            )
            self._conn.commit()
        return sid

    def get_summary(self, session_id: str) -> Optional[Dict]:
        cur = self._conn.execute(
            "SELECT * FROM summaries WHERE session_id=? ORDER BY created_at DESC LIMIT 1",
            (session_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def full_report(self, session_id: str) -> Dict:
        session = self.get_session(session_id)
        if not session:
            return {}
        vulns = self.get_vulnerabilities(session_id)
        for v in vulns:
            v["fixes"] = self.get_fixes(session_id)
        return {
            "session": session,
            "vulnerabilities": vulns,
            "exploits": self.get_exploits(session_id),
            "summary": self.get_summary(session_id),
        }

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass


# ── AutonomousPentest (LangGraph) ─────────────────────────────────────────
# Optional heavy deps loaded lazily so the module still imports without them.

def _require_langgraph():
    try:
        from pydantic import BaseModel, Field
        from langgraph.graph import StateGraph, END
        from langchain_ollama import ChatOllama, OllamaEmbeddings
        from langchain_core.messages import HumanMessage
        import chromadb
        return BaseModel, Field, StateGraph, END, ChatOllama, OllamaEmbeddings, HumanMessage, chromadb
    except ImportError as e:
        raise ImportError(
            f"Autonomous engine requires: langgraph langchain-ollama chromadb\n"
            f"Install: pip install langgraph langchain-ollama chromadb\nOriginal: {e}"
        )


class AutonomousPentest:
    """
    PentAGI-style autonomous cycle:
    researcher → planner → executor → reflector → (loop or report)
    """

    def __init__(self, config: dict, db: PentestDB, soul: Soul,
                 skill_mgr: SkillManager, executor,
                 progress_cb: Optional[Callable] = None):
        (BaseModel, Field, StateGraph, END,
         ChatOllama, OllamaEmbeddings, HumanMessage, chromadb) = _require_langgraph()

        self.config = config
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.executor = executor
        self.progress = progress_cb or print

        ollama_cfg = config.get("ollama", {})
        self.llm = ChatOllama(
            model=ollama_cfg.get("analysis_model", "qwen2.5:7b"),
            base_url=ollama_cfg.get("url", "http://localhost:11434"),
            temperature=ollama_cfg.get("temperature", 0.1),
            num_ctx=8192,
        )
        self.embeddings = OllamaEmbeddings(
            model=ollama_cfg.get("embedding_model", "nomic-embed-text"),
            base_url=ollama_cfg.get("url", "http://localhost:11434"),
        )
        chroma_path = BASE_DIR / "chroma_db"
        chroma_path.mkdir(exist_ok=True)
        self.chroma_client = chromadb.PersistentClient(path=str(chroma_path))
        self.memory_collection = self.chroma_client.get_or_create_collection(
            name="pentest_memory", embedding_function=None
        )
        try:
            import docker as _docker
            self.docker = _docker.from_env()
        except Exception:
            self.docker = None

        # Store LangGraph classes for _build_graph
        self._StateGraph = StateGraph
        self._END = END
        self._HumanMessage = HumanMessage
        self._BaseModel = BaseModel
        self._Field = Field
        self.graph = self._build_graph()

    # ── State ──────────────────────────────────────────────────────────────
    def _make_state_class(self):
        BaseModel = self._BaseModel
        Field = self._Field

        class PentestState(BaseModel):
            target: str
            session_id: str = ""
            research: str = ""
            plan: List[str] = Field(default_factory=list)
            results: List[Dict] = Field(default_factory=list)
            memory_ids: List[str] = Field(default_factory=list)
            step_count: int = 0
            max_steps: int = 30
            finished: bool = False

        return PentestState

    # ── Memory helpers ─────────────────────────────────────────────────────
    def _embed_and_store(self, text: str, metadata: Dict) -> str:
        try:
            embedding = self.embeddings.embed_query(text)
            doc_id = f"mem_{datetime.now().timestamp()}_{hash(text) % 10000}"
            self.memory_collection.add(
                ids=[doc_id], embeddings=[embedding],
                documents=[text], metadatas=[metadata],
            )
            return doc_id
        except Exception:
            return ""

    def _recall_similar(self, query: str, k: int = 3) -> List[str]:
        try:
            embedding = self.embeddings.embed_query(query)
            results = self.memory_collection.query(
                query_embeddings=[embedding], n_results=k
            )
            return results.get("documents", [[]])[0]
        except Exception:
            return []

    # ── LangGraph nodes ────────────────────────────────────────────────────
    def _researcher(self, state):
        from phalanx_tools import run_tool
        self.progress(f"[Researcher] Scanning: {state.target}")
        combined = []
        for tool in ["nmap_quick", "http_probe", "whois"]:
            self.progress(f"  Running {tool}…")
            result = run_tool(tool, target=state.target)
            combined.append(f"[{tool}]\n{result.get('output', '')[:2000]}")
            self.skill_mgr.update_skill(tool, success=(result.get("rc", 0) == 0))
        state.research = "\n\n".join(combined)
        doc_id = self._embed_and_store(
            f"Recon on {state.target}:\n{state.research[:1000]}",
            {"type": "recon", "target": state.target},
        )
        if doc_id:
            state.memory_ids.append(doc_id)
        self.soul.append("AUTO_RECON", state.target, state.research[:500])
        return state

    def _planner(self, state):
        HumanMessage = self._HumanMessage
        self.progress("[Planner] Generating attack plan…")
        similar = self._recall_similar(f"plan for {state.target} {state.research[:200]}")
        memory_ctx = "\n".join(similar[-3:]) if similar else "No similar past plans."
        prompt = (
            f"You are an autonomous penetration tester. Based on the recon below, "
            f"create a numbered list of at most 7 concrete attack steps (one tool/command each). "
            f"Only propose steps that are safe for authorized testing.\n\n"
            f"Target: {state.target}\n\nRecon:\n{state.research[:1500]}\n\n"
            f"Past memories:\n{memory_ctx}\n\nOutput ONLY the numbered list."
        )
        response = self.llm.invoke([HumanMessage(content=prompt)])
        lines = response.content.strip().split("\n")
        state.plan = [l.strip() for l in lines if l.strip() and l[0].isdigit()]
        self.progress(f"  Plan ({len(state.plan)} steps): {state.plan}")
        self._embed_and_store(f"Plan for {state.target}: {state.plan}", {"type": "plan"})
        return state

    def _executor(self, state):
        if not state.plan:
            self.progress("[Executor] No steps to execute.")
            return state
        step = state.plan.pop(0)
        self.progress(f"[Executor] Running: {step}")
        output = ""
        try:
            if self.docker:
                container = self.docker.containers.run(
                    "kalilinux/kali-rolling:latest",
                    command=f"bash -c '{step}'",
                    remove=True, network_mode="host",
                    detach=False, stdout=True, stderr=True,
                    timeout=self.config.get("tools", {}).get("timeout", 60),
                )
                output = container.decode("utf-8", errors="ignore")[:2000]
            else:
                parts = step.split()
                if parts and shutil.which(parts[0]):
                    proc = subprocess.run(parts, capture_output=True, text=True, timeout=60)
                    output = (proc.stdout + proc.stderr)[:2000]
                else:
                    output = f"Tool '{parts[0] if parts else step}' not found in PATH."
        except Exception as e:
            output = f"Error: {e}"
        state.results.append({"step": step, "output": output[:1000]})
        self.soul.append("AUTO_EXEC", step, output[:200])
        self._embed_and_store(f"Step: {step}\nResult: {output[:500]}", {"type": "execution"})
        state.step_count += 1
        return state

    def _reflector(self, state) -> Literal["planner", "reporter"]:
        HumanMessage = self._HumanMessage
        self.progress("[Reflector] Evaluating progress…")
        if state.step_count >= state.max_steps:
            self.progress("  Max steps reached. Finishing.")
            return "reporter"
        recent = state.results[-3:] if state.results else []
        ctx = "\n".join([f"Step: {r['step']}\nOutput: {r['output'][:300]}" for r in recent])
        prompt = (
            f"You are an autonomous pentest agent. Based on the latest results, "
            f"decide: CONTINUE more attack steps or FINISH the assessment.\n\n"
            f"Target: {state.target}\nRecent actions:\n{ctx}\n\n"
            f"Answer with ONE word: CONTINUE or FINISH."
        )
        response = self.llm.invoke([HumanMessage(content=prompt)])
        decision = response.content.strip().upper()
        if "FINISH" in decision:
            self.progress("  Reflector: FINISH.")
            return "reporter"
        self.progress("  Reflector: CONTINUE.")
        return "planner"

    def _reporter(self, state):
        HumanMessage = self._HumanMessage
        self.progress("[Reporter] Generating final report…")
        all_outputs = "\n".join(
            [f"Step {i+1}: {r['step']}\n{r['output'][:500]}"
             for i, r in enumerate(state.results)]
        )
        prompt = (
            f"Create a concise penetration test report for {state.target}.\n\n"
            f"Steps and outputs:\n{all_outputs}\n\n"
            f"Include: key vulnerabilities, risk level, recommended fixes, CVEs/ports."
        )
        report_text = self.llm.invoke([HumanMessage(content=prompt)]).content
        self.db.save_summary(state.session_id, all_outputs, report_text, risk_score=0.0)
        self.db.finish_session(state.session_id, "completed")
        self.soul.append("AUTO_REPORT", state.target, report_text[:500])
        state.finished = True
        return state

    def _build_graph(self):
        StateGraph = self._StateGraph
        END = self._END
        PentestState = self._make_state_class()

        workflow = StateGraph(PentestState)
        workflow.add_node("researcher", self._researcher)
        workflow.add_node("planner", self._planner)
        workflow.add_node("executor", self._executor)
        workflow.add_node("reporter", self._reporter)

        workflow.set_entry_point("researcher")
        workflow.add_edge("researcher", "planner")
        workflow.add_edge("planner", "executor")
        # reflector is a conditional router, not a node
        workflow.add_conditional_edges(
            "executor",
            self._reflector,
            {"planner": "planner", "reporter": "reporter"},
        )
        workflow.add_edge("reporter", END)
        return workflow.compile()

    def run(self, target: str, scan_type: str = "full") -> Dict[str, Any]:
        session_id = self.db.create_session(target, scan_type, [])
        PentestState = self._make_state_class()
        initial_state = PentestState(
            target=target,
            session_id=session_id,
            max_steps=self.config.get("pentest", {}).get("max_steps", 30),
        )
        self.graph.invoke(initial_state)
        return self.db.full_report(session_id)
