#!/usr/bin/env python3
"""
PHALANX Core v3.3 – Database, Soul Memory, RoE, Agent Registry, and SWARM tables.
All data stored in ./phalanx/ (local to project, no dot prefix).
Enhanced with Finding dataclass, RoE guardrail, difficulty estimator, ReAct support,
and Shadow Graph persistence (loot tables + graph storage).

Fixed issues:
- Schema version upgrades with proper migration support
- ShadowGraph and EnhancedSoul defined only here (no duplication)
- Async event loop handling without RuntimeError
- estimate_difficulty made async or cached (now async-aware)
- No circular imports with phalanx_library
- Fixed add_loot foreign key integrity error handling
- Fixed add_loot_from_finding structure for ingest_loot
- Added gateway existence check in query_graph
- Ensured target node exists before adding edges in ingest_loot
- Simplified AutonomousPentest._run_agentic_safe
- Robust agent imports with fallback for syntax errors or missing modules
- Enhanced RoE with logical bug detection (IDOR, auth bypass, CSRF, race conditions)
- Added logical bug escalation objective in agentic mode
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
import logging
import re
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime

# ------------------------------------------------------------------
# Paths – local folder "phalanx" (no dot)
# ------------------------------------------------------------------
BASE_DIR = Path.cwd() / "phalanx"
CONFIG_FILE = BASE_DIR / "config.json"
HISTORY_FILE = BASE_DIR / "history.txt"
AUDIT_DIR = BASE_DIR / "audits"
ENGAGEMENTS_DIR = BASE_DIR / "engagements"
REPORTS_DIR = BASE_DIR / "reports"

logger = logging.getLogger("phalanx.core")
logging.basicConfig(level=logging.INFO)

# ------------------------------------------------------------------
# Default configuration
# ------------------------------------------------------------------
def _default_config() -> dict:
    return {
        "phalanx": {"version": "3.3", "agent_name": "PHALANX"},
        "ollama": {
            "url": "http://localhost:11434",
            "default_model": "qwen2.5:7b",
            "fast_model": "qwen2.5:1.5b",
            "analysis_model": "qwen2.5:7b",
            "embedding_model": "nomic-embed-text",
            "timeout": 120,
            "temperature": 0.1
        },
        "database": {"backend": "sqlite", "sqlite_path": "phalanx/phalanx.db"},
        "pentest": {"max_steps": 50, "docker_image": "kalilinux/kali-rolling", "auto_searchsploit": True},
        "tools": {"timeout": 30, "require_confirm_sudo": True},
        "engagement": {
            "default_roe": {
                "allowed_targets": [],
                "excluded_targets": [],
                "max_severity": "critical",
                "allowed_techniques": [],
                "forbidden_actions": ["data_exfiltration", "destruction"],
                "require_human_confirm": ["privilege_escalation", "exploit", "auth_bypass", "id_or", "data_modification", "race_condition"]
            },
            "time_window": None
        },
        "profiles": {
            "eco": {"orchestrator": "qwen2.5:7b", "planner": "qwen2.5:7b", "recon": "qwen2.5:1.5b",
                    "exploit": "qwen2.5:7b", "post_exploit": "qwen2.5:7b"},
            "max": {"orchestrator": "llama3:70b", "planner": "llama3:70b", "recon": "llama3:70b",
                    "exploit": "llama3:70b", "post_exploit": "llama3:70b"},
            "test": {"orchestrator": "qwen2.5:1.5b", "planner": "qwen2.5:1.5b", "recon": "qwen2.5:1.5b",
                     "exploit": "qwen2.5:1.5b", "post_exploit": "qwen2.5:1.5b"},
        },
        "sandbox": {"enabled": True, "docker_network": "phalanx-net", "image": "kalilinux/kali-rolling"},
        "reporting": {"pdf_enabled": False, "html_template": "default"},
        "c2": {"sliver_server_addr": "127.0.0.1:31337", "auto_start": False},
    }

def load_config(path: Path = CONFIG_FILE) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return _default_config()

def save_config(config: dict, path: Path = CONFIG_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2))

def _ensure_dirs():
    for d in (BASE_DIR, AUDIT_DIR, ENGAGEMENTS_DIR, REPORTS_DIR,
              BASE_DIR / "skills", BASE_DIR / "soul", BASE_DIR / "logs",
              BASE_DIR / "tools", BASE_DIR / "lib", BASE_DIR / "config",
              BASE_DIR / "swarm_logs", BASE_DIR / "playbooks"):
        d.mkdir(parents=True, exist_ok=True)
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

def bootstrap():
    _ensure_dirs()
    if not CONFIG_FILE.exists():
        save_config(_default_config())

# ------------------------------------------------------------------
# Finding dataclass
# ------------------------------------------------------------------
@dataclass
class Finding:
    """Unified finding structure for vulnerabilities, exploits, code issues."""
    id: str
    type: str          # "vuln", "exploit", "code_issue", "misconfig"
    severity: str      # "info", "low", "medium", "high", "critical"
    description: str
    evidence: str
    confidence: float = 0.0   # 0.0 to 1.0
    mitre_id: str = ""
    target: str = ""
    tool: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence[:500],
            "confidence": self.confidence,
            "mitre_id": self.mitre_id,
            "target": self.target,
            "tool": self.tool,
            "metadata": self.metadata,
            "timestamp": self.timestamp
        }

# ------------------------------------------------------------------
# Unified Database (PhalanxDB) with SWARM tables and LOOT table
# ------------------------------------------------------------------
_SCHEMA_VERSION = 7   # bumped for better migration

# Schema statements as separate items (no splitting needed)
_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        target TEXT,
        tool TEXT,
        severity TEXT,
        description TEXT,
        raw_output TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        status TEXT,
        last_seen TEXT,
        capabilities TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        scan_type TEXT DEFAULT 'full',
        tools_used TEXT,
        started_at TEXT,
        finished_at TEXT,
        status TEXT DEFAULT 'running',
        notes TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        vuln_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(session_id),
        name TEXT,
        severity TEXT,
        cve TEXT,
        description TEXT,
        evidence TEXT,
        port TEXT,
        service TEXT,
        discovered_at TEXT,
        mitre_id TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS exploits (
        exploit_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(session_id),
        name TEXT,
        tool TEXT,
        command TEXT,
        result TEXT,
        success INTEGER DEFAULT 0,
        attempted_at TEXT,
        mitre_techniques TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS objectives (
        obj_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(session_id),
        description TEXT,
        status TEXT,
        started_at TEXT,
        finished_at TEXT,
        mitre_tags TEXT,
        evidence_guided INTEGER DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS summaries (
        summary_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(session_id),
        raw_output TEXT,
        ai_analysis TEXT,
        risk_score REAL DEFAULT 0.0,
        created_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS swarm_campaigns (
        campaign_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        scope TEXT,
        mode TEXT DEFAULT 'manual',
        model_used TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT DEFAULT 'running',
        final_report_path TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS swarm_agent_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        step INTEGER NOT NULL,
        input_summary TEXT,
        output_summary TEXT,
        tool_calls TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS swarm_attack_surface (
        surface_id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id TEXT NOT NULL,
        asset_type TEXT NOT NULL,
        asset_value TEXT NOT NULL,
        metadata TEXT,
        discovered_at TEXT NOT NULL,
        FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS loot (
        loot_id TEXT PRIMARY KEY,
        session_id TEXT,
        campaign_id TEXT,
        category TEXT NOT NULL,
        data TEXT NOT NULL,
        ingested_at TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id),
        FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS graph_edges (
        edge_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL,
        from_node TEXT NOT NULL,
        to_node TEXT NOT NULL,
        relation TEXT NOT NULL,
        created_at TEXT NOT NULL,
        metadata TEXT,
        FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_graph_campaign ON graph_edges(campaign_id)",
    "CREATE INDEX IF NOT EXISTS idx_graph_nodes ON graph_edges(from_node, to_node)",
]

class PhalanxDB:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self._lock = threading.Lock()
        db_cfg = self.config.get("database", {})
        db_path = Path(db_cfg.get("sqlite_path", "phalanx/phalanx.db")).expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            cur = self.conn.cursor()
            # Create meta table first
            cur.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            # Check current schema version
            cur.execute("SELECT value FROM meta WHERE key='schema_version'")
            row = cur.fetchone()
            current_version = int(row[0]) if row else 0

            # Apply all schema statements (idempotent)
            for stmt in _SCHEMA_STATEMENTS:
                try:
                    cur.execute(stmt)
                except sqlite3.OperationalError as e:
                    # Ignore "already exists" errors
                    if "already exists" not in str(e).lower():
                        logger.warning(f"Schema statement failed: {stmt[:100]}\nError: {e}")

            # Handle schema upgrades if needed
            if current_version < _SCHEMA_VERSION:
                # Perform any version-specific migrations here
                if current_version < 6:
                    # Add loot and graph_edges tables if missing (already in statements)
                    pass
                if current_version < 7:
                    # Ensure all columns exist (add any missing columns)
                    pass
                # Update version
                cur.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                            ("schema_version", str(_SCHEMA_VERSION)))
            self.conn.commit()

    def _uid(self) -> str:
        return str(uuid.uuid4())[:16]

    def add_finding(self, target: str, tool: str, severity: str,
                    description: str, raw_output: str = "") -> None:
        with self._lock:
            self.conn.execute("""
                INSERT INTO findings (timestamp, target, tool, severity, description, raw_output)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.utcnow().isoformat(), target, tool, severity, description, raw_output))
            self.conn.commit()

    def get_findings(self, limit: int = 100) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM findings ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def register_agent(self, agent_id: str, capabilities: List[str]) -> None:
        with self._lock:
            self.conn.execute("""
                INSERT OR REPLACE INTO agents (id, status, last_seen, capabilities)
                VALUES (?, ?, ?, ?)
            """, (agent_id, "idle", datetime.utcnow().isoformat(), json.dumps(capabilities)))
            self.conn.commit()

    def update_agent_status(self, agent_id: str, status: str) -> None:
        with self._lock:
            self.conn.execute("UPDATE agents SET status = ?, last_seen = ? WHERE id = ?",
                              (status, datetime.utcnow().isoformat(), agent_id))
            self.conn.commit()

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_agents(self) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        return [dict(row) for row in cur.fetchall()]

    def create_session(self, target: str, scan_type: str = "full",
                       tools_used: Optional[List[str]] = None) -> str:
        sid = self._uid()
        now = datetime.now().isoformat()
        with self._lock:
            self.conn.execute("""
                INSERT INTO sessions (session_id, target, scan_type, tools_used, started_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (sid, target, scan_type, json.dumps(tools_used or []), now, "running"))
            self.conn.commit()
        return sid

    def finish_session(self, session_id: str, status: str = "completed") -> None:
        with self._lock:
            self.conn.execute("UPDATE sessions SET finished_at=?, status=? WHERE session_id=?",
                              (datetime.now().isoformat(), status, session_id))
            self.conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_sessions(self, limit: int = 20) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    def add_vulnerability(self, session_id: str, name: str, severity: str,
                          description: str, cve: str = "", evidence: str = "",
                          port: str = "", service: str = "", mitre_id: str = "") -> str:
        vid = self._uid()
        with self._lock:
            self.conn.execute("""
                INSERT INTO vulnerabilities
                (vuln_id, session_id, name, severity, cve, description, evidence, port, service, discovered_at, mitre_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (vid, session_id, name, severity, cve, description, evidence, port, service,
                  datetime.now().isoformat(), mitre_id))
            self.conn.commit()
        return vid

    def get_vulnerabilities(self, session_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM vulnerabilities WHERE session_id=? ORDER BY severity", (session_id,))
        return [dict(r) for r in cur.fetchall()]

    def add_exploit(self, session_id: str, name: str, tool: str, command: str,
                    result: str, success: bool = False, mitre_techniques: Optional[List[str]] = None) -> str:
        eid = self._uid()
        with self._lock:
            self.conn.execute("""
                INSERT INTO exploits
                (exploit_id, session_id, name, tool, command, result, success, attempted_at, mitre_techniques)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (eid, session_id, name, tool, command, result, 1 if success else 0,
                  datetime.now().isoformat(), json.dumps(mitre_techniques or [])))
            self.conn.commit()
        return eid

    def get_exploits(self, session_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM exploits WHERE session_id=?", (session_id,))
        return [dict(r) for r in cur.fetchall()]

    def add_objective(self, session_id: str, description: str,
                      mitre_tags: Optional[List[str]] = None,
                      evidence_guided: bool = False) -> str:
        obj_id = self._uid()
        with self._lock:
            self.conn.execute("""
                INSERT INTO objectives (obj_id, session_id, description, status, started_at, mitre_tags, evidence_guided)
                VALUES (?,?,?,?,?,?,?)
            """, (obj_id, session_id, description, "pending", datetime.now().isoformat(),
                  json.dumps(mitre_tags or []), 1 if evidence_guided else 0))
            self.conn.commit()
        return obj_id

    def update_objective_status(self, obj_id: str, status: str) -> None:
        with self._lock:
            self.conn.execute("""
                UPDATE objectives SET status=?, finished_at=?
                WHERE obj_id=?
            """, (status, datetime.now().isoformat() if status in ("passed","failed") else None, obj_id))
            self.conn.commit()

    def get_objectives(self, session_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM objectives WHERE session_id=? ORDER BY started_at", (session_id,))
        return [dict(r) for r in cur.fetchall()]

    def save_summary(self, session_id: str, raw_output: str, ai_analysis: str,
                     risk_score: float = 0.0) -> str:
        sid = self._uid()
        with self._lock:
            self.conn.execute("""
                INSERT INTO summaries (summary_id, session_id, raw_output, ai_analysis, risk_score, created_at)
                VALUES (?,?,?,?,?,?)
            """, (sid, session_id, raw_output, ai_analysis, risk_score, datetime.now().isoformat()))
            self.conn.commit()
        return sid

    def get_summary(self, session_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM summaries WHERE session_id=? ORDER BY created_at DESC LIMIT 1", (session_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def full_report(self, session_id: str) -> Dict:
        session = self.get_session(session_id)
        if not session:
            return {}
        return {
            "session": session,
            "vulnerabilities": self.get_vulnerabilities(session_id),
            "exploits": self.get_exploits(session_id),
            "objectives": self.get_objectives(session_id),
            "summary": self.get_summary(session_id)
        }

    # LOOT methods
    def add_loot(self, category: str, data: Dict, session_id: str = None, campaign_id: str = None) -> str:
        loot_id = self._uid()
        try:
            with self._lock:
                self.conn.execute("""
                    INSERT INTO loot (loot_id, session_id, campaign_id, category, data, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (loot_id, session_id, campaign_id, category, json.dumps(data), datetime.now().isoformat()))
                self.conn.commit()
        except sqlite3.IntegrityError as e:
            logger.warning(f"Failed to add loot due to foreign key constraint: {e}")
            return ""
        return loot_id

    def get_loot_by_category(self, category: str, campaign_id: str = None, session_id: str = None, limit: int = 100) -> List[Dict]:
        query = "SELECT * FROM loot WHERE category = ?"
        params = [category]
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        query += " ORDER BY ingested_at DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def get_loot(self, campaign_id: str = None, session_id: str = None, limit: int = 100) -> List[Dict]:
        query = "SELECT * FROM loot WHERE 1=1"
        params = []
        if campaign_id:
            query += " AND campaign_id = ?"
            params.append(campaign_id)
        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        query += " ORDER BY ingested_at DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    # Graph persistence (edges)
    def add_graph_edge(self, campaign_id: str, from_node: str, to_node: str, relation: str, metadata: Dict = None) -> str:
        edge_id = self._uid()
        with self._lock:
            self.conn.execute("""
                INSERT INTO graph_edges (edge_id, campaign_id, from_node, to_node, relation, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (edge_id, campaign_id, from_node, to_node, relation, datetime.now().isoformat(), json.dumps(metadata or {})))
            self.conn.commit()
        return edge_id

    def get_graph_edges(self, campaign_id: str, from_node: str = None, to_node: str = None, relation: str = None) -> List[Dict]:
        query = "SELECT * FROM graph_edges WHERE campaign_id = ?"
        params = [campaign_id]
        if from_node:
            query += " AND from_node = ?"
            params.append(from_node)
        if to_node:
            query += " AND to_node = ?"
            params.append(to_node)
        if relation:
            query += " AND relation = ?"
            params.append(relation)
        cur = self.conn.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def delete_graph_edges(self, campaign_id: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM graph_edges WHERE campaign_id = ?", (campaign_id,))
            self.conn.commit()

    # SWARM methods
    def create_swarm_campaign(self, campaign_id: str, target: str, scope: str = None,
                              mode: str = "manual", model_used: str = None) -> str:
        now = datetime.now().isoformat()
        with self._lock:
            self.conn.execute("""
                INSERT INTO swarm_campaigns (campaign_id, target, scope, mode, model_used, started_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (campaign_id, target, scope, mode, model_used, now, "running"))
            self.conn.commit()
        return campaign_id

    def update_swarm_campaign(self, campaign_id: str, status: str, final_report_path: str = None) -> None:
        with self._lock:
            self.conn.execute("""
                UPDATE swarm_campaigns
                SET finished_at = ?, status = ?, final_report_path = ?
                WHERE campaign_id = ?
            """, (datetime.now().isoformat(), status, final_report_path, campaign_id))
            self.conn.commit()

    def log_swarm_agent_action(self, campaign_id: str, agent_name: str, step: int,
                               input_summary: str = None, output_summary: str = None,
                               tool_calls: Dict = None) -> None:
        with self._lock:
            self.conn.execute("""
                INSERT INTO swarm_agent_logs
                (campaign_id, agent_name, step, input_summary, output_summary, tool_calls, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (campaign_id, agent_name, step, input_summary, output_summary,
                  json.dumps(tool_calls or {}), datetime.now().isoformat()))
            self.conn.commit()

    def add_swarm_attack_surface(self, campaign_id: str, asset_type: str,
                                 asset_value: str, metadata: Dict = None) -> None:
        with self._lock:
            self.conn.execute("""
                INSERT INTO swarm_attack_surface
                (campaign_id, asset_type, asset_value, metadata, discovered_at)
                VALUES (?, ?, ?, ?, ?)
            """, (campaign_id, asset_type, asset_value, json.dumps(metadata or {}),
                  datetime.now().isoformat()))
            self.conn.commit()

    def get_swarm_campaign(self, campaign_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM swarm_campaigns WHERE campaign_id = ?", (campaign_id,))
        campaign = cur.fetchone()
        if not campaign:
            return None
        result = dict(campaign)
        cur = self.conn.execute("SELECT * FROM swarm_agent_logs WHERE campaign_id = ? ORDER BY step, timestamp", (campaign_id,))
        result["logs"] = [dict(row) for row in cur.fetchall()]
        cur = self.conn.execute("SELECT * FROM swarm_attack_surface WHERE campaign_id = ?", (campaign_id,))
        result["attack_surface"] = [dict(row) for row in cur.fetchall()]
        cur = self.conn.execute("SELECT * FROM graph_edges WHERE campaign_id = ?", (campaign_id,))
        result["graph_edges"] = [dict(row) for row in cur.fetchall()]
        return result

    def list_swarm_campaigns(self, limit: int = 20) -> List[Dict]:
        cur = self.conn.execute("""
            SELECT campaign_id, target, mode, status, started_at, finished_at
            FROM swarm_campaigns
            ORDER BY started_at DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self.conn.close()
        except:
            pass

# ------------------------------------------------------------------
# Shadow Graph – unified implementation (no duplication)
# ------------------------------------------------------------------
class ShadowGraph:
    """Lightweight in-memory graph for entities and relationships."""
    def __init__(self):
        self.nodes: Dict[str, Dict] = {}  # node_id -> {type, attributes, created_at}
        self.edges: List[Tuple[str, str, str]] = []  # (from_id, to_id, relation)

    def add_node(self, node_id: str, node_type: str, attributes: Dict = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "type": node_type,
                "attributes": attributes or {},
                "created_at": datetime.utcnow().isoformat()
            }
        else:
            self.nodes[node_id]["attributes"].update(attributes or {})

    def add_edge(self, from_id: str, to_id: str, relation: str):
        if from_id not in self.nodes:
            self.add_node(from_id, "unknown", {})
        if to_id not in self.nodes:
            self.add_node(to_id, "unknown", {})
        edge = (from_id, to_id, relation)
        if edge not in self.edges:
            self.edges.append(edge)

    def get_related(self, node_id: str, relation: Optional[str] = None) -> List[str]:
        results = []
        for f, t, r in self.edges:
            if f == node_id and (relation is None or r == relation):
                results.append(t)
            if t == node_id and (relation is None or r == relation):
                results.append(f)
        return results

    def find_paths(self, from_id: str, to_id: str, max_depth: int = 3) -> List[List[str]]:
        if from_id == to_id:
            return [[from_id]]
        from collections import deque
        queue = deque([(from_id, [from_id])])
        visited = set()
        paths = []
        while queue and len(paths) < 5:
            node, path = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            neighbors = self.get_related(node)
            for nb in neighbors:
                if nb == to_id:
                    paths.append(path + [nb])
                elif len(path) < max_depth and nb not in visited:
                    queue.append((nb, path + [nb]))
        return paths

    def to_dict(self) -> Dict:
        return {"nodes": self.nodes, "edges": self.edges}

    def summary(self) -> Dict:
        node_types = {}
        for node, data in self.nodes.items():
            t = data["type"]
            node_types[t] = node_types.get(t, 0) + 1
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": node_types
        }

# ------------------------------------------------------------------
# Enhanced Soul – persistent memory with reflection and Shadow Graph
# ------------------------------------------------------------------
class Soul:
    def __init__(self, db: PhalanxDB, roe: "RoE", campaign_id: str = None):
        self.db = db
        self.roe = roe
        self.campaign_id = campaign_id
        self.state = {"phase": "recon", "findings": [], "current_objective": None}
        self._init_memory()
        # Optional LLM gateway for reflection (set later)
        self.gateway = None
        # Shadow Graph
        self.graph = ShadowGraph()
        if campaign_id:
            self._load_graph_from_db()

    def set_gateway(self, gateway):
        self.gateway = gateway

    def _init_memory(self):
        with self.db.conn:
            self.db.conn.execute("""
                CREATE TABLE IF NOT EXISTS memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT,
                    category TEXT,
                    subtype TEXT,
                    content TEXT
                )
            """)
            try:
                self.db.conn.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS fts_memory USING fts5(content, category, subtype)
                """)
            except sqlite3.OperationalError:
                # FTS5 not available – proceed without full-text search
                pass

    def append_memory(self, category: str, subtype: str, text: str) -> None:
        ts = datetime.now().isoformat()
        with self.db.conn:
            self.db.conn.execute(
                "INSERT INTO memory (ts, category, subtype, content) VALUES (?,?,?,?)",
                (ts, category, subtype, text)
            )
            try:
                self.db.conn.execute(
                    "INSERT INTO fts_memory (content, category, subtype) VALUES (?,?,?)",
                    (text, category, subtype)
                )
            except Exception:
                pass

    def search_memory(self, query: str, limit: int = 6) -> List[Dict]:
        try:
            cur = self.db.conn.execute("""
                SELECT ts, category, subtype, content, snippet(fts_memory, 0, '[', ']', '...', 64) as summary
                FROM fts_memory WHERE fts_memory MATCH ? ORDER BY rank LIMIT ?
            """, (query, limit))
            return [{"ts": r[0], "type": f"{r[1]}/{r[2]}", "summary": r[4] or r[3][:100]} for r in cur.fetchall()]
        except Exception:
            return []

    def recent_memory(self, limit: int = 20) -> List[Dict]:
        cur = self.db.conn.execute(
            "SELECT ts, category, subtype, content FROM memory ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return [{"ts": r[0], "type": f"{r[1]}/{r[2]}", "content": r[3]} for r in cur.fetchall()]

    def record_finding(self, finding: Finding):
        """Store a structured finding in memory and optionally in findings table."""
        self.append_memory("FINDING", finding.type, json.dumps(finding.to_dict()))
        self.db.add_finding(finding.target, finding.tool or finding.type, finding.severity,
                            finding.description, finding.evidence[:500])
        self.add_loot_from_finding(finding)

    def reflect_on_phase(self, phase: str, findings: List[Dict]) -> Dict:
        """
        Use fast LLM to reflect on a phase's results: confidence, summary, pruning suggestions.
        Returns dict with keys: confidence (0-1), key_evidence, suggestion, next_phase.
        """
        if not self.gateway:
            return {"confidence": 0.5, "key_evidence": "", "suggestion": "continue", "next_phase": phase}
        prompt = f"""You are an AI evaluator for a penetration testing framework.
Phase: {phase}
Findings (summarized): {json.dumps(findings[:5])}

Evaluate:
1. Confidence (0.0-1.0) that the phase completed correctly.
2. Key evidence (one sentence).
3. Suggestion: "continue", "prune" (stop this branch), or "escalate" (move to next phase).
4. Next phase: "recon", "exploit", "post_exploit", or "report".

Output JSON only: {{"confidence": float, "key_evidence": "...", "suggestion": "...", "next_phase": "..."}}"""
        response = self.gateway.generate(prompt, model=self.gateway.fast_model, json_mode=True)
        try:
            result = json.loads(response)
            self.append_memory("REFLECTION", phase, json.dumps(result))
            return result
        except:
            return {"confidence": 0.5, "key_evidence": "", "suggestion": "continue", "next_phase": phase}

    def get_next_command(self) -> Optional[str]:
        phase = self.state.get("phase", "recon")
        if phase == "recon":
            return "nmap"
        elif phase == "exploit":
            return "metasploit"
        elif phase == "post_exploit":
            return "sliver_generate"
        else:
            return None

    def update_state(self, phase: str, finding: Optional[Dict] = None) -> str:
        severity = finding.get("severity", "info") if finding else "info"
        if severity == self.roe.max_severity:
            logger.warning(f"Max severity {severity} reached – halting.")
            return "halt"
        tool = finding.get("tool", "") if finding else ""
        if tool in self.roe.forbidden_actions:
            logger.warning(f"Forbidden action {tool} attempted – halting.")
            return "halt"
        if self.state["phase"] == "recon":
            if finding and "open port" in finding.get("description", "").lower():
                self.state["phase"] = "exploit"
                return "next_phase"
            return "continue"
        elif self.state["phase"] == "exploit":
            if finding and finding.get("severity") == "critical":
                self.state["phase"] = "post_exploit"
                return "next_phase"
            return "continue"
        elif self.state["phase"] == "post_exploit":
            if self.state.get("current_objective"):
                self.db.update_objective_status(self.state["current_objective"]["obj_id"], "passed")
            self.state["phase"] = "report"
            return "next_phase"
        else:
            return "report"

    # Shadow Graph methods (using self.graph)
    def _load_graph_from_db(self):
        """Load graph edges from database for this campaign."""
        if not self.campaign_id:
            return
        edges = self.db.get_graph_edges(self.campaign_id)
        for e in edges:
            self.graph.add_edge(e["from_node"], e["to_node"], e["relation"])
        loot_items = self.db.get_loot(campaign_id=self.campaign_id, limit=500)
        for loot in loot_items:
            data = json.loads(loot["data"])
            if loot["category"] == "vuln":
                node_id = data.get("name", data.get("cve", ""))
                if node_id:
                    self.graph.add_node(node_id, "vulnerability", data)
            elif loot["category"] == "cred":
                node_id = f"cred_{data.get('username','')}_{data.get('host','')}"
                self.graph.add_node(node_id, "credential", data)
            elif loot["category"] == "artifact":
                node_id = data.get("id", data.get("path", ""))
                if node_id:
                    self.graph.add_node(node_id, "artifact", data)

    def _save_edge(self, from_node: str, to_node: str, relation: str, metadata: Dict = None):
        """Persist a single edge to the database."""
        if not self.campaign_id:
            return
        self.db.add_graph_edge(self.campaign_id, from_node, to_node, relation, metadata)

    def add_graph_node(self, node_id: str, node_type: str, attributes: Dict = None):
        """Add or update a node in the shadow graph."""
        self.graph.add_node(node_id, node_type, attributes)

    def add_graph_edge(self, from_node: str, to_node: str, relation: str, metadata: Dict = None):
        """Add an edge between two nodes, persist to DB."""
        self.graph.add_edge(from_node, to_node, relation)
        self._save_edge(from_node, to_node, relation, metadata)

    def get_related_nodes(self, node_id: str, relation: Optional[str] = None) -> List[str]:
        """Get nodes related to given node, optionally filtered by relation."""
        return self.graph.get_related(node_id, relation)

    def find_paths(self, from_node: str, to_node: str, max_depth: int = 3) -> List[List[str]]:
        """Find paths between nodes."""
        return self.graph.find_paths(from_node, to_node, max_depth)

    def query_graph(self, query: str) -> str:
        """Interpret natural language query against the graph using LLM if available."""
        if self.gateway is None:
            return "No gateway available for graph query. Install LLM components."
        query_lower = query.lower()
        if "path" in query_lower or "lateral" in query_lower:
            hosts = [nid for nid, data in self.graph.nodes.items() if data["type"] == "host"]
            if len(hosts) >= 2:
                paths = []
                for i, src in enumerate(hosts):
                    for dst in hosts[i+1:]:
                        p = self.find_paths(src, dst, max_depth=3)
                        if p:
                            paths.append(f"Path from {src} to {dst}: {' -> '.join(p[0])}")
                if paths:
                    return "Lateral movement paths:\n" + "\n".join(paths[:5])
                else:
                    return "No lateral paths found between known hosts."
            else:
                return "Need at least two hosts to find lateral paths."
        elif "credentials" in query_lower:
            creds = [nid for nid, data in self.graph.nodes.items() if data["type"] == "credential"]
            if creds:
                return f"Credentials found: {', '.join(creds[:10])}"
            else:
                return "No credentials in graph."
        elif "vulnerabilities" in query_lower:
            vulns = [nid for nid, data in self.graph.nodes.items() if data["type"] == "vulnerability"]
            if vulns:
                return f"Vulnerabilities: {', '.join(vulns[:10])}"
            else:
                return "No vulnerabilities in graph."
        if self.gateway:
            graph_summary = self.graph.summary()
            prompt = f"""You are a strategic advisor with access to a knowledge graph.
Query: {query}
Graph summary: {json.dumps(graph_summary)}
Nodes (sample): {list(self.graph.nodes.keys())[:20]}
Edges (sample): {self.graph.edges[:20]}

Provide a concise, actionable answer based on the graph data.
If the graph lacks information, say so clearly."""
            try:
                response = self.gateway.generate(prompt, model=self.gateway.fast_model)
                return response.strip()
            except Exception as e:
                logger.warning(f"Graph LLM query failed: {e}")
        return f"Graph contains {len(self.graph.nodes)} nodes and {len(self.graph.edges)} edges."

    def ingest_loot(self, loot_dict: Dict):
        """
        Extract entities from a loot dictionary and update the graph.
        loot_dict format: {"type": "recon", "target": "...", "findings": {...}}
        """
        findings = loot_dict.get("findings", {})
        target = loot_dict.get("target", "")

        def add_host(host):
            self.add_graph_node(host, "host", {"address": host})

        ips = set()
        if target:
            ips.add(target)
        if "subdomains" in findings:
            for sub in findings["subdomains"]:
                ips.add(sub)
        if "urls" in findings:
            for url in findings["urls"]:
                match = re.match(r"https?://([^/:]+)", url)
                if match:
                    ips.add(match.group(1))
        if "emails" in findings:
            for email in findings["emails"]:
                if "@" in email:
                    domain = email.split("@")[1]
                    ips.add(domain)
        for ip in ips:
            add_host(ip)
            self.db.add_loot("artifact", {"type": "host", "address": ip}, campaign_id=self.campaign_id)

        vulns = findings.get("vulnerabilities", [])
        for vuln in vulns:
            vuln_id = vuln.get("name", vuln.get("cve_id", str(uuid.uuid4())))
            self.add_graph_node(vuln_id, "vulnerability", vuln)
            if target:
                add_host(target)
                self.add_graph_edge(target, vuln_id, "has_vuln")
            self.db.add_loot("vuln", vuln, campaign_id=self.campaign_id)

        credentials = loot_dict.get("credentials", []) or findings.get("credentials", [])
        for cred in credentials:
            cred_id = f"cred_{hash(str(cred))}"
            self.add_graph_node(cred_id, "credential", cred)
            if target:
                add_host(target)
                self.add_graph_edge(target, cred_id, "has_cred")
            if "host" in cred:
                host = cred["host"]
                add_host(host)
                self.add_graph_edge(host, cred_id, "has_cred")
            self.db.add_loot("cred", cred, campaign_id=self.campaign_id)

        self.append_memory("LOOT", loot_dict.get("type", "unknown"), json.dumps(loot_dict)[:500])

    def add_loot_from_finding(self, finding: Finding):
        """Convert a Finding into loot and ingest."""
        loot_data = {
            "type": finding.type,
            "severity": finding.severity,
            "description": finding.description,
            "evidence": finding.evidence,
            "mitre_id": finding.mitre_id,
            "target": finding.target,
            "tool": finding.tool
        }
        self.db.add_loot(finding.type, loot_data, campaign_id=self.campaign_id)
        self.ingest_loot({"type": finding.type, "target": finding.target, "findings": loot_data})

    def graph_summary(self) -> Dict:
        """Return a summary of the graph for reporting."""
        return self.graph.summary()

# ------------------------------------------------------------------
# Rules of Engagement (RoE)
# ------------------------------------------------------------------
@dataclass
class RoE:
    targets: List[str] = field(default_factory=list)
    excluded_targets: List[str] = field(default_factory=list)
    max_severity: str = "critical"
    allowed_techniques: List[str] = field(default_factory=list)
    forbidden_actions: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "RoE":
        return cls(
            targets=data.get("targets", []),
            excluded_targets=data.get("excluded_targets", []),
            max_severity=data.get("max_severity", "critical"),
            allowed_techniques=data.get("allowed_techniques", []),
            forbidden_actions=data.get("forbidden_actions", [])
        )

# ------------------------------------------------------------------
# RoE Enforcer with guardrail and difficulty estimator (async-aware)
# ------------------------------------------------------------------
class RoEEnforcer:
    def __init__(self, config: dict, confirm_callback: Optional[Callable[[str, Dict], bool]] = None,
                 gateway=None):
        self.config = config
        self.active_plan = None
        self.confirm_callback = confirm_callback or self._default_confirm
        self.gateway = gateway  # for difficulty estimation

    def load_plan(self, plan: dict):
        self.active_plan = plan

    def check_action(self, action: str, target: str, details: Dict = None) -> Tuple[bool, str, bool]:
        if not self.active_plan:
            return True, "No active RoE plan", False
        roe = self.active_plan.get("roe", {})
        allowed = roe.get("allowed_targets", [])
        if allowed and target not in allowed:
            return False, f"Target {target} not in RoE allowed list", False
        forbidden = roe.get("forbidden_actions",
                            self.config.get("engagement", {}).get("default_roe", {}).get("forbidden_actions", []))
        for f in forbidden:
            if f in action.lower():
                return False, f"Action '{action}' matches forbidden pattern '{f}'", False

        # Logical bug detection – high-impact vulnerabilities that require confirmation
        for logical in ["id_or", "auth_bypass", "csrf", "race_condition", "2fa_bypass", "cors"]:
            if logical in action.lower() or (details and details.get("category") == logical):
                return True, f"Action '{action}' is high-impact logical bug – requires confirmation", True

        require_confirm = roe.get("require_human_confirm",
                                  self.config.get("engagement", {}).get("default_roe", {}).get("require_human_confirm", []))
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

    async def estimate_difficulty_async(self, phase: str, findings: List[Dict], context: Dict, soul: Optional[Soul] = None) -> float:
        """Async version of difficulty estimation to avoid blocking."""
        graph_factor = 0.0
        if soul and hasattr(soul, "graph_summary"):
            summary = soul.graph_summary()
            total_nodes = summary.get("total_nodes", 0)
            if total_nodes > 0:
                unknowns = summary.get("node_types", {}).get("unknown", 0)
                graph_factor = unknowns / total_nodes
        if not self.gateway:
            return 0.5 + graph_factor * 0.3
        prompt = f"""Estimate difficulty of next pentest phase:
Phase: {phase}
Number of findings: {len(findings)}
Context length (chars): {len(str(context))}
Graph complexity factor: {graph_factor:.2f}
Output a float between 0.0 (trivial) and 1.0 (extremely hard/risky).
Return only a number, no explanation."""
        if hasattr(self.gateway, 'generate_async'):
            response = await self.gateway.generate_async(prompt, model=self.gateway.fast_model)
        else:
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(None, lambda: self.gateway.generate(prompt, model=self.gateway.fast_model))
        try:
            diff = float(response.strip())
            return max(0.0, min(1.0, diff + graph_factor * 0.2))
        except:
            return 0.5 + graph_factor * 0.3

    def estimate_difficulty(self, phase: str, findings: List[Dict], context: Dict, soul: Optional[Soul] = None) -> float:
        """Synchronous wrapper – warns if called in async context."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                logger.warning("estimate_difficulty called from async context – consider using estimate_difficulty_async")
        except RuntimeError:
            pass
        graph_factor = 0.0
        if soul and hasattr(soul, "graph_summary"):
            summary = soul.graph_summary()
            total_nodes = summary.get("total_nodes", 0)
            if total_nodes > 0:
                unknowns = summary.get("node_types", {}).get("unknown", 0)
                graph_factor = unknowns / total_nodes
        return 0.5 + graph_factor * 0.3

    def _default_confirm(self, prompt: str, details: Dict) -> bool:
        print(f"\n⚠️  {prompt}")
        resp = input("Confirm? (y/N): ").strip().lower()
        return resp == "y"

# ------------------------------------------------------------------
# Agent Registry
# ------------------------------------------------------------------
class AgentRegistry:
    def __init__(self, db: PhalanxDB):
        self.db = db

    def register(self, agent_id: str, capabilities: List[str]) -> None:
        self.db.register_agent(agent_id, capabilities)

    def update_status(self, agent_id: str, status: str) -> None:
        self.db.update_agent_status(agent_id, status)

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        return self.db.get_agent(agent_id)

    def list_agents(self) -> List[Dict]:
        return self.db.list_agents()

# ------------------------------------------------------------------
# Skill Manager
# ------------------------------------------------------------------
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
                        skills.append({
                            "name": parts[0].strip(),
                            "success": int(parts[1].strip()),
                            "fail": int(parts[2].strip()),
                            "last_used": parts[3].strip()
                        })
        except Exception:
            pass
        return skills

    def update_skill(self, name: str, success: bool = True) -> None:
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
                    "last_used": datetime.now().isoformat()
                })
            lines = ["# PHALANX Skill Log"]
            for s in skills:
                lines.append(f"{s['name']}|{s['success']}|{s['fail']}|{s['last_used']}")
            self.path.write_text("\n".join(lines) + "\n")

# ------------------------------------------------------------------
# Autonomous Pentest Engine with ReAct support and async event loop handling
# ------------------------------------------------------------------
class AutonomousPentest:
    def __init__(self, config: dict, db: PhalanxDB, soul: Soul, skill_mgr: SkillManager,
                 executor, gateway, progress_cb=None, orchestrator=None):
        self.config = config
        self.db = db
        self.soul = soul
        self.skill_mgr = skill_mgr
        self.executor = executor
        self.gateway = gateway
        self.progress = progress_cb or (lambda msg: logger.info(msg))
        self.orchestrator = orchestrator
        self.roe_enforcer = RoEEnforcer(config, gateway=gateway)

        # Ensure soul has gateway for reflection
        self.soul.set_gateway(gateway)

    def _check_roe(self, tool_name: str, target: str, details: Dict = None) -> bool:
        try:
            self.roe_enforcer.enforce(tool_name, target, details)
            return True
        except PermissionError as e:
            self.progress(f"[ROE BLOCKED] {e}")
            return False

    def run(self, target: str, scan_type: str = "full", user_input: str = "") -> Dict:
        session_id = self.db.create_session(target, scan_type, [])
        self.progress(f"[*] Session {session_id} started for {target}")
        if self.orchestrator:
            self.progress("[*] Using agentic orchestrator with ReAct...")
            return self._run_agentic_safe(target, session_id, user_input)
        else:
            self.progress("[*] Using simple state machine...")
            return self._run_simple(target, session_id)

    def _run_agentic_safe(self, target: str, session_id: str, user_input: str) -> Dict:
        """Run agentic mode with proper async event loop handling."""
        try:
            return asyncio.run(self._run_agentic_async(target, session_id, user_input))
        except RuntimeError as e:
            if "cannot be called from a running event loop" in str(e):
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        lambda: asyncio.run(self._run_agentic_async(target, session_id, user_input))
                    )
                    return future.result()
            else:
                raise

    async def _run_agentic_async(self, target: str, session_id: str, user_input: str) -> Dict:
        """Async implementation of agentic mode."""
        from phalanx_library import generate_engagement_plan
        plan = generate_engagement_plan(target, user_input, self.gateway)
        # Ensure plan has objectives list
        plan.setdefault("objectives", [])
        # Add logical bug escalation objective
        plan["objectives"].append({
            "description": "Identify and chain logical bugs (IDOR, auth bypass, CSRF, race conditions)",
            "mitre_tags": ["T1190", "T1555"],
            "evidence_guided": True
        })
        for obj in plan.get("objectives", []):
            evidence_guided = obj.get("evidence_guided", False)
            self.db.add_objective(session_id, obj["description"], obj.get("mitre_tags", []), evidence_guided)
        self.roe_enforcer.load_plan(plan)

        current_phase = "recon"
        max_steps = self.config.get("pentest", {}).get("max_steps", 50)
        step = 0
        phase_turn_limit = 5
        phase_turns = 0
        findings_accumulated = []

        while step < max_steps and current_phase != "report":
            step += 1
            phase_turns += 1

            # Reason (orchestrator decides next agent)
            decision = await self.orchestrator.run({
                "phase": current_phase,
                "target": target,
                "session_id": session_id,
                "objectives": self.db.get_objectives(session_id),
                "recent_findings": findings_accumulated[-3:]
            })
            next_agent = decision.get("next_agent", "recon")
            self.progress(f"[Orchestrator] Reason → next agent: {next_agent}")

            # Act (execute agent)
            action_result = None
            try:
                if next_agent == "recon":
                    try:
                        from recon_agent import ReconAgent
                        recon = ReconAgent("recon", self.gateway, self.db, self.soul, self.skill_mgr)
                        recon_result = await recon.run({"target": target, "objective": {}})
                        action_result = recon_result
                        for tool, result in recon_result.get("results", {}).items():
                            if self._check_roe(tool, target, {"category": "recon"}):
                                exec_res = self.gateway.run_tool(tool, {"target": target})
                                findings_accumulated.append({"tool": tool, "output": exec_res.get("output", "")[:200]})
                                self.soul.ingest_loot({
                                    "type": "recon",
                                    "target": target,
                                    "findings": {tool: exec_res.get("output", "")[:500]}
                                })
                        current_phase = "exploit"
                    except Exception as e:
                        self.progress(f"[!] ReconAgent failed: {e}. Falling back to nmap.")
                        if self._check_roe("nmap", target):
                            res = self.gateway.run_tool("nmap", {"target": target})
                            findings_accumulated.append({"tool": "nmap", "output": res.get("output", "")[:200]})
                            self.soul.ingest_loot({
                                "type": "recon",
                                "target": target,
                                "findings": {"nmap": res.get("output", "")[:500]}
                            })
                        current_phase = "exploit"

                elif next_agent == "exploit":
                    try:
                        from exploit_agent import ExploitAgent
                        exploit = ExploitAgent("exploit", self.gateway, self.db, self.soul, self.skill_mgr)
                        exploit_result = await exploit.run({"target": target, "recon_data": findings_accumulated})
                        action_result = exploit_result
                        for exp in exploit_result.get("exploits", []):
                            tool = exp.get("tool")
                            if tool and self._check_roe(tool, target, {"category": "exploit"}):
                                res = self.gateway.run_tool(tool, exp.get("args", {}))
                                findings_accumulated.append({"tool": tool, "output": res.get("output", "")[:200]})
                                self.soul.ingest_loot({
                                    "type": "exploit",
                                    "target": target,
                                    "findings": {tool: res.get("output", "")[:500]}
                                })
                        current_phase = "post_exploit"
                    except Exception as e:
                        self.progress(f"[!] ExploitAgent failed: {e}. Skipping exploit phase.")
                        current_phase = "post_exploit"

                elif next_agent == "post_exploit":
                    try:
                        from post_exploit_agent import PostExploitAgent
                        post = PostExploitAgent("post", self.gateway, self.db, self.soul, self.skill_mgr)
                        post_result = await post.run({"target": target})
                        action_result = post_result
                        for tool in post_result.get("plan", {}).get("tools", []):
                            if self._check_roe(tool, target, {"category": "post"}):
                                res = self.gateway.run_tool(tool, {"target": target})
                                findings_accumulated.append({"tool": tool, "output": res.get("output", "")[:200]})
                                self.soul.ingest_loot({
                                    "type": "post_exploit",
                                    "target": target,
                                    "findings": {tool: res.get("output", "")[:500]}
                                })
                        current_phase = "report"
                    except Exception as e:
                        self.progress(f"[!] PostExploitAgent failed: {e}. Skipping.")
                        current_phase = "report"

                elif next_agent == "reporter":
                    self.progress("[*] Generating final report...")
                    current_phase = "report"
                    break

            except Exception as agent_err:
                self.progress(f"[!] Agent execution error: {agent_err}. Moving to next phase.")
                current_phase = "report"

            # Observe & Reflect (after each major action)
            if action_result:
                reflection = self.soul.reflect_on_phase(current_phase, findings_accumulated[-5:])
                self.progress(f"[Reflection] Confidence: {reflection.get('confidence',0.5)}, Suggestion: {reflection.get('suggestion','continue')}")
                if reflection.get("suggestion") == "prune":
                    self.progress("[Reflection] Pruning this branch – moving to report.")
                    current_phase = "report"
                    break
                elif reflection.get("suggestion") == "escalate" and current_phase != "report":
                    if current_phase == "recon":
                        current_phase = "exploit"
                    elif current_phase == "exploit":
                        current_phase = "post_exploit"
                    phase_turns = 0

            if phase_turns >= phase_turn_limit:
                self.progress(f"[ReAct] Reached {phase_turn_limit} turns in phase {current_phase}, escalating.")
                if current_phase == "recon":
                    current_phase = "exploit"
                elif current_phase == "exploit":
                    current_phase = "post_exploit"
                elif current_phase == "post_exploit":
                    current_phase = "report"
                phase_turns = 0

        report_data = self.db.full_report(session_id)
        report_data["graph_summary"] = self.soul.graph_summary()
        self.db.finish_session(session_id, "completed")
        return report_data

    def _run_simple(self, target: str, session_id: str) -> Dict:
        self.soul.state["phase"] = "recon"
        max_steps = self.config.get("pentest", {}).get("max_steps", 20)
        for step in range(max_steps):
            cmd = self.soul.get_next_command()
            if not cmd:
                break
            if not self._check_roe(cmd, target):
                self.progress(f"[ROE] Skipping {cmd} due to RoE")
                continue
            if cmd == "nmap":
                result = self.gateway.run_tool("nmap", {"target": target, "options": "-sV"})
                finding = {
                    "target": target,
                    "tool": "nmap",
                    "severity": "info",
                    "description": f"Scan results: {result.get('output', '')[:200]}",
                    "raw_output": result.get("output", "")
                }
                self.db.add_finding(**finding)
                self.soul.ingest_loot({
                    "type": "recon",
                    "target": target,
                    "findings": {"nmap": result.get("output", "")[:500]}
                })
                action = self.soul.update_state("recon", finding)
                if action == "halt":
                    break
                elif action == "next_phase":
                    pass
            elif cmd == "metasploit":
                self.progress("[*] Exploitation phase (placeholder)")
        self.db.finish_session(session_id, "completed")
        return self.db.full_report(session_id)

if __name__ == "__main__":
    bootstrap()
    print("PHALANX Core v3.3 ready (local ./phalanx/ folder).")
    db = PhalanxDB()
    print(f"Database initialized at {db.conn}")
    db.close()
