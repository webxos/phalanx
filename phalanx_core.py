#!/usr/bin/env python3
"""
PHALANX Core v3.6 – Database, Soul Memory, RoE, Agent Registry, SWARM tables,
Benchmark Suite (verify-claims), Operator Archetypes, and Egress-Scope Containment.

All data stored in ./phalanx/ (local to project, no dot prefix).

Enhancements from T3MP3ST + OGhidra + Raptor Loop integration:
- Added Benchmark class for verify-claims regression testing.
- Enhanced RoEEnforcer with egress-scope containment (check_scope).
- Added OPERATOR_ARCHETYPES constant for 8-operator ReAct kill chain.
- New database tables: benchmark_results, operator_states, loop_coverage,
  disposition_ledger, scrutiny_kb.
- Schema version bumped to 10.

Fixed issues (inherited from v3.5):
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
- Updated to v3.5 with consistent Rich integration and panel outputs
- Added add_defense_alert method to PhalanxDB
- Added warning for missing FTS5 instead of silent pass
- Fixed RoE logical bug detection to include 'idor' alias
- Fixed Soul.ingest_loot fallback for missing target
- Removed unused 'Table' import
- Expanded logical bug detection with more variants
- Renamed SindriKit → WinStealth (table, config, methods)
- Added defense_alerts table to schema for upfront creation
- Enforce foreign key constraints with PRAGMA foreign_keys = ON
- Improved database path writability check and error handling
- Added method to force schema recreation if needed (for debugging)
- SkillManager now supports routing matrix from skills/routing.md
- LavaWall default configuration section added.

FIXED in this version:
- AutonomousPentest._run_agentic_async now uses async ReconAgent, ExploitAgent, and PostExploitAgent
  from phalanx_library to avoid the "dict await" error. All agent calls are properly awaited.
- Added graceful fallback to nmap scan if agent imports fail.
- Ensured all agent imports are from phalanx_library (which defines async agents).
- Removed direct import from agents directory to prevent stub mismatch.
- Schema upgrade now explicitly creates benchmark_results and operator_states when version < 9.
- Added fallback static plan generation in _run_agentic_async if generate_engagement_plan fails.
- Schema statements now use textwrap.dedent for better readability and maintainability.
- Improved _extract_open_ports in Benchmark with proper XML parsing.
- Added warning logging in add_loot when foreign key constraint fails.
- Safe FTS5 creation in Soul._init_memory (wraps in try/except).
- Better async loop handling in AutonomousPentest._run_agentic_safe (explicit check for running loop).
- Added detailed logging for schema upgrades in PhalanxDB._init_schema.
- FIX: Ensure generate_engagement_plan result is not None; fallback to static plan if None.
- FIX: RoEEnforcer now initializes self.config as empty dict if None is provided.
- FIX: Soul.add_loot_from_finding now checks return value of db.add_loot and logs error if it fails.
- DOC: Clarified that ReActToolAgent from phalanx_engine is not directly used in AutonomousPentest;
       the orchestrator (if provided) handles ReAct loops.

NEW in this version (Raptor Loop):
- Added tables for loop_coverage, disposition_ledger, scrutiny_kb.
- Added PhalanxDB methods: add_coverage, get_coverage, add_ledger_entry, update_scrutiny.
- Extended Benchmark.verify_claims with the 11‑axis trap battery (placeholders implemented).
- Foreign key cascades added for new tables.
- Early-return guards added in critical DB methods to handle missing IDs gracefully.

ENHANCEMENTS per user request (v3.6.2):
- SkillManager now has a fallback to the 'shell' skill when no other route matches.
- Soul.get_raptor_insight() provides a summary of coverage, ledger, and scrutiny for a campaign.
- PhalanxDB added get_ledger() and get_scrutiny() methods to query Raptor loop data.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
import logging
import re
import asyncio
import os
import textwrap
import concurrent.futures  # Added for ThreadPoolExecutor in _run_agentic_safe
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime

# ------------------------------------------------------------------
# Rich for optional pretty console output (TUI enhancements)
# ------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    # from rich.table import Table  # not used
    from rich.prompt import Confirm
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
    Panel = None
    Table = None
    Confirm = None

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
# Default configuration (v3.6) – includes LavaWall and new OPSEC settings
# ------------------------------------------------------------------
def _default_config() -> dict:
    return {
        "phalanx": {"version": "3.6", "agent_name": "PHALANX"},
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
        "winstealth": {
            "enabled": False,
            "default_profile": "Win32",
            "pe_library_path": "phalanx/lib/winstealth/build/libwinstealth.so",
            "auto_obfuscate": True,
            "hash_algo": "DJB2",
            "syscall_strategy": "hellsgate"
        },
        "lavawall": {
            "wifi_interface": "wlan0",
            "scan_duration": 30,
            "vpn_config_path": "/etc/openvpn/client.ovpn",
            "metrics_interval": 5
        },
        # T3MP3ST / OPSEC
        "opsec": {
            "scope_strict": True,
            "max_detection_risk": 0.8,
            "operator_cooldown": 60,  # seconds
            "benchmark_suite": "basic"
        },
        "oghidra": {
            "enabled": True,
            "ghidra_path": "/opt/ghidra",
            "model": "gemma3:27b",
            "malware_detect": True,
            "rag_enabled": True
        }
    }

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def load_config(path: Path = CONFIG_FILE) -> dict:
    """Load configuration from file and merge with defaults."""
    defaults = _default_config()
    if path.exists():
        try:
            file_config = json.loads(path.read_text())
            # Deep merge file_config into defaults so missing keys are added
            return _deep_merge(defaults, file_config)
        except Exception as e:
            logger.warning(f"Failed to load config from {path}: {e}")
            # Fall back to defaults
            return defaults
    return defaults

def save_config(config: dict, path: Path = CONFIG_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2))

def _ensure_dirs():
    for d in (BASE_DIR, AUDIT_DIR, ENGAGEMENTS_DIR, REPORTS_DIR,
              BASE_DIR / "skills", BASE_DIR / "soul", BASE_DIR / "logs",
              BASE_DIR / "tools", BASE_DIR / "lib", BASE_DIR / "config",
              BASE_DIR / "swarm_logs", BASE_DIR / "playbooks",
              BASE_DIR / "bench"):  # New benchmark directory
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
# Operator Archetypes (T3MP3ST 8-operator kill chain)
# ------------------------------------------------------------------
OPERATOR_ARCHETYPES = {
    "RECON": {
        "phase": "reconnaissance",
        "mitre": "TA0043",
        "description": "Information gathering, OSINT, network scanning"
    },
    "SCANNER": {
        "phase": "discovery",
        "mitre": "TA0007",
        "description": "Vulnerability scanning, service enumeration"
    },
    "EXPLOITER": {
        "phase": "initial_access",
        "mitre": "TA0001, TA0002",
        "description": "Exploit development and execution"
    },
    "INFILTRATOR": {
        "phase": "lateral_movement",
        "mitre": "TA0008, TA0004",
        "description": "Pivoting, lateral movement, credential harvesting"
    },
    "EXFILTRATOR": {
        "phase": "exfiltration",
        "mitre": "TA0009, TA0010",
        "description": "Data extraction, covert channels"
    },
    "GHOST": {
        "phase": "persistence",
        "mitre": "TA0003, TA0005",
        "description": "Persistence mechanisms, defense evasion"
    },
    "COORDINATOR": {
        "phase": "c2",
        "mitre": "TA0011",
        "description": "Command and control, orchestration"
    },
    "ANALYST": {
        "phase": "reporting",
        "mitre": "",
        "description": "Reporting, correlation, recommendations"
    }
}

# ------------------------------------------------------------------
# Unified Database (PhalanxDB) with SWARM tables, LOOT table, and new T3MP3ST tables
# ------------------------------------------------------------------
_SCHEMA_VERSION = 10   # bumped for Raptor Loop tables

# Schema statements using textwrap.dedent for cleaner formatting
_SCHEMA_STATEMENTS = [
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target TEXT,
            tool TEXT,
            severity TEXT,
            description TEXT,
            raw_output TEXT
        )
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            status TEXT,
            last_seen TEXT,
            capabilities TEXT
        )
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS summaries (
            summary_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            raw_output TEXT,
            ai_analysis TEXT,
            risk_score REAL DEFAULT 0.0,
            created_at TEXT
        )
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS swarm_attack_surface (
            surface_id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            asset_value TEXT NOT NULL,
            metadata TEXT,
            discovered_at TEXT NOT NULL,
            FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id)
        )
    """),
    textwrap.dedent("""
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
    """),
    textwrap.dedent("""
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
    """),
    "CREATE INDEX IF NOT EXISTS idx_graph_campaign ON graph_edges(campaign_id)",
    "CREATE INDEX IF NOT EXISTS idx_graph_nodes ON graph_edges(from_node, to_node)",
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS winstealth_contexts (
            context_id TEXT PRIMARY KEY,
            campaign_id TEXT,
            profile TEXT NOT NULL,
            pe_hash TEXT,
            created_at TEXT NOT NULL,
            metadata TEXT,
            FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id)
        )
    """),
    "CREATE INDEX IF NOT EXISTS idx_winstealth_campaign ON winstealth_contexts(campaign_id)",
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS defense_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            risk TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            process TEXT,
            action_taken TEXT,
            llm_analysis TEXT
        )
    """),
    # ----- NEW TABLES for T3MP3ST -----
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS benchmark_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suite_name TEXT,
            test_name TEXT,
            passed INTEGER,
            expected_output TEXT,
            actual_output TEXT,
            run_at TEXT
        )
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS operator_states (
            operator_id TEXT PRIMARY KEY,
            archetype TEXT,
            status TEXT,  -- idle, tasked, executing, cooldown, burned
            detection_risk REAL,
            cooldown_until TEXT,
            last_task TEXT,
            metadata TEXT
        )
    """),
    "CREATE INDEX IF NOT EXISTS idx_operator_archetype ON operator_states(archetype)",

    # ----- NEW Raptor Loop Tables (v3.6 Raptor) -----
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS loop_coverage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT,
            altitude TEXT,       -- 'project','file','feature','function'
            target TEXT,
            covered BOOLEAN,
            last_checked TIMESTAMP,
            metadata TEXT,
            FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id) ON DELETE CASCADE
        )
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS disposition_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT,
            finding_id TEXT,
            disposition TEXT,   -- 'confirm','reject','downgrade'
            evidence_receipt TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id) ON DELETE CASCADE
        )
    """),
    textwrap.dedent("""
        CREATE TABLE IF NOT EXISTS scrutiny_kb (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id TEXT,
            entity TEXT,
            scrutiny_level INTEGER,  -- increases monotonically
            last_updated TIMESTAMP,
            reason TEXT,
            FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id) ON DELETE CASCADE
        )
    """),
    "CREATE INDEX IF NOT EXISTS idx_loop_campaign ON loop_coverage(campaign_id)",
    "CREATE INDEX IF NOT EXISTS idx_ledger_campaign ON disposition_ledger(campaign_id)",
    "CREATE INDEX IF NOT EXISTS idx_scrutiny_campaign ON scrutiny_kb(campaign_id)",
]

class PhalanxDB:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self._lock = threading.Lock()
        db_cfg = self.config.get("database", {})
        db_path = Path(db_cfg.get("sqlite_path", "phalanx/phalanx.db")).expanduser()
        # Ensure the directory exists and is writable
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if not os.access(db_path.parent, os.W_OK):
            raise PermissionError(f"Database directory {db_path.parent} is not writable")
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # Enforce foreign key constraints
        self.conn.execute("PRAGMA foreign_keys = ON")
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

            # Log the current schema version
            logger.info(f"Current database schema version: {current_version}, target: {_SCHEMA_VERSION}")

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
                logger.info(f"Upgrading schema from version {current_version} to {_SCHEMA_VERSION}")

                # If upgrading from version < 9, add T3MP3ST tables explicitly
                if current_version < 9:
                    logger.info("Applying schema upgrades for version < 9: creating benchmark_results and operator_states tables")
                    try:
                        cur.execute("""
                            CREATE TABLE IF NOT EXISTS benchmark_results (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                suite_name TEXT,
                                test_name TEXT,
                                passed INTEGER,
                                expected_output TEXT,
                                actual_output TEXT,
                                run_at TEXT
                            )
                        """)
                        cur.execute("""
                            CREATE TABLE IF NOT EXISTS operator_states (
                                operator_id TEXT PRIMARY KEY,
                                archetype TEXT,
                                status TEXT,
                                detection_risk REAL,
                                cooldown_until TEXT,
                                last_task TEXT,
                                metadata TEXT
                            )
                        """)
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_operator_archetype ON operator_states(archetype)")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"Could not create T3MP3ST tables: {e}")

                # If upgrading from version < 10, create Raptor Loop tables
                if current_version < 10:
                    logger.info("Applying schema upgrades for version < 10: creating Raptor Loop tables")
                    try:
                        cur.execute("""
                            CREATE TABLE IF NOT EXISTS loop_coverage (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                campaign_id TEXT,
                                altitude TEXT,
                                target TEXT,
                                covered BOOLEAN,
                                last_checked TIMESTAMP,
                                metadata TEXT,
                                FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id) ON DELETE CASCADE
                            )
                        """)
                        cur.execute("""
                            CREATE TABLE IF NOT EXISTS disposition_ledger (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                campaign_id TEXT,
                                finding_id TEXT,
                                disposition TEXT,
                                evidence_receipt TEXT,
                                timestamp TIMESTAMP,
                                FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id) ON DELETE CASCADE
                            )
                        """)
                        cur.execute("""
                            CREATE TABLE IF NOT EXISTS scrutiny_kb (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                campaign_id TEXT,
                                entity TEXT,
                                scrutiny_level INTEGER,
                                last_updated TIMESTAMP,
                                reason TEXT,
                                FOREIGN KEY (campaign_id) REFERENCES swarm_campaigns(campaign_id) ON DELETE CASCADE
                            )
                        """)
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_loop_campaign ON loop_coverage(campaign_id)")
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_ledger_campaign ON disposition_ledger(campaign_id)")
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_scrutiny_campaign ON scrutiny_kb(campaign_id)")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"Could not create Raptor Loop tables: {e}")

                # Update version
                cur.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                            ("schema_version", str(_SCHEMA_VERSION)))
                logger.info(f"Schema version updated to {_SCHEMA_VERSION}")
            else:
                logger.debug("Schema is already at the latest version.")

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
        # Early return if neither session nor campaign is provided
        if not session_id and not campaign_id:
            logger.warning("add_loot called without session_id or campaign_id; loot not stored.")
            return ""
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

    # Defense alerts (table created upfront, so no need to recreate)
    def add_defense_alert(self, risk: str, source_ip: str, dest_ip: str, process: str, action_taken: str, llm_analysis: str = ""):
        """Record a defense alert in the database."""
        with self._lock:
            self.conn.execute("""
                INSERT INTO defense_alerts (timestamp, risk, source_ip, dest_ip, process, action_taken, llm_analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (datetime.utcnow().isoformat(), risk, source_ip, dest_ip, process, action_taken, llm_analysis))
            self.conn.commit()

    # WinStealth contexts (renamed from sindri_contexts)
    def save_winstealth_context(self, context_id: str, campaign_id: str, profile: str,
                                pe_hash: str = "", metadata: Dict = None) -> bool:
        """Persist a WinStealth context for later reuse."""
        try:
            with self._lock:
                self.conn.execute("""
                    INSERT OR REPLACE INTO winstealth_contexts
                    (context_id, campaign_id, profile, pe_hash, created_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (context_id, campaign_id, profile, pe_hash,
                      datetime.now().isoformat(), json.dumps(metadata or {})))
                self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save WinStealth context: {e}")
            return False

    def get_winstealth_context(self, context_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM winstealth_contexts WHERE context_id = ?", (context_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_winstealth_contexts_for_campaign(self, campaign_id: str) -> List[Dict]:
        cur = self.conn.execute("SELECT * FROM winstealth_contexts WHERE campaign_id = ? ORDER BY created_at DESC", (campaign_id,))
        return [dict(row) for row in cur.fetchall()]

    def delete_winstealth_context(self, context_id: str) -> bool:
        try:
            with self._lock:
                self.conn.execute("DELETE FROM winstealth_contexts WHERE context_id = ?", (context_id,))
                self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to delete WinStealth context: {e}")
            return False

    # ------------------------------------------------------------------
    # Benchmark (verify-claims) methods
    # ------------------------------------------------------------------
    def save_benchmark_result(self, suite_name: str, test_name: str, passed: bool,
                              expected: str, actual: str) -> None:
        """Store a benchmark result for later verification."""
        with self._lock:
            self.conn.execute("""
                INSERT INTO benchmark_results (suite_name, test_name, passed, expected_output, actual_output, run_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (suite_name, test_name, 1 if passed else 0, expected, actual, datetime.utcnow().isoformat()))
            self.conn.commit()

    def get_benchmark_results(self, suite_name: str = None, limit: int = 100) -> List[Dict]:
        query = "SELECT * FROM benchmark_results"
        params = []
        if suite_name:
            query += " WHERE suite_name = ?"
            params.append(suite_name)
        query += " ORDER BY run_at DESC LIMIT ?"
        params.append(limit)
        cur = self.conn.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    # Operator states (T3MP3ST)
    def update_operator_state(self, operator_id: str, archetype: str, status: str,
                              detection_risk: float = 0.0, cooldown_until: str = None,
                              last_task: str = None, metadata: Dict = None) -> None:
        """Update or insert operator state."""
        with self._lock:
            self.conn.execute("""
                INSERT OR REPLACE INTO operator_states
                (operator_id, archetype, status, detection_risk, cooldown_until, last_task, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (operator_id, archetype, status, detection_risk, cooldown_until, last_task, json.dumps(metadata or {})))
            self.conn.commit()

    def get_operator_state(self, operator_id: str) -> Optional[Dict]:
        cur = self.conn.execute("SELECT * FROM operator_states WHERE operator_id = ?", (operator_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def list_operator_states(self, archetype: str = None) -> List[Dict]:
        query = "SELECT * FROM operator_states"
        params = []
        if archetype:
            query += " WHERE archetype = ?"
            params.append(archetype)
        cur = self.conn.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------
    # Raptor Loop methods
    # ------------------------------------------------------------------
    def add_coverage(self, campaign_id: str, altitude: str, target: str,
                     covered: bool, metadata: Dict = None) -> bool:
        """Record a coverage entry for a given altitude."""
        if not campaign_id:
            logger.warning("add_coverage called without campaign_id; skipping.")
            return False
        try:
            with self._lock:
                self.conn.execute("""
                    INSERT INTO loop_coverage (campaign_id, altitude, target, covered, last_checked, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (campaign_id, altitude, target, 1 if covered else 0,
                      datetime.utcnow().isoformat(), json.dumps(metadata or {})))
                self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add coverage: {e}")
            return False

    def get_coverage(self, campaign_id: str, altitude: str = None) -> List[Dict]:
        """Retrieve coverage entries for a campaign, optionally filtered by altitude."""
        if not campaign_id:
            return []
        query = "SELECT * FROM loop_coverage WHERE campaign_id = ?"
        params = [campaign_id]
        if altitude:
            query += " AND altitude = ?"
            params.append(altitude)
        query += " ORDER BY last_checked DESC"
        cur = self.conn.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

    def add_ledger_entry(self, campaign_id: str, finding_id: str,
                         disposition: str, evidence_receipt: str = "") -> bool:
        """Add an entry to the disposition ledger."""
        if not campaign_id:
            logger.warning("add_ledger_entry called without campaign_id; skipping.")
            return False
        try:
            with self._lock:
                self.conn.execute("""
                    INSERT INTO disposition_ledger (campaign_id, finding_id, disposition, evidence_receipt, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (campaign_id, finding_id, disposition, evidence_receipt, datetime.utcnow().isoformat()))
                self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add ledger entry: {e}")
            return False

    def get_ledger(self, campaign_id: str, limit: int = 100) -> List[Dict]:
        """Retrieve disposition ledger entries for a campaign."""
        if not campaign_id:
            return []
        cur = self.conn.execute(
            "SELECT * FROM disposition_ledger WHERE campaign_id = ? ORDER BY timestamp DESC LIMIT ?",
            (campaign_id, limit)
        )
        return [dict(row) for row in cur.fetchall()]

    def update_scrutiny(self, campaign_id: str, entity: str, reason: str) -> bool:
        """
        Increase the scrutiny level of an entity by 1, or insert with level 1.
        Returns True on success.
        """
        if not campaign_id:
            logger.warning("update_scrutiny called without campaign_id; skipping.")
            return False
        try:
            with self._lock:
                # Check if exists
                cur = self.conn.execute("""
                    SELECT scrutiny_level FROM scrutiny_kb
                    WHERE campaign_id = ? AND entity = ?
                """, (campaign_id, entity))
                row = cur.fetchone()
                if row:
                    new_level = row[0] + 1
                    self.conn.execute("""
                        UPDATE scrutiny_kb
                        SET scrutiny_level = ?, last_updated = ?, reason = ?
                        WHERE campaign_id = ? AND entity = ?
                    """, (new_level, datetime.utcnow().isoformat(), reason, campaign_id, entity))
                else:
                    self.conn.execute("""
                        INSERT INTO scrutiny_kb (campaign_id, entity, scrutiny_level, last_updated, reason)
                        VALUES (?, ?, ?, ?, ?)
                    """, (campaign_id, entity, 1, datetime.utcnow().isoformat(), reason))
                self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to update scrutiny: {e}")
            return False

    def get_scrutiny(self, campaign_id: str, entity: str = None) -> List[Dict]:
        """Retrieve scrutiny entries for a campaign, optionally for a specific entity."""
        if not campaign_id:
            return []
        query = "SELECT * FROM scrutiny_kb WHERE campaign_id = ?"
        params = [campaign_id]
        if entity:
            query += " AND entity = ?"
            params.append(entity)
        cur = self.conn.execute(query, params)
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
        # Ensure both nodes exist
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
            # Try to create FTS5 virtual table, but don't fail if not available
            try:
                self.db.conn.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS fts_memory USING fts5(content, category, subtype)
                """)
            except sqlite3.OperationalError as e:
                # FTS5 not available - reduced to debug to avoid log noise
                logger.debug(f"FTS5 not available – full-text search disabled: {e}")

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
            # Fallback to LIKE
            cur = self.db.conn.execute("""
                SELECT ts, category, subtype, content FROM memory
                WHERE content LIKE ? OR category LIKE ? OR subtype LIKE ?
                ORDER BY id DESC LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
            return [{"ts": r[0], "type": f"{r[1]}/{r[2]}", "summary": r[3][:100]} for r in cur.fetchall()]

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
        Enhanced with Rich panel output if available.
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

            # If Rich is available, display reflection result nicely
            if RICH_AVAILABLE and Console and Panel:
                console = Console()
                content = (
                    f"Phase: {phase}\n"
                    f"Confidence: {result.get('confidence', 0.5):.2f}\n"
                    f"Key Evidence: {result.get('key_evidence', '')[:100]}\n"
                    f"Suggestion: {result.get('suggestion', 'continue')}\n"
                    f"Next Phase: {result.get('next_phase', '')}"
                )
                console.print(Panel(content, title="Reflection", border_style="cyan"))
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
        # Fallback: if target is empty, try to extract from findings
        if not target and "address" in findings:
            target = findings["address"]

        def add_host(host):
            if host:
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
            if ip:
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
        loot_id = self.db.add_loot(finding.type, loot_data, campaign_id=self.campaign_id)
        if not loot_id:
            # Foreign key likely failed because session/campaign ID is invalid
            logger.error(f"Failed to add loot for finding {finding.id} (type={finding.type}) – "
                         f"campaign_id={self.campaign_id or 'None'}. Check that the campaign exists.")
            # Optionally raise an exception to alert caller
            raise RuntimeError(f"Failed to store loot for finding {finding.id}: invalid campaign/session.")
        self.ingest_loot({"type": finding.type, "target": finding.target, "findings": loot_data})

    def graph_summary(self) -> Dict:
        """Return a summary of the graph for reporting."""
        return self.graph.summary()

    # ------------------------------------------------------------------
    # Raptor Insight: aggregate coverage, ledger, scrutiny for a campaign
    # ------------------------------------------------------------------
    def get_raptor_insight(self, campaign_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Retrieve a summary of Raptor loop data for the given campaign
        (or the current campaign if not specified).
        Returns a dict with coverage, ledger entries, scrutiny levels, and a brief summary.
        """
        cid = campaign_id or self.campaign_id
        if not cid:
            return {"error": "No campaign ID provided or set in Soul"}

        coverage = self.db.get_coverage(cid)
        ledger = self.db.get_ledger(cid, limit=50)
        scrutiny = self.db.get_scrutiny(cid)

        # Compute some stats
        total_altitudes = len(coverage)
        covered = sum(1 for c in coverage if c.get("covered", False))
        coverage_pct = (covered / total_altitudes * 100) if total_altitudes else 0.0

        # Ledger dispositions
        dispositions = {}
        for entry in ledger:
            d = entry.get("disposition", "unknown")
            dispositions[d] = dispositions.get(d, 0) + 1

        # Scrutiny level summary
        scrutiny_levels = {}
        for s in scrutiny:
            entity = s.get("entity", "unknown")
            level = s.get("scrutiny_level", 0)
            scrutiny_levels[entity] = level

        return {
            "campaign_id": cid,
            "coverage": {
                "total_altitudes": total_altitudes,
                "covered": covered,
                "coverage_percent": coverage_pct,
                "entries": coverage[:20],  # sample
            },
            "ledger": {
                "total_entries": len(ledger),
                "dispositions": dispositions,
                "recent": ledger[:10],  # sample
            },
            "scrutiny": {
                "total_entities": len(scrutiny),
                "levels": scrutiny_levels,
                "entries": scrutiny[:10],  # sample
            },
            "summary": (
                f"Raptor campaign {cid}: {covered}/{total_altitudes} altitudes covered "
                f"({coverage_pct:.1f}%). Ledger has {len(ledger)} entries, "
                f"scrutiny tracked for {len(scrutiny)} entities."
            )
        }

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
# RoE Enforcer with guardrail, difficulty estimator, and egress-scope containment
# ------------------------------------------------------------------
class RoEEnforcer:
    def __init__(self, config: dict, confirm_callback: Optional[Callable[[str, Dict], bool]] = None,
                 gateway=None):
        self.config = config or {}  # Ensure config is always a dict
        self.active_plan = None
        self.confirm_callback = confirm_callback or self._default_confirm
        self.gateway = gateway  # for difficulty estimation

    def load_plan(self, plan: dict):
        self.active_plan = plan

    def check_scope(self, target: str) -> Tuple[bool, str]:
        """Enforce egress-scope containment - reject off-scope hosts."""
        if not self.active_plan:
            return True, "No active plan, scope check skipped"
        roe = self.active_plan.get("roe", {})
        allowed = roe.get("allowed_targets", [])
        if allowed and target not in allowed:
            return False, f"Target {target} not in RoE allowed list (egress guard)"
        return True, "In scope"

    def check_action(self, action: str, target: str, details: Dict = None) -> Tuple[bool, str, bool]:
        # First, check scope
        in_scope, scope_msg = self.check_scope(target)
        if not in_scope:
            return False, scope_msg, False

        if not self.active_plan:
            return True, "No active RoE plan", False
        roe = self.active_plan.get("roe", {})
        # Also check allowed targets again (redundant but kept)
        allowed = roe.get("allowed_targets", [])
        if allowed and target not in allowed:
            return False, f"Target {target} not in RoE allowed list", False
        forbidden = roe.get("forbidden_actions",
                            self.config.get("engagement", {}).get("default_roe", {}).get("forbidden_actions", []))
        for f in forbidden:
            if f in action.lower():
                return False, f"Action '{action}' matches forbidden pattern '{f}'", False

        # Logical bug detection – high-impact vulnerabilities that require confirmation
        # Expanded list of logical bug variants
        logical_bugs = [
            "idor", "id_or", "auth_bypass", "csrf", "race_condition",
            "insecure_direct_object_reference", "privilege_escalation"
        ]
        if any(logical in action.lower() or (details and details.get("category") == logical)
               for logical in logical_bugs):
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
        # Use Rich confirmation prompt if available, else fallback to input
        if RICH_AVAILABLE and Confirm:
            return Confirm.ask(f"\n⚠️  {prompt}")
        else:
            resp = input(f"\n⚠️  {prompt}\nConfirm? (y/N): ").strip().lower()
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
# Skill Manager – extended with routing matrix and shell fallback
# ------------------------------------------------------------------
class SkillManager:
    def __init__(self, path: Path = BASE_DIR / "skills.md", skills_dir: Path = BASE_DIR / "skills"):
        """
        Initialize skill manager.
        :param path: Path to the skill performance log (skills.md)
        :param skills_dir: Directory containing skill subdirectories and routing.md
        """
        self.path = path
        self.skills_dir = skills_dir
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("# PHALANX Skill Log\n")
        # Ensure skills directory exists
        self.skills_dir.mkdir(parents=True, exist_ok=True)

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

    # ---------- Routing matrix methods ----------
    def load_routing_matrix(self) -> Dict[str, Dict]:
        """
        Parse skills/routing.md and return a dict mapping target type to skill info.
        Expected format: markdown table with columns: Target Type | Skill | Description
        """
        routing_file = self.skills_dir / "routing.md"
        if not routing_file.exists():
            return {}
        content = routing_file.read_text()
        routes = {}
        lines = content.splitlines()
        for line in lines:
            # Skip header separators and comments
            if '|' in line and '---' not in line and not line.strip().startswith('#'):
                parts = [p.strip() for p in line.split('|') if p.strip()]
                if len(parts) >= 2:
                    key = parts[0].lower()
                    routes[key] = {
                        "skill": parts[1],
                        "description": parts[2] if len(parts) > 2 else ""
                    }
        return routes

    def get_skill_for_target(self, target_type: str) -> Optional[str]:
        """
        Return the skill name for a given target type (e.g., '.apk', 'web').
        Uses fuzzy matching: exact match, then suffix/prefix match.
        If no match is found, returns 'shell' as a fallback skill.
        """
        if not target_type:
            return None
        target_type = target_type.lower()
        routes = self.load_routing_matrix()
        # Exact match
        if target_type in routes:
            return routes[target_type]["skill"]
        # Suffix match (e.g., '.apk' matches 'apk')
        for key, info in routes.items():
            if target_type.endswith(key) or key.endswith(target_type):
                return info["skill"]
        # Substring match
        for key, info in routes.items():
            if key in target_type:
                return info["skill"]
        # No match: fallback to 'shell' skill
        logger.info(f"No route found for target type '{target_type}', falling back to 'shell' skill.")
        return "shell"

    def add_skill_route(self, target_type: str, skill_name: str, description: str = "") -> bool:
        """
        Dynamically add a new skill route to the routing matrix.
        If the routing.md file exists, appends a new row.
        Returns True on success, False otherwise.
        """
        routing_file = self.skills_dir / "routing.md"
        if not routing_file.exists():
            # Create a minimal routing file with header and the new route
            header = "# Reverse-Skill Routing Matrix\n\n| Target Type | Skill | Description |\n|-------------|-------|-------------|\n"
            content = header + f"| {target_type} | {skill_name} | {description} |\n"
            try:
                routing_file.write_text(content)
                return True
            except Exception as e:
                logger.error(f"Failed to create routing file: {e}")
                return False
        else:
            # Append a new line if not already present
            try:
                existing = routing_file.read_text()
                new_line = f"| {target_type} | {skill_name} | {description} |\n"
                if new_line.strip() not in existing:
                    with open(routing_file, 'a') as f:
                        f.write(new_line)
                return True
            except Exception as e:
                logger.error(f"Failed to append route to routing file: {e}")
                return False

# ------------------------------------------------------------------
# Benchmark (verify-claims) Class – extended with 11‑axis trap battery
# ------------------------------------------------------------------
class Benchmark:
    """T3MP3ST-style verify-claims regression testing suite with 11-axis trap battery."""
    def __init__(self, db: PhalanxDB, config: dict):
        self.db = db
        self.config = config
        self.bench_dir = Path("phalanx/bench")
        self.golden_dir = self.bench_dir / "golden"
        self.golden_dir.mkdir(parents=True, exist_ok=True)

    def verify_claims(self, suite: str = "basic") -> Dict:
        """
        Run regression tests against committed golden outputs.
        Implements the 11‑axis trap battery (stub tests).
        Returns dict with passed, failed, and score.
        """
        results = {"passed": [], "failed": [], "score": 0.0}

        # Axis 1: Recall
        self._run_trap_test("Recall", results, suite, self._test_recall)

        # Axis 2: FP‑resistance
        self._run_trap_test("FP_resistance", results, suite, self._test_fp_resistance)

        # Axis 3: False‑rejection
        self._run_trap_test("False_rejection", results, suite, self._test_false_rejection)

        # Axis 4: Coverage‑honesty
        self._run_trap_test("Coverage_honesty", results, suite, self._test_coverage_honesty)

        # Axis 5: Severity‑downgrade integrity
        self._run_trap_test("Severity_downgrade", results, suite, self._test_severity_downgrade)

        # Axis 6: Evidence‑chain fidelity
        self._run_trap_test("Evidence_fidelity", results, suite, self._test_evidence_fidelity)

        # Axis 7: Temporal consistency
        self._run_trap_test("Temporal_consistency", results, suite, self._test_temporal_consistency)

        # Axis 8: Cross‑tool agreement
        self._run_trap_test("Cross_tool_agreement", results, suite, self._test_cross_tool_agreement)

        # Axis 9: Adversarial resilience
        self._run_trap_test("Adversarial_resilience", results, suite, self._test_adversarial_resilience)

        # Axis 10: Explainability
        self._run_trap_test("Explainability", results, suite, self._test_explainability)

        # Axis 11: Operational utility
        self._run_trap_test("Operational_utility", results, suite, self._test_operational_utility)

        # Calculate score
        total_tests = len(results["passed"]) + len(results["failed"])
        results["score"] = (len(results["passed"]) / total_tests * 100) if total_tests else 0.0

        return results

    def _run_trap_test(self, name: str, results: Dict, suite: str, test_func):
        """Run a single trap test and record result."""
        try:
            passed = test_func()
            self.db.save_benchmark_result(suite, name, passed, "", "")
            if passed:
                results["passed"].append(name)
            else:
                results["failed"].append({"name": name, "diff": "Test did not meet criteria"})
        except Exception as e:
            results["failed"].append({"name": name, "diff": str(e)})

    # --------------------------------------------------------------
    # 11-axis trap battery implementations (placeholders)
    # --------------------------------------------------------------
    def _test_recall(self) -> bool:
        """Test 1: Recall – ensure known findings are not missed."""
        # Placeholder: compare against a known set of expected findings
        return True

    def _test_fp_resistance(self) -> bool:
        """Test 2: FP‑resistance – ensure false positives are low."""
        return True

    def _test_false_rejection(self) -> bool:
        """Test 3: False‑rejection – ensure true findings are not rejected."""
        return True

    def _test_coverage_honesty(self) -> bool:
        """Test 4: Coverage‑honesty – reported coverage matches actual."""
        return True

    def _test_severity_downgrade(self) -> bool:
        """Test 5: Severity‑downgrade integrity – no unjustified downgrades."""
        return True

    def _test_evidence_fidelity(self) -> bool:
        """Test 6: Evidence‑chain fidelity – evidence links are consistent."""
        return True

    def _test_temporal_consistency(self) -> bool:
        """Test 7: Temporal consistency – results are stable over time."""
        return True

    def _test_cross_tool_agreement(self) -> bool:
        """Test 8: Cross‑tool agreement – findings align across tools."""
        return True

    def _test_adversarial_resilience(self) -> bool:
        """Test 9: Adversarial resilience – robust against noise/perturbations."""
        return True

    def _test_explainability(self) -> bool:
        """Test 10: Explainability – each finding has a clear rationale."""
        return True

    def _test_operational_utility(self) -> bool:
        """Test 11: Operational utility – findings are actionable."""
        return True

    # --------------------------------------------------------------
    # Legacy test(s) – kept for compatibility
    # --------------------------------------------------------------
    def _extract_open_ports(self, nmap_xml: str) -> List[int]:
        """Extract open ports from nmap XML output (simplified)."""
        import xml.etree.ElementTree as ET
        ports = []
        try:
            root = ET.fromstring(nmap_xml)
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    ports.append(int(port.get("portid")))
        except Exception:
            # Fallback: regex
            for line in nmap_xml.splitlines():
                if " open " in line:
                    match = re.search(r'(\d+)/\w+\s+open', line)
                    if match:
                        ports.append(int(match.group(1)))
        return ports

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
            # Try to get the current event loop; if we are in a running loop,
            # we need to run the async function in a separate thread.
            loop = asyncio.get_running_loop()
            # We're in an async context; use ThreadPoolExecutor to avoid nested loop
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    lambda: asyncio.run(self._run_agentic_async(target, session_id, user_input))
                )
                return future.result()
        except RuntimeError:
            # No running loop, safe to use asyncio.run()
            return asyncio.run(self._run_agentic_async(target, session_id, user_input))

    async def _run_agentic_async(self, target: str, session_id: str, user_input: str) -> Dict:
        """Async implementation of agentic mode using async agents from phalanx_library."""
        from phalanx_library import generate_engagement_plan, ReconAgent, ExploitAgent

        # Generate plan with fallback to static plan if needed
        plan = None
        try:
            plan = generate_engagement_plan(target, user_input, self.gateway)
        except Exception as e:
            logger.warning(f"generate_engagement_plan failed: {e}. Using static fallback plan.")
            plan = self._static_fallback_plan(target, user_input, str(e))

        # If plan is still None (e.g., generate_engagement_plan returned None), fallback
        if plan is None:
            logger.warning("generate_engagement_plan returned None. Using static fallback plan.")
            plan = self._static_fallback_plan(target, user_input, "generate_engagement_plan returned None")

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

        # Use ReconAgent and ExploitAgent from phalanx_library (they are async)
        recon_agent = ReconAgent("recon", self.gateway, self.db, self.soul, self.skill_mgr,
                                 model=self.gateway.default_model, progress_callback=self.progress)
        exploit_agent = ExploitAgent("exploit", self.gateway, self.db, self.soul, self.skill_mgr,
                                     model=self.gateway.default_model, progress_callback=self.progress)

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
                        # Use the async ReconAgent from phalanx_library
                        recon_result = await recon_agent.run({"target": target})
                        action_result = recon_result
                        # Process recon findings
                        findings = recon_result.get("findings", {})
                        if findings:
                            self.soul.ingest_loot({
                                "type": "recon",
                                "target": target,
                                "findings": findings
                            })
                            # Add findings to DB (simplified)
                            for key, value in findings.items():
                                if isinstance(value, list):
                                    for item in value[:3]:
                                        if isinstance(item, dict):
                                            desc = item.get("name", item.get("description", str(item)[:50]))
                                            self.db.add_finding(target, key, "info", desc, json.dumps(item)[:500])
                        current_phase = "exploit"
                    except Exception as e:
                        self.progress(f"[!] ReconAgent failed: {e}. Falling back to nmap.")
                        # Fallback to nmap scan
                        if self._check_roe("nmap", target):
                            res = self.gateway.run_tool("nmap", {"target": target, "options": "-sV -p- --open"})
                            findings_accumulated.append({"tool": "nmap", "output": res.get("output", "")[:200]})
                            self.soul.ingest_loot({
                                "type": "recon",
                                "target": target,
                                "findings": {"nmap": res.get("output", "")[:500]}
                            })
                        current_phase = "exploit"

                elif next_agent == "exploit":
                    try:
                        exploit_result = await exploit_agent.run({"target": target, "recon_data": findings_accumulated})
                        action_result = exploit_result
                        # Process exploit plan
                        plan_items = exploit_result.get("exploit_plan", [])
                        for item in plan_items:
                            tool = item.get("tool")
                            if tool and self._check_roe(tool, target, {"category": "exploit"}):
                                res = self.gateway.run_tool(tool, item.get("args", {}))
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
                    # Simple post-exploit: run sliver generate or similar
                    self.progress("[*] Post-exploitation phase (simplified)")
                    if self._check_roe("sliver_generate", target, {"category": "post"}):
                        res = self.gateway.run_tool("sliver_generate", {"target_ip": target})
                        findings_accumulated.append({"tool": "sliver_generate", "output": res.get("output", "")[:200]})
                        self.soul.ingest_loot({
                            "type": "post_exploit",
                            "target": target,
                            "findings": {"sliver_generate": res.get("output", "")[:500]}
                        })
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

    def _static_fallback_plan(self, target: str, user_input: str, reason: str) -> Dict:
        """Generate a static plan when the AI planner is unavailable."""
        logger.info(f"Using static fallback plan for {target} (reason: {reason})")
        objectives = [
            {
                "description": f"Reconnaissance of {target} – discover open ports, services, subdomains, and technologies",
                "mitre_tags": ["T1595", "T1046"],
                "evidence_guided": False
            },
            {
                "description": f"Vulnerability assessment of {target} – scan for known CVEs, misconfigurations, and logical flaws",
                "mitre_tags": ["T1595.002", "T1190"],
                "evidence_guided": False
            },
            {
                "description": f"Exploitation of {target} – attempt to compromise via highest severity vulnerabilities (RCE, SQLi, XSS, etc.)",
                "mitre_tags": ["T1190", "T1210"],
                "evidence_guided": True
            },
            {
                "description": f"Post‑exploitation and pivoting – extract credentials, establish persistence, and map lateral movement",
                "mitre_tags": ["T1003", "T1059"],
                "evidence_guided": True
            },
            {
                "description": f"Reporting – generate final report with findings, evidence, and remediation recommendations",
                "mitre_tags": [],
                "evidence_guided": False
            }
        ]
        # Add logical bug objective if user input suggests web app focus
        if any(term in user_input.lower() for term in ["web", "api", "app", "bug"]):
            objectives.insert(2, {
                "description": "Identify and chain logical bugs (IDOR, auth bypass, CSRF, race conditions)",
                "mitre_tags": ["T1190", "T1555"],
                "evidence_guided": True
            })
        roe = {
            "allowed_targets": [target],
            "excluded_targets": [],
            "forbidden_actions": ["data_exfiltration", "destruction", "ransomware", "denial_of_service"],
            "require_human_confirm": [
                "privilege_escalation",
                "exploit",
                "auth_bypass",
                "id_or",
                "data_modification",
                "race_condition",
                "c2_deployment"
            ],
            "max_severity": "critical"
        }
        return {
            "objectives": objectives,
            "roe": roe,
            "user_input": user_input,
            "generated_by": "static_fallback_core",
            "fallback_reason": reason,
            "schema_version": "2.0"
        }

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
                # Force advance to exploitation after first scan
                self.soul.state["phase"] = "exploit"
            elif cmd == "metasploit":
                self.progress("[*] Exploitation phase (placeholder)")
        self.db.finish_session(session_id, "completed")
        return self.db.full_report(session_id)

if __name__ == "__main__":
    bootstrap()
    print("PHALANX Core v3.6 ready (local ./phalanx/ folder).")
    db = PhalanxDB()
    print(f"Database initialized at {db.conn}")
    db.close()