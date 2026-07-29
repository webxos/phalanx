#!/usr/bin/env python3
"""
PHALANX v3.6 – War Room Dashboard Server (Production-Ready)

A standalone FastAPI server that serves the War Room frontend and provides
REST API endpoints for defense monitoring, system status, logs, controls,
and new T3MP3ST + OGhidra features.

Designed to be run independently or alongside the PHALANX REPL.
It reuses the PHALANX core components (PhalanxDB, Soul, etc.) and
communicates with the LavaWall defense monitor if it is running.

Usage:
    python dashboard_server.py [--port 3333] [--host 0.0.0.0] [--reload]

The server serves:
- Static HTML/JS/CSS from ./ui/static
- REST API endpoints under /api/*

Environment variables:
    PHALANX_DB_PATH: override the database path
    PHALANX_CONFIG_PATH: override the config file path
    PHALANX_STATIC_DIR: override the static directory path
    PHALANX_WARROOM_HOST: bind address (default: 0.0.0.0)
    PHALANX_WARROOM_PORT: bind port (default: 3333)
    PHALANX_CORS_ORIGINS: comma-separated list of allowed origins (default: "*")

Version: 3.6 - T3MP3ST + OGhidra Enhanced + Raptor Loop

FIXES (v3.6):
- Raptor Loop endpoints now query actual database tables (loop_coverage,
  disposition_ledger, scrutiny_kb) instead of returning stubs.
- Added /api/shell/history endpoint to retrieve shell command history.
- Enhanced fallback index.html with a live dashboard using the API.
- All endpoints include proper error handling and null checks.
"""

import sys
import os
import json
import logging
import time
import psutil
from pathlib import Path
from typing import Optional, Dict, Any, List
import argparse
import webbrowser
import threading

# ------------------------------------------------------------------
# Import FastAPI and related dependencies with graceful fallback
# ------------------------------------------------------------------
try:
    from fastapi import FastAPI, HTTPException, Query, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, PlainTextResponse, Response
    from fastapi.staticfiles import StaticFiles
    import uvicorn
except ImportError as e:
    print(f"[ERROR] FastAPI or uvicorn not installed: {e}")
    print("Please install: pip install fastapi uvicorn[standard] python-multipart aiofiles")
    sys.exit(1)

# ------------------------------------------------------------------
# Add PHALANX root to path for local imports
# ------------------------------------------------------------------
BASE_DIR = Path.cwd()
PHALANX_DIR = BASE_DIR / "phalanx"
sys.path.insert(0, str(BASE_DIR))

# ------------------------------------------------------------------
# PHALANX imports (core + defense + new v3.6 modules)
# ------------------------------------------------------------------
try:
    from phalanx_core import PhalanxDB, load_config, Benchmark
    from phalanx_defense import get_defense_monitor, NetWatchMonitor
except ImportError as e:
    print(f"[ERROR] Failed to import PHALANX core modules: {e}")
    print("Make sure you are running from the PHALANX project root.")
    sys.exit(1)

# Optional v3.6 features
try:
    from phalanx_tools import run_oghidra_analyze, run_oghidra_conversational, run_tool
    OGHIDRA_AVAILABLE = True
except ImportError:
    OGHIDRA_AVAILABLE = False
    run_oghidra_analyze = None
    run_oghidra_conversational = None
    run_tool = None

try:
    from phalanx_library import run_health_check, list_ollama_models
    LIBRARY_AVAILABLE = True
except ImportError:
    LIBRARY_AVAILABLE = False
    run_health_check = None
    list_ollama_models = None

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("phalanx.dashboard")

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
config_path = os.environ.get("PHALANX_CONFIG_PATH", PHALANX_DIR / "config" / "config.json")
config_path = Path(config_path)
config = load_config(config_path) if config_path.exists() else {}

# Database path
db_path = os.environ.get("PHALANX_DB_PATH", config.get("database", {}).get("sqlite_path", "phalanx/phalanx.db"))
db_path = Path(db_path)

# Static directory
static_dir = os.environ.get("PHALANX_STATIC_DIR", Path(__file__).parent / "ui" / "static")
static_dir = Path(static_dir)

# ------------------------------------------------------------------
# Database instance (lazy) with retry and permission handling
# ------------------------------------------------------------------
_db: Optional[PhalanxDB] = None
_db_lock = threading.Lock()

def get_db() -> PhalanxDB:
    """Lazy initialize database connection with retry logic."""
    global _db
    if _db is not None:
        return _db
    with _db_lock:
        if _db is not None:
            return _db
        # Ensure the database directory exists and is writable
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            logger.error(f"Permission denied creating database directory: {e}")
            raise HTTPException(503, f"Database directory permission denied: {e}")
        except Exception as e:
            logger.error(f"Failed to create database directory: {e}")
            raise HTTPException(503, f"Database directory creation failed: {e}")

        # Retry up to 3 times with 1s sleep
        for attempt in range(3):
            try:
                _db = PhalanxDB(config)
                logger.info("Database initialized successfully")
                return _db
            except PermissionError as e:
                logger.error(f"Permission denied accessing database: {e}")
                if attempt == 2:
                    raise HTTPException(503, f"Database permission denied: {e}")
                time.sleep(1)
            except Exception as e:
                logger.warning(f"Database init attempt {attempt+1} failed: {e}")
                if attempt < 2:
                    time.sleep(1)
        raise HTTPException(503, "Database unavailable after retries")

def get_defense() -> Optional[NetWatchMonitor]:
    """Get the global defense monitor instance if available."""
    return get_defense_monitor()

# ------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------
app = FastAPI(
    title="PHALANX War Room API",
    version="3.6",
    description="REST API for PHALANX defense monitoring, system status, and T3MP3ST+OGhidra features."
)

# ------------------------------------------------------------------
# CORS configuration: allow specific origins from environment or default to all
# ------------------------------------------------------------------
cors_origins_env = os.environ.get("PHALANX_CORS_ORIGINS", "")
if cors_origins_env:
    # Expect comma-separated list, e.g., "http://localhost:3000,https://example.com"
    cors_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
else:
    # Default to allow all origins (development mode)
    cors_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Serve static frontend files with fallback (enhanced dashboard)
# ------------------------------------------------------------------
def _ensure_static_dir(path: Path = None) -> Path:
    """Ensure static directory exists with a fallback index containing a live dashboard."""
    if path is None:
        path = static_dir
    if not path.exists():
        logger.warning(f"Static directory not found: {path}. Creating fallback dashboard.")
        path.mkdir(parents=True, exist_ok=True)
        fallback_html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PHALANX War Room</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #e0e0e0; font-family: 'Segoe UI', monospace; padding: 20px; }
        h1 { color: #00ccff; text-shadow: 0 0 20px #00ccff88; margin-bottom: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 10px; padding: 20px; }
        .card h2 { color: #88ddff; border-bottom: 1px solid #2a2a2a; padding-bottom: 10px; margin-bottom: 15px; }
        .status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.9em; }
        .status-on { background: #00aa44; color: #000; }
        .status-off { background: #aa3333; color: #fff; }
        .status-unknown { background: #666; color: #fff; }
        .log-entry { padding: 4px 0; border-bottom: 1px solid #222; font-size: 0.9em; }
        .log-time { color: #888; margin-right: 10px; }
        .log-level { font-weight: bold; }
        .log-level-HIGH { color: #ff4444; }
        .log-level-MED { color: #ffaa00; }
        .log-level-LOW { color: #88ddff; }
        pre { background: #111; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; }
        .refresh-btn { background: #00ccff33; border: 1px solid #00ccff; color: #00ccff; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin-top: 10px; }
        .refresh-btn:hover { background: #00ccff55; }
    </style>
</head>
<body>
    <h1>⚡ PHALANX War Room</h1>
    <div class="grid">
        <!-- System Status -->
        <div class="card" id="status-card">
            <h2>System Status</h2>
            <div id="status-content">Loading...</div>
            <button class="refresh-btn" onclick="fetchStatus()">⟳ Refresh</button>
        </div>
        <!-- Defense Alerts -->
        <div class="card" id="alerts-card">
            <h2>Recent Defense Alerts</h2>
            <div id="alerts-content">Loading...</div>
            <button class="refresh-btn" onclick="fetchAlerts()">⟳ Refresh</button>
        </div>
        <!-- Shell History -->
        <div class="card" id="shell-card">
            <h2>Shell Command History</h2>
            <div id="shell-content">Loading...</div>
            <button class="refresh-btn" onclick="fetchShell()">⟳ Refresh</button>
        </div>
        <!-- Raptor Coverage -->
        <div class="card" id="raptor-card">
            <h2>Raptor Coverage</h2>
            <div id="raptor-content">Loading...</div>
            <button class="refresh-btn" onclick="fetchRaptor()">⟳ Refresh</button>
        </div>
    </div>
    <script>
        const API_BASE = '/api';

        async function fetchStatus() {
            try {
                const res = await fetch(API_BASE + '/system/status');
                const data = await res.json();
                const el = document.getElementById('status-content');
                const defense = data.defense.active ? '<span class="status-badge status-on">Active</span>' : '<span class="status-badge status-off">Inactive</span>';
                const og = data.oghidra.available ? '✓' : '✗';
                const raptor = data.raptor_loop_engine.active ? 'Active' : 'Idle';
                el.innerHTML = `
                    <p><strong>Version:</strong> ${data.version}</p>
                    <p><strong>Defense:</strong> ${defense}</p>
                    <p><strong>OGhidra:</strong> ${og}</p>
                    <p><strong>Raptor Loop:</strong> ${raptor}</p>
                    <p><strong>Ollama URL:</strong> ${data.ollama_url || 'N/A'}</p>
                    <p><strong>Models:</strong> ${(data.ollama_models || []).join(', ') || 'None'}</p>
                `;
            } catch (e) {
                document.getElementById('status-content').textContent = 'Error: ' + e.message;
            }
        }

        async function fetchAlerts() {
            try {
                const res = await fetch(API_BASE + '/defense/alerts/recent?limit=5');
                const data = await res.json();
                const el = document.getElementById('alerts-content');
                if (!data.alerts || data.alerts.length === 0) {
                    el.innerHTML = '<p>No recent alerts.</p>';
                    return;
                }
                let html = '';
                for (const alert of data.alerts) {
                    const levelClass = 'log-level-' + (alert.risk || 'LOW').toUpperCase();
                    html += `<div class="log-entry"><span class="log-time">${alert.timestamp.slice(0,19)}</span><span class="log-level ${levelClass}">[${alert.risk}]</span> ${alert.dest_ip || alert.source_ip} - ${alert.process || '?'} - ${alert.action_taken || ''}</div>`;
                }
                el.innerHTML = html;
            } catch (e) {
                document.getElementById('alerts-content').textContent = 'Error: ' + e.message;
            }
        }

        async function fetchShell() {
            try {
                const res = await fetch(API_BASE + '/shell/history?limit=5');
                const data = await res.json();
                const el = document.getElementById('shell-content');
                if (!data.history || data.history.length === 0) {
                    el.innerHTML = '<p>No shell commands recorded.</p>';
                    return;
                }
                let html = '';
                for (const entry of data.history) {
                    html += `<div class="log-entry"><span class="log-time">${entry.ts || ''}</span> <code>${entry.command || entry.summary}</code></div>`;
                }
                el.innerHTML = html;
            } catch (e) {
                document.getElementById('shell-content').textContent = 'Error: ' + e.message;
            }
        }

        async function fetchRaptor() {
            try {
                const res = await fetch(API_BASE + '/loop/coverage');
                const data = await res.json();
                const el = document.getElementById('raptor-content');
                if (!data.altitudes || data.altitudes.length === 0) {
                    el.innerHTML = '<p>No Raptor coverage data.</p>';
                    return;
                }
                let html = `<p>Campaign: ${data.campaign_id || 'N/A'}</p>`;
                html += `<p>Coverage: ${data.total_covered}/${data.total_altitudes} altitudes</p><ul>`;
                for (const alt of data.altitudes) {
                    const status = alt.covered ? '✅' : '❌';
                    html += `<li>${alt.level}: ${status}</li>`;
                }
                html += '</ul>';
                el.innerHTML = html;
            } catch (e) {
                document.getElementById('raptor-content').textContent = 'Error: ' + e.message;
            }
        }

        // Auto-refresh every 15 seconds
        setInterval(() => {
            fetchStatus();
            fetchAlerts();
            fetchShell();
            fetchRaptor();
        }, 15000);

        // Initial load
        fetchStatus();
        fetchAlerts();
        fetchShell();
        fetchRaptor();
    </script>
</body>
</html>"""
        (path / "index.html").write_text(fallback_html)
    return path

# Ensure static directory is ready before mounting
_static_dir = _ensure_static_dir()
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
logger.info(f"Serving static files from {_static_dir}")

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main War Room HTML page."""
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    # Fallback if index.html missing after mount
    return HTMLResponse(
        "<h1>PHALANX War Room</h1><p>Index not found. Check ui/static/</p>"
    )

# ------------------------------------------------------------------
# Health endpoint with DB connection retry
# ------------------------------------------------------------------
@app.get("/api/health")
async def health_check():
    """Health check endpoint with database connectivity verification (retry 3 times)."""
    db_status = "unknown"
    db_error = None

    try:
        db = get_db()
        if db:
            # Try to execute a simple query with retry
            for attempt in range(3):
                try:
                    db.conn.execute("SELECT 1").fetchone()
                    db_status = "connected"
                    break
                except Exception as e:
                    db_status = "error"
                    db_error = str(e)
                    if attempt < 2:
                        time.sleep(0.5)
        else:
            db_status = "not_available"
            db_error = "Database not initialized"
    except Exception as e:
        db_status = "error"
        db_error = str(e)

    defense_monitor = get_defense()
    defense_active = defense_monitor is not None and defense_monitor.running

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "database_error": db_error,
        "defense_active": defense_active,
        "timestamp": time.time()
    }

# ------------------------------------------------------------------
# System health and status
# ------------------------------------------------------------------
@app.get("/api/system/health")
async def system_health():
    """Basic health check endpoint (alias for /api/health)."""
    return await health_check()

@app.get("/api/system/status")
async def system_status():
    """Return comprehensive system status including optional components."""
    defense_monitor = get_defense()
    status = {
        "version": "3.6",
        "database": {"path": str(db_path), "exists": db_path.exists()},
        "defense": {"active": defense_monitor is not None and defense_monitor.running},
        "oghidra": {"available": OGHIDRA_AVAILABLE},
        "library": {"available": LIBRARY_AVAILABLE},
        "ollama_models": list_ollama_models() if list_ollama_models else [],
        "raptor_loop_engine": {"available": True, "active": False},  # stub; will be updated when RaptorLoopEngine is integrated
        "disposition_ledger": {"available": True, "entries": 0}      # stub
    }
    if config:
        status["ollama_url"] = config.get("ollama", {}).get("url", "http://localhost:11434")
    return status

# ------------------------------------------------------------------
# System Metrics (CPU, memory, disk, network)
# ------------------------------------------------------------------
@app.get("/api/metrics/system")
async def get_system_metrics():
    """Return real-time system metrics: CPU, memory, disk, network connections."""
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        conns = len(psutil.net_connections())
        return {
            "cpu": cpu,
            "memory": {
                "total": mem.total,
                "used": mem.used,
                "free": mem.free,
                "percent": mem.percent
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            },
            "network": {
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv,
                "connections": conns
            },
            "timestamp": time.time()
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get system metrics: {e}")

# ------------------------------------------------------------------
# API Endpoints – Defense
# ------------------------------------------------------------------

@app.get("/api/defense/status")
async def get_defense_status():
    """Return LavaWall status, VPN, Wi-Fi, alerts, and system metrics."""
    monitor = get_defense()
    if monitor and monitor.running and hasattr(monitor, "lava_manager"):
        try:
            metrics = monitor.get_metrics()
            sys_metrics = monitor.lava_manager.get_system_metrics()
            return {
                "status": "active",
                "standby": monitor.standby_mode,
                "vpn": {
                    "active": monitor.lava_manager.vpn_active,
                    "config": monitor.lava_manager.vpn_config_path
                },
                "wifi": {
                    "last_scan": monitor.lava_manager._last_scan_time,
                    "interface": monitor.lava_manager.wifi_interface
                },
                "metrics": sys_metrics,
                "alerts_count": metrics.get("alert_count", 0),
                "connections_seen": metrics.get("total_connections_seen", 0),
                "uptime": str(metrics.get("start_time", "")),
                "oghidra_enabled": getattr(monitor, "oghidra_enabled", False),
            }
        except Exception as e:
            logger.error(f"Error fetching defense status: {e}")
            raise HTTPException(500, f"Failed to get defense status: {e}")
    else:
        return {
            "status": "inactive",
            "standby": True,
            "vpn": {"active": False, "config": ""},
            "wifi": {"last_scan": None, "interface": "wlan0"},
            "metrics": {},
            "alerts_count": 0,
            "connections_seen": 0,
            "uptime": "0:00:00",
            "oghidra_enabled": False,
        }

@app.get("/api/defense/logs")
async def get_defense_logs(limit: int = 50, risk: Optional[str] = Query(None)):
    """Return defense alerts from the database, optionally filtered by risk."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        conn = db.conn
        if risk:
            query = "SELECT * FROM defense_alerts WHERE risk = ? ORDER BY timestamp DESC LIMIT ?"
            params = [risk, limit]
        else:
            query = "SELECT * FROM defense_alerts ORDER BY timestamp DESC LIMIT ?"
            params = [limit]
        cur = conn.execute(query, params)
        logs = [dict(row) for row in cur.fetchall()]
        return {"logs": logs}
    except Exception as e:
        logger.error(f"Error fetching defense logs: {e}")
        raise HTTPException(500, f"Failed to fetch logs: {e}")

@app.get("/api/defense/alerts/recent")
async def get_recent_alerts(limit: int = 10):
    """Return the most recent alerts (short format for dashboard)."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        cur = db.conn.execute(
            "SELECT timestamp, risk, source_ip, dest_ip, process, action_taken FROM defense_alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        alerts = [dict(row) for row in cur.fetchall()]
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Error fetching recent alerts: {e}")
        raise HTTPException(500, f"Failed to fetch alerts: {e}")

@app.get("/api/defense/alerts/count")
async def get_alert_counts():
    """Return counts of alerts per risk level (for pie chart)."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        cur = db.conn.execute(
            "SELECT risk, COUNT(*) as count FROM defense_alerts GROUP BY risk"
        )
        counts = {row["risk"]: row["count"] for row in cur.fetchall()}
        return counts
    except Exception as e:
        logger.error(f"Error fetching alert counts: {e}")
        raise HTTPException(500, f"Failed to fetch counts: {e}")

@app.get("/api/defense/export")
async def export_defense_logs(format: str = "json"):
    """Export defense logs as JSON or CSV."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        cur = db.conn.execute("SELECT * FROM defense_alerts ORDER BY timestamp DESC")
        logs = [dict(row) for row in cur.fetchall()]
        if format == "csv":
            import csv
            from io import StringIO
            output = StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                writer.writerows(logs)
            # FIX: Use plain Response, not JSONResponse
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=defense_logs.csv"}
            )
        return JSONResponse(logs)
    except Exception as e:
        logger.error(f"Error exporting defense logs: {e}")
        raise HTTPException(500, f"Failed to export logs: {e}")

@app.post("/api/defense/standby")
async def set_standby(enabled: bool):
    """Toggle standby mode."""
    monitor = get_defense()
    if not monitor or not monitor.running:
        raise HTTPException(409, "Defense monitor is not active")
    try:
        monitor.set_standby(enabled)
        return {"standby": enabled}
    except Exception as e:
        logger.error(f"Error setting standby: {e}")
        raise HTTPException(500, f"Failed to set standby: {e}")

@app.post("/api/defense/vpn")
async def toggle_vpn(action: str = Query(..., regex="^(on|off)$")):
    """Start or stop VPN."""
    monitor = get_defense()
    if not monitor or not monitor.running:
        raise HTTPException(409, "Defense monitor is not active")
    try:
        result = monitor.lava_manager.toggle_vpn(action)
        return {"message": result}
    except Exception as e:
        logger.error(f"Error toggling VPN: {e}")
        raise HTTPException(500, f"Failed to toggle VPN: {e}")

@app.post("/api/defense/wifi/scan")
async def trigger_wifi_scan(interface: Optional[str] = None, duration: int = 30):
    """Trigger a Wi-Fi scan."""
    monitor = get_defense()
    if not monitor or not monitor.running:
        raise HTTPException(409, "Defense monitor is not active")
    try:
        iface = interface or monitor.lava_manager.wifi_interface
        result = monitor.wifi_scanner.scan(interface=iface, duration=duration)
        return result
    except Exception as e:
        logger.error(f"Error triggering Wi-Fi scan: {e}")
        raise HTTPException(500, f"Failed to scan Wi-Fi: {e}")

@app.get("/api/defense/self-test")
async def self_test():
    """Run a self-test of the defense monitor (if active)."""
    monitor = get_defense()
    if monitor:
        try:
            return monitor.self_test()
        except Exception as e:
            logger.error(f"Error in self-test: {e}")
            raise HTTPException(500, f"Self-test failed: {e}")
    return {"status": "defense_not_active"}

# ------------------------------------------------------------------
# API Endpoints – Swarm / Missions / Findings / Graph
# ------------------------------------------------------------------

@app.get("/api/missions")
async def get_missions():
    """List recent swarm campaigns."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        campaigns = db.list_swarm_campaigns(20)
        return {"missions": campaigns}
    except Exception as e:
        logger.error(f"Error fetching missions: {e}")
        raise HTTPException(500, f"Failed to fetch missions: {e}")

@app.get("/api/findings")
async def get_findings(limit: int = 50):
    """List recent findings from the database."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        findings = db.get_findings(limit)
        return {"findings": findings}
    except Exception as e:
        logger.error(f"Error fetching findings: {e}")
        raise HTTPException(500, f"Failed to fetch findings: {e}")

@app.get("/api/graph")
async def get_graph(campaign_id: Optional[str] = None):
    """Return Shadow Graph nodes and edges for a given campaign or the most recent."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        if campaign_id:
            edges = db.get_graph_edges(campaign_id)
        else:
            campaigns = db.list_swarm_campaigns(1)
            if campaigns:
                campaign_id = campaigns[0]["campaign_id"]
                edges = db.get_graph_edges(campaign_id)
            else:
                edges = []
        nodes = {}
        for edge in edges:
            for node_id in [edge["from_node"], edge["to_node"]]:
                if node_id not in nodes:
                    nodes[node_id] = {"id": node_id, "type": "unknown"}
        if campaign_id:
            loot_items = db.get_loot(campaign_id=campaign_id, limit=500)
            for loot in loot_items:
                data = json.loads(loot["data"])
                if "address" in data:
                    node_id = data["address"]
                    nodes[node_id] = {"id": node_id, "type": "host", "attributes": data}
                elif "name" in data:
                    node_id = data["name"]
                    nodes[node_id] = {"id": node_id, "type": "vulnerability", "attributes": data}
        return {
            "nodes": list(nodes.values()),
            "edges": [{"from": e["from_node"], "to": e["to_node"], "relation": e["relation"]} for e in edges]
        }
    except Exception as e:
        logger.error(f"Error fetching graph: {e}")
        raise HTTPException(500, f"Failed to fetch graph: {e}")

# ------------------------------------------------------------------
# New v3.6 API Endpoints – T3MP3ST + OGhidra
# ------------------------------------------------------------------

@app.get("/api/verify")
async def run_verify(suite: str = "basic"):
    """Run verify-claims benchmark suite."""
    try:
        db = get_db()
        if db is None:
            raise HTTPException(503, "Database not available")
        bench = Benchmark(db, config)
        results = bench.verify_claims(suite)
        return JSONResponse(results)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running verify: {e}")
        raise HTTPException(500, f"Benchmark failed: {e}")

@app.post("/api/reverse/analyze")
async def reverse_analyze(binary_path: str, task_mode: str = "smart"):
    """Run OGhidra analysis on a binary."""
    if not OGHIDRA_AVAILABLE or not run_oghidra_analyze:
        raise HTTPException(501, "OGhidra not available")
    if not Path(binary_path).exists():
        raise HTTPException(404, f"Binary not found: {binary_path}")
    try:
        result = run_oghidra_analyze(binary_path, task_mode=task_mode, config=config)
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"OGhidra analysis failed: {e}")
        raise HTTPException(500, f"OGhidra analysis failed: {e}")

@app.post("/api/reverse/chat")
async def reverse_chat(binary_path: str, query: str):
    """Conversational analysis with OGhidra."""
    if not OGHIDRA_AVAILABLE or not run_oghidra_conversational:
        raise HTTPException(501, "OGhidra chat not available")
    if not Path(binary_path).exists():
        raise HTTPException(404, f"Binary not found: {binary_path}")
    try:
        result = run_oghidra_conversational(binary_path, query, config=config)
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"OGhidra chat failed: {e}")
        raise HTTPException(500, f"OGhidra chat failed: {e}")

@app.get("/api/status")
async def get_feature_status():
    """Return T3MP3ST-style feature status table."""
    defense_monitor = get_defense()
    features = {
        "War Room": {"status": "active", "url": "http://localhost:3333"},
        "verify-claims": {"status": "available" if config else "unknown"},
        "OGhidra Integration": {"status": "available" if OGHIDRA_AVAILABLE else "unavailable"},
        "LavaWall Defense": {"status": "active" if (defense_monitor and defense_monitor.running) else "inactive"},
        "WinStealth": {"status": "available" if config.get("winstealth", {}).get("enabled", False) else "disabled"},
        "8-Operator Swarm": {"status": "available" if LIBRARY_AVAILABLE else "unavailable"},
        "ReAct Tool Agent": {"status": "available" if OGHIDRA_AVAILABLE else "unavailable"},
        "Raptor Loop Engine": {"status": "available", "active": False},  # stub
        "Disposition Ledger": {"status": "available", "entries": 0},    # stub
    }
    return features

@app.post("/api/tools/run")
async def run_tool_endpoint(tool_name: str, params: Dict[str, Any] = {}):
    """Execute a PHALANX tool (requires run_tool from phalanx_tools)."""
    if not run_tool:
        raise HTTPException(501, "Tool execution not available")
    try:
        result = run_tool(tool_name, config=config, **params)
        # Guard against None result
        if result is None:
            result = {"error": "Tool returned None", "rc": -1}
        # Normalise keys for consistent response
        result.setdefault("status", "SUCCESS" if result.get("rc", -1) == 0 else "ERROR")
        result.setdefault("summary", result.get("output", result.get("error", ""))[:200])
        result.setdefault("output", result.get("raw_output", ""))
        return JSONResponse(result)
    except Exception as e:
        logger.error(f"Tool execution failed: {e}")
        raise HTTPException(500, f"Tool execution failed: {e}")

# ------------------------------------------------------------------
# Shell History Endpoint (NEW)
# ------------------------------------------------------------------
@app.get("/api/shell/history")
async def get_shell_history(limit: int = 20, campaign_id: Optional[str] = None):
    """
    Retrieve shell command history from swarm_agent_logs.
    Filters for entries where agent_name is 'shell' or tool_calls contain shell commands.
    """
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        conn = db.conn
        # Query swarm_agent_logs for shell-related entries
        # We'll look for agent_name == 'shell' or tool_calls containing 'shell'
        query = """
            SELECT timestamp, agent_name, input_summary, output_summary, tool_calls
            FROM swarm_agent_logs
            WHERE agent_name = 'shell' OR tool_calls LIKE '%shell%'
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params = [limit]
        if campaign_id:
            query = """
                SELECT timestamp, agent_name, input_summary, output_summary, tool_calls
                FROM swarm_agent_logs
                WHERE (agent_name = 'shell' OR tool_calls LIKE '%shell%')
                AND campaign_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """
            params = [campaign_id, limit]
        cur = conn.execute(query, params)
        rows = cur.fetchall()
        history = []
        for row in rows:
            entry = {
                "ts": row["timestamp"],
                "agent": row["agent_name"],
                "summary": row["input_summary"] or row["output_summary"] or "",
                "command": row["input_summary"] or "",
                "tool_calls": json.loads(row["tool_calls"]) if row["tool_calls"] else None
            }
            # If there's a tool_calls with a shell command, extract it
            if entry["tool_calls"] and isinstance(entry["tool_calls"], dict):
                if "command" in entry["tool_calls"]:
                    entry["command"] = entry["tool_calls"]["command"]
            history.append(entry)
        return {"history": history, "count": len(history)}
    except Exception as e:
        logger.error(f"Error fetching shell history: {e}")
        raise HTTPException(500, f"Failed to fetch shell history: {e}")

# ------------------------------------------------------------------
# Raptor Loop Endpoints (now querying real database tables)
# ------------------------------------------------------------------

@app.get("/api/loop/coverage")
async def get_loop_coverage(campaign_id: Optional[str] = None):
    """
    Return the multi-altitude coverage matrix for the Raptor loop.
    If campaign_id is provided, filter by that campaign; otherwise return latest.
    """
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        if campaign_id:
            coverage_entries = db.get_coverage(campaign_id)
        else:
            # Get the most recent campaign with coverage data
            cur = db.conn.execute(
                "SELECT DISTINCT campaign_id FROM loop_coverage ORDER BY last_checked DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                campaign_id = row["campaign_id"]
                coverage_entries = db.get_coverage(campaign_id)
            else:
                coverage_entries = []
        if not coverage_entries:
            return {
                "campaign_id": campaign_id or "none",
                "altitudes": [],
                "total_covered": 0,
                "total_altitudes": 0
            }
        altitudes = []
        covered_count = 0
        for entry in coverage_entries:
            alt = {
                "level": entry["altitude"],
                "covered": bool(entry["covered"]),
                "last_checked": entry["last_checked"]
            }
            altitudes.append(alt)
            if entry["covered"]:
                covered_count += 1
        return {
            "campaign_id": campaign_id,
            "altitudes": altitudes,
            "total_covered": covered_count,
            "total_altitudes": len(altitudes)
        }
    except Exception as e:
        logger.error(f"Error fetching loop coverage: {e}")
        raise HTTPException(500, f"Failed to fetch loop coverage: {e}")

@app.get("/api/loop/ledger")
async def get_loop_ledger(campaign_id: Optional[str] = None, limit: int = 100):
    """
    Return the disposition ledger entries with evidence receipts.
    """
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        query = "SELECT * FROM disposition_ledger"
        params = []
        if campaign_id:
            query += " WHERE campaign_id = ?"
            params.append(campaign_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cur = db.conn.execute(query, params)
        entries = [dict(row) for row in cur.fetchall()]
        return {
            "campaign_id": campaign_id or "all",
            "entries": entries,
            "count": len(entries)
        }
    except Exception as e:
        logger.error(f"Error fetching loop ledger: {e}")
        raise HTTPException(500, f"Failed to fetch loop ledger: {e}")

@app.get("/api/loop/kb")
async def get_loop_kb(campaign_id: Optional[str] = None):
    """
    Return the monotonic scrutiny knowledge base.
    """
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")
    try:
        query = "SELECT * FROM scrutiny_kb"
        params = []
        if campaign_id:
            query += " WHERE campaign_id = ?"
            params.append(campaign_id)
        cur = db.conn.execute(query, params)
        entities = [dict(row) for row in cur.fetchall()]
        return {
            "campaign_id": campaign_id or "all",
            "entities": entities,
            "count": len(entities)
        }
    except Exception as e:
        logger.error(f"Error fetching loop KB: {e}")
        raise HTTPException(500, f"Failed to fetch loop KB: {e}")

# ------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="PHALANX War Room Dashboard Server")
    parser.add_argument("--host", default=os.environ.get("PHALANX_WARROOM_HOST", "0.0.0.0"), help="Bind address")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PHALANX_WARROOM_PORT", "3333")), help="Bind port")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    parser.add_argument("--static-dir", help="Override static directory path")
    parser.add_argument("--open-browser", action="store_true", help="Open browser after starting")
    args = parser.parse_args()

    if args.static_dir:
        global static_dir
        static_dir = Path(args.static_dir)
        # Ensure the override directory exists and has fallback index
        _ensure_static_dir(static_dir)
        # Re-mount static files
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
        logger.info(f"Static directory overridden to {static_dir}")

    logger.info(f"Starting War Room server on http://{args.host}:{args.port}")
    if args.open_browser:
        webbrowser.open(f"http://{args.host}:{args.port}")

    uvicorn.run(
        "dashboard_server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )

if __name__ == "__main__":
    main()