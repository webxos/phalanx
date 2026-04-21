#!/usr/bin/env python3
"""
PHALANX v3.3 – Standalone planner CLI.
Generates an engagement plan (OPPLAN) for a given target using the PlannerAgent.
No changes required for /swarm – the swarm orchestrator uses the same planning functions internally.

Enhanced with:
- Graceful fallback when agent components are missing
- Proper config path resolution
- Error handling for missing Ollama or Gateway
- Fixed missing load_config import (now uses direct JSON loading)
- Improved static plan structure to match RoE expectations
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Optional

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("phalanx_planner")

# ------------------------------------------------------------------
# Add parent directory to path for local imports
# ------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.absolute()
sys.path.insert(0, str(SCRIPT_DIR))

# ------------------------------------------------------------------
# Try to import core components with graceful fallback
# ------------------------------------------------------------------
try:
    from phalanx_core import BASE_DIR
except ImportError as e:
    logger.error(f"Failed to import phalanx_core: {e}")
    logger.error("Make sure you are running from the PHALANX root directory.")
    sys.exit(1)

try:
    from phalanx_tools import Gateway, TOOL_REGISTRY
except ImportError as e:
    logger.error(f"Failed to import phalanx_tools: {e}")
    sys.exit(1)

# ------------------------------------------------------------------
# Simple config loader (since load_config is not exported from core)
# ------------------------------------------------------------------
def _load_config(config_path: Optional[Path] = None) -> Dict:
    """Load configuration from a JSON file, or return defaults."""
    defaults = {
        "ollama": {
            "url": "http://localhost:11434",
            "default_model": "qwen2.5:7b",
            "fast_model": "qwen2.5:1.5b"
        },
        "sandbox": {"enabled": False}
    }
    if config_path and config_path.exists():
        try:
            data = json.loads(config_path.read_text())
            # Merge with defaults to ensure required keys exist
            for key, value in defaults.items():
                if key not in data:
                    data[key] = value
            return data
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
    return defaults

# Lazy import for planning function (may depend on agent components)
def _get_planning_function():
    """Import generate_engagement_plan only when needed, with fallback."""
    try:
        from phalanx_library import generate_engagement_plan
        return generate_engagement_plan
    except ImportError as e:
        logger.warning(f"Agentic planning not available: {e}")
        return None

# ------------------------------------------------------------------
# Fallback plan generator (static, no LLM)
# ------------------------------------------------------------------
def _static_plan(target: str, user_input: str = "") -> Dict:
    """
    Generate a simple static plan when PlannerAgent is unavailable.
    Structure matches what RoEEnforcer expects in phalanx_core.
    """
    logger.info("Using static plan generator (PlannerAgent not available)")
    return {
        "objectives": [
            {"description": f"Reconnaissance of {target}", "mitre_tags": ["T1595"], "evidence_guided": False},
            {"description": f"Vulnerability assessment of {target}", "mitre_tags": ["T1595.002"], "evidence_guided": False},
            {"description": f"Exploitation of {target}", "mitre_tags": ["T1190"], "evidence_guided": True}
        ],
        "roe": {
            "allowed_targets": [target],
            "excluded_targets": [],
            "forbidden_actions": ["data_exfiltration", "destruction"],
            "require_human_confirm": ["privilege_escalation", "exploit"],
            "max_severity": "critical"
        },
        "user_input": user_input,
        "generated_by": "static_fallback"
    }

# ------------------------------------------------------------------
# Main: load config, init gateway, generate plan
# ------------------------------------------------------------------
def main():
    # Parse command line
    if len(sys.argv) < 2:
        print("Usage: python phalanx_planner.py <target> [user_input]")
        print("Example: python phalanx_planner.py example.com \"Focus on web apps\"")
        sys.exit(1)

    target = sys.argv[1]
    user_input = sys.argv[2] if len(sys.argv) > 2 else ""

    # Locate config file
    config_path = Path("config.json")
    if not config_path.exists():
        # Try default location in phalanx/config
        default_config = BASE_DIR / "config" / "config.json"
        if default_config.exists():
            config_path = default_config
        else:
            logger.warning("No config.json found. Using defaults.")
            config_path = None

    # Load configuration
    config = _load_config(config_path)

    # Initialize Gateway (may be None if unreachable)
    gateway = None
    try:
        gateway = Gateway(config, TOOL_REGISTRY)
        if not gateway.check_ollama():
            logger.warning("Ollama not reachable. Static plan will be used.")
            gateway = None
    except Exception as e:
        logger.error(f"Failed to initialize Gateway: {e}")
        gateway = None

    # Try to get planning function
    plan_func = _get_planning_function()

    # Generate plan
    if plan_func and gateway:
        try:
            logger.info(f"Generating AI-driven plan for {target}")
            plan = plan_func(target, user_input, gateway)
        except Exception as e:
            logger.error(f"AI planning failed: {e}. Falling back to static plan.")
            plan = _static_plan(target, user_input)
    else:
        plan = _static_plan(target, user_input)

    # Output plan as JSON
    print(json.dumps(plan, indent=2))

if __name__ == "__main__":
    main()
