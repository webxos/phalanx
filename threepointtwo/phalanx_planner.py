#!/usr/bin/env python3
import json, sys
from pathlib import Path
from phalanx_core import generate_engagement_plan, load_config, BASE_DIR
from phalanx_tools import Gateway

if __name__ == "__main__":
    config = load_config(BASE_DIR / "config.json")
    gw = Gateway(config)
    if len(sys.argv) > 1:
        target = sys.argv[1]
        plan = generate_engagement_plan(target, "", gw)
        print(json.dumps(plan, indent=2))
    else:
        print("Usage: python phalanx_planner.py <target>")
