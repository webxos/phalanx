#!/usr/bin/env python3
import subprocess
import time
import pexpect
from typing import Dict

_TMUX_AVAILABLE = subprocess.run(["which", "tmux"], capture_output=True).returncode == 0
_PEXPECT_AVAILABLE = True

def run_interactive(tool: str, command: str, timeout: int = 60, expect_prompt: str = None, send_input: str = None) -> Dict:
    if not (_TMUX_AVAILABLE and _PEXPECT_AVAILABLE):
        return {"output": "", "error": "tmux or pexpect not available", "rc": -1}
    session = f"phalanx_{tool}_{int(time.time())}"
    try:
        subprocess.run(["tmux", "new-session", "-d", "-s", session, tool], check=True)
        subprocess.run(["tmux", "send-keys", "-t", session, command, "Enter"], check=True)
        if expect_prompt:
            # Wait for prompt then send additional input
            child = pexpect.spawn(f"tmux capture-pane -p -t {session}")
            child.expect(expect_prompt, timeout=timeout)
            if send_input:
                subprocess.run(["tmux", "send-keys", "-t", session, send_input, "Enter"], check=True)
        child = pexpect.spawn(f"tmux capture-pane -p -t {session}")
        child.expect(pexpect.EOF, timeout=timeout)
        output = child.before.decode("utf-8", errors="ignore")
        subprocess.run(["tmux", "kill-session", "-t", session])
        return {"output": output, "error": None, "rc": 0}
    except Exception as e:
        return {"output": "", "error": str(e), "rc": -1}
