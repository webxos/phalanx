"""
PHALANX v3.6 Cross-Platform – Autonomous Pentesting Framework
This __init__.py allows Python to treat the project directory as a package,
enabling absolute imports like 'from phalanx_core import ...' when running
from any location (especially important for module resolution).

WinStealth Integration:
- Added WinStealth low‑level Windows evasion library support (reflective PE loading, syscall obfuscation, etc.).
- Enable via config "winstealth.enabled": true or --winstealth flag in demo/agentic modes.
- See phalanx_winstealth.py for Python bindings.

WinStealthWrapper raises NotImplementedError if the library is not built – catch it when calling.
"""

__version__ = "3.6"
__author__ = "PHALANX Team"

# Optional import – gracefully degrades if the library is not built
try:
    from phalanx_winstealth import WinStealthWrapper
except ImportError:
    WinStealthWrapper = None

# Replace None with a placeholder that raises a clear error when used
if WinStealthWrapper is None:
    class WinStealthWrapper:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError(
                "WinStealthWrapper is not available because the phalanx_winstealth "
                "library was not built on this system."
            )

# Export public symbols (always includes the wrapper, now safe to use)
__all__ = [
    '__version__',
    '__author__',
    'WinStealthWrapper',
]