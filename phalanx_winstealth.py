#!/usr/bin/env python3
"""
PHALANX WinStealth Wrapper – low‑level Windows evasion primitives.

This module provides Python bindings for the WinStealth C library
(formerly SindriKit), allowing PHALANX to leverage advanced Windows
stealth techniques (reflective loading, syscall obfuscation, profile
switching, etc.) directly from Python.

Usage:
    from phalanx_winstealth import WinStealthWrapper, WinStealthError
    wrapper = WinStealthWrapper()
    ctx = wrapper.create_context()
    wrapper.set_profile(ctx, "Win32")
    wrapper.pe_load(ctx, pe_bytes)
    wrapper.execute(ctx, "reflect")
    wrapper.destroy_context(ctx)

Build Instructions:
    WinStealth is a C library that must be built before use.
    On Windows/WSL, run:
        python phalanx_extra.py --build-winstealth
    Or manually:
        1. Install CMake and mingw-w64 (or equivalent)
        2. Clone https://github.com/youssefnoob003/SindriKit.git into phalanx/lib/winstealth
        3. In that directory, run:
            mkdir build && cd build
            cmake .. -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
            make -j$(nproc)
    The library will be placed at phalanx/lib/winstealth/build/libwinstealth.so (or .dll).
    To skip WinStealth entirely, set PHALANX_SKIP_WINSTEALTH=1 in your environment.

    If the library is installed elsewhere, set PHALANX_WINSTEALTH_LIB to the full path.

Dependencies:
    - ctypes (built-in)
    - On Windows/WSL: CMake, mingw-w64 (for building)
    - On other platforms, WinStealth is not required and will be skipped.
"""

import ctypes
import ctypes.util
import os
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
from contextlib import contextmanager

logger = logging.getLogger("phalanx.winstealth")

# ------------------------------------------------------------------
# Path to the built WinStealth shared library
# ------------------------------------------------------------------
# Try to import BASE_DIR from core for consistent path resolution
try:
    from phalanx_core import BASE_DIR
except ImportError:
    # Fallback: determine BASE_DIR relative to this file or current directory
    try:
        BASE_DIR = Path(__file__).parent / "phalanx"
        if not BASE_DIR.exists():
            BASE_DIR = Path.cwd() / "phalanx"
    except NameError:
        BASE_DIR = Path.cwd() / "phalanx"

WINSTEALTH_LIB_NAME = "libwinstealth.so" if os.name != "nt" else "winstealth.dll"

# Default path
DEFAULT_WINSTEALTH_LIB_PATH = BASE_DIR / "lib" / "winstealth" / "build" / WINSTEALTH_LIB_NAME

# If the library is placed elsewhere, user can set environment variable
ENV_WINSTEALTH_LIB = os.environ.get("PHALANX_WINSTEALTH_LIB")
if ENV_WINSTEALTH_LIB:
    DEFAULT_WINSTEALTH_LIB_PATH = Path(ENV_WINSTEALTH_LIB)

# Additional fallback paths
FALLBACK_PATHS = [
    Path.cwd() / "phalanx" / "lib" / "winstealth" / "build" / WINSTEALTH_LIB_NAME,
    Path.cwd() / "lib" / "winstealth" / "build" / WINSTEALTH_LIB_NAME,
    Path.home() / ".phalanx" / "lib" / "winstealth" / "build" / WINSTEALTH_LIB_NAME,
]

# ------------------------------------------------------------------
# Exceptions
# ------------------------------------------------------------------
class WinStealthError(Exception):
    """Base exception for WinStealth wrapper errors."""
    pass

class WinStealthLibNotFoundError(WinStealthError):
    """Raised when the WinStealth shared library cannot be found."""
    pass

class WinStealthContextError(WinStealthError):
    """Raised when a context operation fails."""
    pass

class WinStealthLibLoadError(WinStealthError):
    """Raised when the library fails to load (e.g., missing dependencies)."""
    pass

# ------------------------------------------------------------------
# C Structures (mirroring WinStealth's public types)
# ------------------------------------------------------------------
class WinStealthContext(ctypes.Structure):
    """
    Opaque context structure for WinStealth.
    Actual layout is defined in winstealth.h; we treat it as opaque.
    """
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        # Additional fields are not needed for Python binding.
    ]

class WinStealthVersion(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_uint32),
        ("minor", ctypes.c_uint32),
        ("patch", ctypes.c_uint32),
    ]

# ------------------------------------------------------------------
# Helper function to locate the library
# ------------------------------------------------------------------
def _locate_winstealth_lib() -> Path:
    """
    Locate the WinStealth shared library.
    Returns a Path if found, otherwise raises WinStealthLibNotFoundError.
    """
    # Check environment variable first
    if ENV_WINSTEALTH_LIB:
        env_path = Path(ENV_WINSTEALTH_LIB)
        if env_path.exists():
            return env_path
        else:
            logger.warning(f"PHALANX_WINSTEALTH_LIB set to {env_path} but file not found.")

    # Check default path
    if DEFAULT_WINSTEALTH_LIB_PATH.exists():
        return DEFAULT_WINSTEALTH_LIB_PATH

    # Check fallback paths
    for path in FALLBACK_PATHS:
        if path.exists():
            logger.info(f"Found WinStealth library at {path}")
            return path

    # If still not found, provide helpful error
    raise WinStealthLibNotFoundError(
        f"WinStealth library not found.\n"
        f"Expected locations:\n"
        f"  - {DEFAULT_WINSTEALTH_LIB_PATH}\n"
        f"  - {FALLBACK_PATHS}\n"
        "Build WinStealth first:\n"
        "  1. python phalanx_extra.py --build-winstealth\n"
        "  2. Or set PHALANX_SKIP_WINSTEALTH=1 to disable WinStealth.\n"
        "  3. Or set PHALANX_WINSTEALTH_LIB to the full path of the library.\n"
        "See module docstring for manual build instructions."
    )

# ------------------------------------------------------------------
# WinStealthWrapper – main interface
# ------------------------------------------------------------------
class WinStealthWrapper:
    """
    Python wrapper for WinStealth shared library.

    Manages loading of the library, context creation/destruction,
    profile switching, PE loading, and execution of techniques.
    """

    def __init__(self, lib_path: Optional[Path] = None):
        """
        Initialize wrapper and load the WinStealth library.

        Args:
            lib_path: Optional path to the shared library. If not provided,
                      attempts to locate it automatically.
        """
        self.lib_path = lib_path or _locate_winstealth_lib()
        self._lib = None
        self._loaded = False
        self._load_library()

    def _load_library(self):
        """Load the WinStealth shared library using ctypes."""
        if not self.lib_path.exists():
            raise WinStealthLibNotFoundError(
                f"WinStealth library not found at {self.lib_path}.\n"
                "Build WinStealth first:\n"
                "  1. python phalanx_extra.py --build-winstealth\n"
                "  2. Or set PHALANX_SKIP_WINSTEALTH=1 to disable WinStealth.\n"
                "  3. Or place the built library at the path above."
            )
        try:
            self._lib = ctypes.CDLL(str(self.lib_path))
            self._init_function_prototypes()
            self._loaded = True
            logger.info(f"WinStealth library loaded from {self.lib_path}")
        except OSError as e:
            # Common causes: missing dependencies (libc, etc.) or incompatible architecture
            raise WinStealthLibLoadError(
                f"Failed to load WinStealth library from {self.lib_path}: {e}\n"
                "This may be due to missing system dependencies or an incompatible architecture.\n"
                "On Linux, ensure libc and other runtime libraries are installed.\n"
                "On Windows, ensure the Visual C++ Redistributable is installed.\n"
                "If the problem persists, set PHALANX_SKIP_WINSTEALTH=1 to disable WinStealth."
            ) from e

    def _init_function_prototypes(self):
        """Set argument and return types for all used WinStealth functions."""
        lib = self._lib

        # Context management
        lib.ws_context_create.argtypes = []
        lib.ws_context_create.restype = ctypes.POINTER(WinStealthContext)

        lib.ws_context_destroy.argtypes = [ctypes.POINTER(WinStealthContext)]
        lib.ws_context_destroy.restype = None

        # Profile management
        lib.ws_set_profile.argtypes = [ctypes.POINTER(WinStealthContext), ctypes.c_char_p]
        lib.ws_set_profile.restype = ctypes.c_int

        lib.ws_get_profile.argtypes = [ctypes.POINTER(WinStealthContext)]
        lib.ws_get_profile.restype = ctypes.c_char_p

        lib.ws_list_profiles.argtypes = []
        lib.ws_list_profiles.restype = ctypes.c_char_p  # JSON string or comma-separated

        # PE loading
        lib.ws_pe_load.argtypes = [
            ctypes.POINTER(WinStealthContext),
            ctypes.c_char_p,   # optional file path (NULL if using memory)
            ctypes.c_void_p,   # pointer to PE bytes (if using memory)
        ]
        lib.ws_pe_load.restype = ctypes.c_int

        # Execution
        lib.ws_execute.argtypes = [ctypes.POINTER(WinStealthContext), ctypes.c_char_p]
        lib.ws_execute.restype = ctypes.c_int

        # Error handling
        lib.ws_last_error.argtypes = [ctypes.POINTER(WinStealthContext)]
        lib.ws_last_error.restype = ctypes.c_char_p

        # Version info
        lib.ws_version.argtypes = []
        lib.ws_version.restype = ctypes.POINTER(WinStealthVersion)

        # Obfuscation settings (if exposed)
        lib.ws_set_hash_algo.argtypes = [ctypes.c_char_p]
        lib.ws_set_hash_algo.restype = ctypes.c_int

        lib.ws_set_randomize_seed.argtypes = [ctypes.c_uint32]
        lib.ws_set_randomize_seed.restype = None

        # Syscall resolution strategy (if exposed)
        lib.ws_set_syscall_strategy.argtypes = [ctypes.c_char_p]
        lib.ws_set_syscall_strategy.restype = ctypes.c_int

        # Debug mode
        lib.ws_set_debug.argtypes = [ctypes.c_int]
        lib.ws_set_debug.restype = None

    # ------------------------------------------------------------------
    # Low-level wrappers
    # ------------------------------------------------------------------
    def create_context(self) -> int:
        """
        Create a new WinStealth context.

        Returns:
            int: pointer to the context (cast to int).
        Raises:
            WinStealthContextError: if context creation fails.
        """
        if not self._loaded:
            raise WinStealthError("WinStealth library not loaded")
        ctx = self._lib.ws_context_create()
        if not ctx:
            raise WinStealthContextError("ws_context_create returned NULL")
        # Return the pointer address correctly
        return ctypes.addressof(ctx.contents)

    def destroy_context(self, ctx_ptr: int) -> None:
        """
        Destroy a WinStealth context and free its resources.

        Args:
            ctx_ptr: integer pointer previously returned by create_context.
        """
        if ctx_ptr == 0 or not self._loaded:
            return
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        if ctx:
            self._lib.ws_context_destroy(ctx)

    @contextmanager
    def context(self):
        """Context manager for automatic cleanup of a WinStealth context."""
        ctx_ptr = self.create_context()
        try:
            yield ctx_ptr
        finally:
            self.destroy_context(ctx_ptr)

    def set_profile(self, ctx_ptr: int, profile: str) -> bool:
        """
        Set the execution profile for the context.

        Args:
            ctx_ptr: context pointer.
            profile: name of the profile ("Win32", "Native", "Custom").

        Returns:
            bool: True on success, False on failure.
        """
        if not self._loaded:
            return False
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        try:
            return self._lib.ws_set_profile(ctx, profile.encode()) == 0
        except Exception as e:
            logger.error(f"ws_set_profile failed: {e}")
            return False

    def get_profile(self, ctx_ptr: int) -> str:
        """Get the current profile name for the context."""
        if not self._loaded:
            return ""
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        try:
            result = self._lib.ws_get_profile(ctx)
            return result.decode() if result else ""
        except Exception as e:
            logger.error(f"ws_get_profile failed: {e}")
            return ""

    def list_profiles(self) -> List[str]:
        """Return a list of available execution profiles."""
        if not self._loaded:
            return []
        try:
            result = self._lib.ws_list_profiles()
            if not result:
                return []
            raw = result.decode()
            if raw.startswith('['):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    pass
            return [p.strip() for p in raw.split(',') if p.strip()]
        except Exception as e:
            logger.error(f"ws_list_profiles failed: {e}")
            return []

    def pe_load(self, ctx_ptr: int, pe_data: bytes) -> bool:
        """
        Load a PE image from raw bytes into the context.

        Args:
            ctx_ptr: context pointer.
            pe_data: bytes containing the PE image.

        Returns:
            bool: True on success.
        """
        if not self._loaded:
            return False
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        data_ptr = ctypes.cast(pe_data, ctypes.c_void_p)
        try:
            return self._lib.ws_pe_load(ctx, None, data_ptr) == 0
        except Exception as e:
            logger.error(f"ws_pe_load (memory) failed: {e}")
            return False

    def pe_load_from_file(self, ctx_ptr: int, file_path: Union[str, Path]) -> bool:
        """
        Load a PE image from a file.

        Args:
            ctx_ptr: context pointer.
            file_path: path to PE file.

        Returns:
            bool: True on success.
        """
        if not self._loaded:
            return False
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        path_str = str(file_path).encode()
        try:
            return self._lib.ws_pe_load(ctx, path_str, None) == 0
        except Exception as e:
            logger.error(f"ws_pe_load (file) failed: {e}")
            return False

    def execute(self, ctx_ptr: int, command: str) -> bool:
        """
        Execute a technique/command using the context.

        Known commands: "reflect" (reflective load), "inject", "unhook", etc.

        Args:
            ctx_ptr: context pointer.
            command: command string.

        Returns:
            bool: True on success.
        """
        if not self._loaded:
            return False
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        try:
            return self._lib.ws_execute(ctx, command.encode()) == 0
        except Exception as e:
            logger.error(f"ws_execute failed: {e}")
            return False

    def last_error(self, ctx_ptr: int) -> str:
        """Retrieve the last error message for the context."""
        if not self._loaded:
            return "WinStealth library not loaded"
        ctx = ctypes.cast(ctx_ptr, ctypes.POINTER(WinStealthContext))
        try:
            err = self._lib.ws_last_error(ctx)
            return err.decode() if err else ""
        except Exception as e:
            logger.error(f"ws_last_error failed: {e}")
            return ""

    def version(self) -> Dict[str, int]:
        """Get the WinStealth library version."""
        if not self._loaded:
            return {"major": 0, "minor": 0, "patch": 0}
        try:
            ver = self._lib.ws_version()
            if not ver:
                return {"major": 0, "minor": 0, "patch": 0}
            return {
                "major": ver.contents.major,
                "minor": ver.contents.minor,
                "patch": ver.contents.patch,
            }
        except Exception as e:
            logger.error(f"ws_version failed: {e}")
            return {"major": 0, "minor": 0, "patch": 0}

    # ------------------------------------------------------------------
    # Obfuscation settings (compile-time)
    # ------------------------------------------------------------------
    def set_hash_algo(self, algo: str) -> bool:
        """
        Set the hash algorithm for symbol obfuscation (e.g., "DJB2", "FNV1A").

        Returns True on success.
        """
        if not self._loaded:
            return False
        try:
            return self._lib.ws_set_hash_algo(algo.encode()) == 0
        except Exception as e:
            logger.error(f"ws_set_hash_algo failed: {e}")
            return False

    def set_randomize_seed(self, seed: int) -> None:
        """Set a random seed for compile-time obfuscation (0 to disable)."""
        if not self._loaded:
            return
        try:
            self._lib.ws_set_randomize_seed(ctypes.c_uint32(seed))
        except Exception as e:
            logger.error(f"ws_set_randomize_seed failed: {e}")

    def set_syscall_strategy(self, strategy: str) -> bool:
        """
        Set the syscall resolution strategy: "hellsgate", "halosgate", "veles", etc.
        """
        if not self._loaded:
            return False
        try:
            return self._lib.ws_set_syscall_strategy(strategy.encode()) == 0
        except Exception as e:
            logger.error(f"ws_set_syscall_strategy failed: {e}")
            return False

    def set_debug(self, enabled: bool) -> None:
        """Enable or disable debug output from WinStealth."""
        if not self._loaded:
            return
        try:
            self._lib.ws_set_debug(1 if enabled else 0)
        except Exception as e:
            logger.error(f"ws_set_debug failed: {e}")

    # ------------------------------------------------------------------
    # High-level helpers for PHALANX
    # ------------------------------------------------------------------
    def reflective_load_pe(self, pe_bytes: bytes, profile: str = "Win32") -> Dict[str, Any]:
        """
        Convenience method: create a context, set profile, load PE, execute reflectively.

        Args:
            pe_bytes: raw PE image bytes.
            profile: execution profile name.

        Returns:
            dict: {"success": bool, "context": int (if success), "error": str (if failure)}
                  If success is True, the context is left alive for the caller to destroy.
                  If success is False, the context is also left alive (caller should destroy).
        """
        ctx_ptr = None
        try:
            ctx_ptr = self.create_context()
            if not self.set_profile(ctx_ptr, profile):
                return {"success": False, "error": f"Failed to set profile '{profile}'", "context": ctx_ptr}
            if not self.pe_load(ctx_ptr, pe_bytes):
                return {"success": False, "error": "PE load failed", "context": ctx_ptr}
            if not self.execute(ctx_ptr, "reflect"):
                return {"success": False, "error": "Reflective execution failed", "context": ctx_ptr}
            return {"success": True, "context": ctx_ptr}
        except Exception as e:
            # Context is left alive; caller should destroy it.
            return {"success": False, "error": str(e), "context": ctx_ptr}

    def reflective_load_pe_from_file(self, file_path: Union[str, Path], profile: str = "Win32") -> Dict[str, Any]:
        """
        Load and reflectively execute a PE from a file.

        Returns:
            dict: same as reflective_load_pe.
        """
        try:
            with open(file_path, "rb") as f:
                pe_bytes = f.read()
            return self.reflective_load_pe(pe_bytes, profile)
        except Exception as e:
            return {"success": False, "error": str(e), "context": None}

# ------------------------------------------------------------------
# Global instance (singleton) for convenience
# ------------------------------------------------------------------
_winstealth_wrapper: Optional[WinStealthWrapper] = None

def get_winstealth() -> WinStealthWrapper:
    """Get a global WinStealthWrapper instance (singleton)."""
    global _winstealth_wrapper
    if _winstealth_wrapper is None:
        _winstealth_wrapper = WinStealthWrapper()
    return _winstealth_wrapper

# ------------------------------------------------------------------
# Module-level exports
# ------------------------------------------------------------------
__all__ = [
    "WinStealthWrapper",
    "WinStealthError",
    "WinStealthLibNotFoundError",
    "WinStealthLibLoadError",
    "WinStealthContextError",
    "get_winstealth",
]

# ------------------------------------------------------------------
# Self-test (if run as main)
# ------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    print("PHALANX WinStealth Wrapper")
    try:
        wrapper = get_winstealth()
        print(f"WinStealth version: {wrapper.version()}")
        print(f"Available profiles: {wrapper.list_profiles()}")
        with wrapper.context() as ctx:
            print(f"Current profile: {wrapper.get_profile(ctx)}")
    except WinStealthLibNotFoundError as e:
        print(f"Library not found: {e}", file=sys.stderr)
        sys.exit(1)
    except WinStealthLibLoadError as e:
        print(f"Library load error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)