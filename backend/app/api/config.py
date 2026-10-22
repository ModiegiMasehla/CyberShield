"""Backward-compatible shim for the legacy ``app.api.config`` import path.

The canonical configuration module is ``app.config``. Keep this compatibility
module available so existing imports continue to work while the codebase moves to
 the supported location.
"""

from app.config import Settings, settings

__all__ = ["Settings", "settings"]
