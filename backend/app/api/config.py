"""Deprecated duplicate config module.

This module intentionally fails to import to prevent it from shadowing the canonical
``app.config`` settings object. Import the settings from ``app.config`` instead.
"""

raise ImportError("app.api.config has been removed; use app.config instead")