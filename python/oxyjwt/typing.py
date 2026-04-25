"""Typing helpers for OxyJWT users."""

from __future__ import annotations

from typing import Any, Mapping, TypeAlias

Claims: TypeAlias = Mapping[str, Any]
Headers: TypeAlias = Mapping[str, Any]
