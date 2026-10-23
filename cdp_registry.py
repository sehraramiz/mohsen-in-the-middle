from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cdp_manager import CdpManager

_manager: CdpManager | None = None


def register(m: CdpManager) -> CdpManager:
    """Register the manager, keeping the first one.

    A second registration means the addon module was executed twice (e.g. an
    addon imported ``cdp_manager`` directly instead of going through this
    registry). Reusing the canonical instance prevents a second CDP poll loop
    and duplicate Chrome connections.
    """
    global _manager
    if _manager is not None and _manager is not m:
        return _manager
    _manager = m
    return m


def get() -> CdpManager | None:
    return _manager
