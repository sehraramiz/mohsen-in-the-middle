"""Last `:chains` capture, shared between `chains.py` and its consumers.

mitmproxy loads `-s` scripts under `__mitmproxy_script__.<name>`, so
`from chains import addon` elsewhere would import a second, empty module
instance rather than the running addon. This registry is the hand-off point —
the same idea as `cdp_registry.py`, but for plain data instead of a manager.

`chains.end()` publishes `(flows, links)`; consumers (e.g.
`oauth_marker_v2.py`) read it on demand.
"""

_capture: tuple[list, list] | None = None


def publish(flows: list, links: list) -> None:
    global _capture
    _capture = (flows, links)


def get() -> tuple[list, list] | None:
    return _capture


def clear() -> None:
    global _capture
    _capture = None
