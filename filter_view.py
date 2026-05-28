import re
import logging
from collections.abc import Callable

from mitmproxy import ctx, command, http
from mitmproxy.log import ALERT
from mitmproxy.addonmanager import Loader


class FilterPreset:
    __slots__ = ("name", "label", "meta_key", "description", "match_fn", "enabled")

    def __init__(
        self,
        name: str,
        label: str,
        meta_key: str,
        description: str,
        match_fn: Callable[[http.HTTPFlow], bool],
    ) -> None:
        self.name = name
        self.label = label
        self.meta_key = meta_key
        self.description = description
        self.match_fn = match_fn
        self.enabled = False


_PRESETS: dict[str, FilterPreset] = {}
_base_view_filter: str = "~all"

_RE_NOIMAGE_URL = re.compile(r"\.(jpg|jpeg|png|webp|gif|svg|ico|bmp|avif)")
_RE_NOSTYLE_URL = re.compile(r"\.(css|scss|ttf|woff2?|otf|pbf)")
_RE_NOSTYLE_CT = re.compile(r"text/css")
_RE_NOJS_URL = re.compile(r"\.js(\.map)?")
_RE_NOJS_CT = re.compile(r"(application|text)/javascript")


def _register(
    name: str,
    label: str,
    meta_key: str,
    description: str,
    match_fn: Callable[[http.HTTPFlow], bool],
) -> None:
    _PRESETS[name] = FilterPreset(name, label, meta_key, description, match_fn)


def _match_noimage(flow: http.HTTPFlow) -> bool:
    if flow.response:
        ct = flow.response.headers.get("content-type", "")
        if "image/" in ct:
            return True
    return bool(_RE_NOIMAGE_URL.search(flow.request.pretty_url))


def _match_nostyle(flow: http.HTTPFlow) -> bool:
    if flow.response:
        ct = flow.response.headers.get("content-type", "")
        if _RE_NOSTYLE_CT.search(ct):
            return True
    return bool(_RE_NOSTYLE_URL.search(flow.request.pretty_url))


def _match_nojs(flow: http.HTTPFlow) -> bool:
    if flow.response:
        ct = flow.response.headers.get("content-type", "")
        if _RE_NOJS_CT.search(ct):
            return True
    return bool(_RE_NOJS_URL.search(flow.request.pretty_url))


_register("noimage", "NI", "ft_noimage", "Hide image requests", _match_noimage)
_register("nostyle", "NS", "ft_nostyle", "Hide style/font requests", _match_nostyle)
_register("nojs", "NJ", "ft_nojs", "Hide JavaScript requests", _match_nojs)


def _tag_flow(flow: http.HTTPFlow) -> None:
    for preset in _PRESETS.values():
        if preset.match_fn(flow):
            flow.metadata[preset.meta_key] = "true"


def _rebuild_view_filter() -> None:
    blocks: list[str] = []
    for p in _PRESETS.values():
        if p.enabled:
            blocks.append(f'((({p.label} | !~meta "{p.meta_key}: true")))')
    if not blocks:
        ctx.options.view_filter = _base_view_filter
    else:
        combined = " & ".join(blocks)
        if _base_view_filter == "~all":
            ctx.options.view_filter = combined
        else:
            ctx.options.view_filter = _base_view_filter + " & " + combined


def _toggle(name: str) -> None:
    preset = _PRESETS.get(name)
    if not preset:
        return
    preset.enabled = not preset.enabled
    logging.log(ALERT, f"Filter '{name}' {'enabled' if preset.enabled else 'disabled'}")
    _rebuild_view_filter()


def _toggle_multiple(names: list[str]) -> None:
    changed: list[str] = []
    for name in names:
        preset = _PRESETS.get(name)
        if preset:
            preset.enabled = not preset.enabled
            changed.append(f"'{name}' {'enabled' if preset.enabled else 'disabled'}")
    if changed:
        logging.log(ALERT, ", ".join(changed))
        _rebuild_view_filter()


def request(flow: http.HTTPFlow) -> None:
    _tag_flow(flow)


def response(flow: http.HTTPFlow) -> None:
    _tag_flow(flow)


def load(loader: Loader) -> None:
    global _base_view_filter
    if ctx.options.view_filter:
        _base_view_filter = ctx.options.view_filter
    for flow in ctx.master.view:
        _tag_flow(flow)
    logging.log(ALERT, "Filter view addon loaded")


@command.command("noimage")
def noimage_cmd() -> None:
    _toggle("noimage")


@command.command("nostyle")
def nostyle_cmd() -> None:
    _toggle("nostyle")


@command.command("nojs")
def nojs_cmd() -> None:
    _toggle("nojs")


@command.command("nonoise")
def nonoise_cmd() -> None:
    _toggle_multiple(["noimage", "nostyle", "nojs"])


@command.command("filters")
def filters_cmd() -> None:
    lines = ["Filter presets:"]
    for name, p in _PRESETS.items():
        status = "ON" if p.enabled else "off"
        lines.append(f"  {name:12s} [{status}]  {p.description}")
    logging.log(ALERT, "\n".join(lines))


@command.command("check")
def check_cmd() -> None:
    lines = ["Active view filters:"]
    active = [p for p in _PRESETS.values() if p.enabled]
    if not active:
        lines.append("  (none)")
    else:
        for p in active:
            lines.append(f"  {p.label:4s} {p.name:12s} {p.description}")
    inactive = [p for p in _PRESETS.values() if not p.enabled]
    if inactive:
        lines.append("Inactive:")
        for p in inactive:
            lines.append(f"  {p.label:4s} {p.name:12s} {p.description}")
    logging.log(ALERT, "\n".join(lines))
