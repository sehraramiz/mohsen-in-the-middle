import urwid
from mitmproxy import ctx, command
from mitmproxy.addonmanager import Loader
from mitmproxy.log import ALERT
from mitmproxy.tools.console import flowlist, palettes


COLOR_MAP = {
    "red": "highlight_red",
    "orange": "highlight_orange",
    "yellow": "highlight_yellow",
    "green": "highlight_green",
    "blue": "highlight_blue",
    "pink": "highlight_pink",
    "gray": "highlight_gray",
}

_HIGHLIGHT_ENTRIES = [
    ("highlight_red", ("white", "light red")),
    ("highlight_orange", ("white", "brown")),
    ("highlight_yellow", ("black", "yellow")),
    ("highlight_green", ("white", "dark green")),
    ("highlight_blue", ("white", "dark blue")),
    ("highlight_pink", ("white", "dark magenta")),
    ("highlight_gray", ("white", "dark gray")),
    ("highlight_focus", ("white,bold", "dark red")),
]


def _patch_palettes() -> None:
    for name, (fg, bg) in _HIGHLIGHT_ENTRIES:
        if name not in palettes.Palette._fields:
            palettes.Palette._fields.append(name)
        for cls in [
            palettes.LowDark,
            palettes.Dark,
            palettes.SolarizedDark,
            palettes.LowLight,
            palettes.Light,
            palettes.SolarizedLight,
        ]:
            cls.low[name] = (fg, bg)
            if cls.high:
                cls.high[name] = (fg, bg)


def _get_highlight_key(flow) -> str | None:
    color = flow.metadata.get("highlight_color")
    if color:
        return COLOR_MAP.get(color)
    return None


class FlowItemWithHighlight(flowlist.FlowItem):
    _DEFAULT_COLOR: str = "highlight_focus"
    _focus_map: dict | None = None
    _cache_palette: str | None = None
    _cache_transparent: bool | None = None
    _palette_keys: list[str] | None = None
    _highlight_maps: dict[str, dict] | None = None

    def _ensure_cache(self) -> None:
        pn = self.master.options.console_palette
        pt = self.master.options.console_palette_transparent

        if self._cache_palette != pn or self._cache_transparent != pt:
            palette = palettes.palettes[pn].palette(pt)
            self._focus_map = {item[0]: self._DEFAULT_COLOR for item in palette}
            self._palette_keys = [item[0] for item in palette]
            self._highlight_maps = {}
            self._cache_palette = pn
            self._cache_transparent = pt

    def _get_highlight_map(self, key: str) -> dict:
        if self._highlight_maps is None:
            self._highlight_maps = {}
        m = self._highlight_maps.get(key)
        if m is None:
            m = {k: key for k in self._palette_keys}
            self._highlight_maps[key] = m
        return m

    def get_text(self) -> urwid.Widget:
        self._ensure_cache()

        key = _get_highlight_key(self.flow)
        if key:
            highlight_map = self._get_highlight_map(key)
            flow_row = urwid.AttrMap(
                super().get_text(),
                highlight_map,
                self._focus_map,
            )
            return urwid.AttrMap(flow_row, key, self._DEFAULT_COLOR)

        flow_row = urwid.AttrMap(super().get_text(), None, self._focus_map)
        return urwid.AttrMap(flow_row, None, self._DEFAULT_COLOR)


def load(loader: Loader) -> None:
    _patch_palettes()
    flowlist.FlowItem = FlowItemWithHighlight  # type: ignore[assignment]


@command.command("highlight")
def highlight(color: str = "") -> None:
    flow = ctx.master.view.focus.flow
    if not flow:
        return

    if color == "list":
        names = ", ".join(sorted(COLOR_MAP))
        ctx.log(f"available highlight colors: {names}")
        return

    if color:
        if color.lower() not in COLOR_MAP:
            names = ", ".join(sorted(COLOR_MAP))
            ctx.log(f"unknown color '{color}'. available: {names}", ALERT)
            return
        flow.metadata["highlight_color"] = color.lower()
        return

    current = flow.metadata.get("highlight_color")
    if current:
        flow.metadata.pop("highlight_color", None)
    else:
        flow.metadata["highlight_color"] = "red"
