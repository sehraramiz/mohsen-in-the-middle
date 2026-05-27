import urwid
from mitmproxy import ctx, command
from mitmproxy.addonmanager import Loader
from mitmproxy.tools.console import flowlist, palettes


_HIGHLIGHT_COLOR = "focusfield_error"


class FlowItemWithHighlight(flowlist.FlowItem):
    _DEFAULT_COLOR: str = "heading"
    _focus_map: dict | None = None
    _highlight_map: dict | None = None
    _cache_palette: str | None = None
    _cache_transparent: bool | None = None

    def _ensure_cache(self) -> None:
        pn = self.master.options.console_palette
        pt = self.master.options.console_palette_transparent

        if self._cache_palette != pn or self._cache_transparent != pt:
            palette = palettes.palettes[pn].palette(pt)
            self._focus_map = {item[0]: self._DEFAULT_COLOR for item in palette}
            self._highlight_map = {item[0]: _HIGHLIGHT_COLOR for item in palette}
            self._cache_palette = pn
            self._cache_transparent = pt

    def get_text(self) -> urwid.Widget:
        self._ensure_cache()

        if self.flow.metadata.get("highlighted", False):
            flow_row = urwid.AttrMap(
                super().get_text(),
                self._highlight_map,
                self._focus_map,
            )
            return urwid.AttrMap(flow_row, _HIGHLIGHT_COLOR, self._DEFAULT_COLOR)

        flow_row = urwid.AttrMap(super().get_text(), None, self._focus_map)
        return urwid.AttrMap(flow_row, None, self._DEFAULT_COLOR)


def load(loader: Loader) -> None:
    flowlist.FlowItem = FlowItemWithHighlight  # type: ignore[assignment]


@command.command("highlight")
def highlight() -> None:
    flow = ctx.master.view.focus.flow
    if not flow:
        return
    flow.metadata["highlighted"] = not flow.metadata.get("highlighted", False)
