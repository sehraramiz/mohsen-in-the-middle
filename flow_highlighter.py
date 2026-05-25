import urwid
from mitmproxy import ctx, http, command
from mitmproxy.addonmanager import Loader
from mitmproxy.tools.console import flowlist, palettes


class FlowItemWithHighlight(flowlist.FlowItem):
    _DEFAULT_COLOR: str = "heading"
    _focus_map: dict | None = None
    _highlight_map: dict | None = None
    _cache_palette: str | None = None
    _cache_transparent: bool | None = None

    def __init__(self, master: object, flow: http.HTTPFlow) -> None:
        super().__init__(master, flow)

    def _ensure_cache(self) -> None:
        pn = self.master.options.console_palette
        pt = self.master.options.console_palette_transparent
        if (
            FlowItemWithHighlight._cache_palette != pn
            or FlowItemWithHighlight._cache_transparent != pt
        ):
            palette = palettes.palettes[pn].palette(pt)
            FlowItemWithHighlight._focus_map = {
                item[0]: FlowItemWithHighlight._DEFAULT_COLOR for item in palette
            }
            FlowItemWithHighlight._highlight_map = {
                item[0]: "focusfield_error" for item in palette
            }
            FlowItemWithHighlight._cache_palette = pn
            FlowItemWithHighlight._cache_transparent = pt

    def get_text(self) -> urwid.Widget:
        self._ensure_cache()
        if self.flow.metadata.get("highlighted", False):
            flow_row = urwid.AttrMap(
                super().get_text(),
                FlowItemWithHighlight._highlight_map,
                FlowItemWithHighlight._focus_map,
            )
            return urwid.AttrMap(
                flow_row, "focusfield_error", FlowItemWithHighlight._DEFAULT_COLOR
            )
        flow_row = urwid.AttrMap(
            super().get_text(), None, FlowItemWithHighlight._focus_map
        )
        return urwid.AttrMap(flow_row, None, FlowItemWithHighlight._DEFAULT_COLOR)


def load(loader: Loader) -> None:
    flowlist.FlowItem = FlowItemWithHighlight


@command.command("highlight")
def highlight() -> None:
    flow = ctx.master.view.focus.flow
    if not flow:
        return
    flow.metadata["highlighted"] = not flow.metadata.get("highlighted", False)
