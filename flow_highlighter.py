import urwid
from mitmproxy import ctx
from mitmproxy.tools.console import flowlist, palettes
from mitmproxy import command


class FlowItemWithHighlight(flowlist.FlowItem):
    def __init__(self, master, flow):
        self.default_color = "heading"
        super().__init__(master, flow)
        urwid.WidgetWrap.__init__(self, self.get_text())

    def get_text(self):
        palette = palettes.palettes[self.master.options.console_palette].palette(
            self.master.options.console_palette_transparent
        )
        focus_map = {item[0]: self.default_color for item in palette}

        highlighted = self.flow.metadata.get("highlighted", False)
        if highlighted:
            highlight_color = "focusfield_error"
            highlight_map = {item[0]: highlight_color for item in palette}
            flow_row = urwid.AttrMap(super().get_text(), highlight_map, focus_map)
            return urwid.AttrMap(flow_row, highlight_color, self.default_color)
        else:
            flow_row = urwid.AttrMap(super().get_text(), None, focus_map)
            return urwid.AttrMap(flow_row, None, self.default_color)


def load(loader):
    flowlist.FlowItem = FlowItemWithHighlight


@command.command("highlight")
def highlight() -> None:
    flow = ctx.master.view.focus.flow
    if not flow:
        return
    flow.metadata["highlighted"] = not flow.metadata.get("highlighted", False)
