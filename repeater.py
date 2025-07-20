import logging
from datetime import datetime
from contextvars import ContextVar

from mitmproxy import ctx
from mitmproxy import command
from mitmproxy import hooks
from mitmproxy.log import ALERT


last_view_filter: ContextVar[str] = ContextVar("last_view_filter", default="")


@command.command("repeat")
def mark_for_repeater() -> None:
    """Send flow to repeater (mark as R)"""

    flow = ctx.master.view.focus.flow
    if not flow:
        return

    flow_copy = flow.copy()
    flow_copy.marked = "R"
    flow_copy.timestamp_created = datetime.now().timestamp()
    ctx.master.view.add([flow_copy])
    logging.log(ALERT, "Sent a copy to Repeater")
    ctx.master.addons.trigger(hooks.UpdateHook([flow]))


@command.command("repeater")
def show_repeater() -> None:
    """Show repeater (show R marked flows)"""

    show_repeater_filter = "(~marker R)"
    current_view_filter = ctx.options.view_filter
    if current_view_filter == show_repeater_filter:
        ctx.options.view_filter = last_view_filter.get()
    else:
        last_view_filter.set(current_view_filter)
        ctx.options.view_filter = show_repeater_filter
