import logging
from contextvars import ContextVar

from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import command
from mitmproxy import hooks
from mitmproxy.log import ALERT


last_view_filter: ContextVar[str] = ContextVar("last_view_filter", default="")
freezed_flows: ContextVar[dict] = ContextVar("freezed_flows", default={})


def response(flow: http.HTTPFlow):
    current_freezed_flows = freezed_flows.get()
    req_url = flow.request.pretty_url.split("?")[0]
    freezed_flow_id = current_freezed_flows.get(req_url)
    if not freezed_flow_id:
        return
    freezed_flow = ctx.master.view.get_by_id(freezed_flow_id)
    if freezed_flow:
        flow.response = freezed_flow.response.copy()


@command.command("freeze")
def mark_freeze() -> None:
    flow = ctx.master.view.focus.flow
    if not flow:
        return

    req_url = flow.request.pretty_url.split("?")[0]
    is_frozen = flow.metadata.get("frozen", False)
    current_freezed_flows = freezed_flows.get()
    if is_frozen:
        flow.marked = ""
        current_freezed_flows.pop(req_url, None)
    else:
        flow.marked = "F"
        prev_freezed_flow_id = current_freezed_flows.pop(req_url, None)
        if prev_freezed_flow_id:
            prev_freezed_flow = ctx.master.view.get_by_id(prev_freezed_flow_id)
            prev_freezed_flow.marked = ""
            ctx.master.addons.trigger(hooks.UpdateHook([prev_freezed_flow]))
        current_freezed_flows[req_url] = flow.id
    freezed_flows.set(current_freezed_flows)
    flow.metadata["frozen"] = not is_frozen
    logging.log(ALERT, f"Freezed {req_url}")


@command.command("freezer")
def show_freezer() -> None:
    filter = "((( FILTER:SPECIAL_VIEW_FREEZER | ~meta \"frozen: true\" )))"
    current_view_filter = ctx.options.view_filter
    if "SPECIAL_VIEW_FREEZER" in current_view_filter:
        filter = last_view_filter.get()
    elif "SPECIAL_VIEW" not in current_view_filter:
        last_view_filter.set(current_view_filter)
    ctx.options.view_filter = filter
