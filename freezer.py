import logging

from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import command
from mitmproxy import hooks
from mitmproxy.log import ALERT


_last_view_filter: str = ""
_frozen_flows: dict[str, str] = {}


def response(flow: http.HTTPFlow):
    req_url = flow.request.pretty_url.split("?")[0]
    req_key = f"{flow.request.method}-{req_url}"
    frozen_flow_id = _frozen_flows.get(req_key)
    if not frozen_flow_id:
        return
    frozen_flow = ctx.master.view.get_by_id(frozen_flow_id)
    if frozen_flow:
        flow.response = frozen_flow.response.copy()
        flow.marked = "F"
    else:
        _frozen_flows.pop(req_key, None)
        logging.log(ALERT, f"Frozen flow {req_key} was deleted, removing reference")


@command.command("freeze")
def mark_freeze() -> None:
    flow = ctx.master.view.focus.flow
    if not flow:
        return

    req_url = flow.request.pretty_url.split("?")[0]
    req_key = f"{flow.request.method}-{req_url}"
    is_frozen = flow.metadata.get("frozen", False)
    if is_frozen:
        flow.marked = ""
        _frozen_flows.pop(req_key, None)
    else:
        flow.marked = "F"
        prev_frozen_flow_id = _frozen_flows.pop(req_key, None)
        if prev_frozen_flow_id:
            prev_frozen_flow = ctx.master.view.get_by_id(prev_frozen_flow_id)
            if prev_frozen_flow:
                prev_frozen_flow.marked = ""
                ctx.master.addons.trigger(hooks.UpdateHook([prev_frozen_flow]))
        _frozen_flows[req_key] = flow.id
    flow.metadata["frozen"] = not is_frozen
    logging.log(ALERT, f"Frozen {req_key}")
    ctx.master.addons.trigger(hooks.UpdateHook([flow]))


@command.command("freezer")
def show_freezer() -> None:
    global _last_view_filter
    freezer_filter = "((( FILTER:SPECIAL_VIEW_FREEZER | ~meta \"frozen: true\" )))"
    current_view_filter = ctx.options.view_filter
    if "((( FILTER:SPECIAL_VIEW_FREEZER" in current_view_filter:
        ctx.options.view_filter = _last_view_filter
    elif "((( FILTER:" not in current_view_filter:
        _last_view_filter = current_view_filter
        ctx.options.view_filter = freezer_filter
