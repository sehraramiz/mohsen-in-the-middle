import re
from typing import Callable
from functools import partial
from datetime import datetime

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import http
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    project_name: str = "ProxyProject"
    user_agent_suffix: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_scope: list[str] = Field(default_factory=list)
    view_filter_include_hosts: list[str] = Field(default_factory=list)
    view_filter_exclude_hosts: list[str] = Field(default_factory=list)
    view_filters: list[str] = Field(default_factory=list)
    include_headers: list[list[str]] = Field(default_factory=list)
    remove_headers: list[str] = Field(default_factory=list)

    model_config = SettingsConfigDict(env_file=".env", extra="allow")


def scope_decorator(in_scope: list[str], out_scope: list[str]):
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            if len(args) > 1:
                flow = args[1]
                is_in_scope = any(re.search(p, flow.request.host) for p in in_scope)
                is_out_scope = any(re.search(p, flow.request.host) for p in out_scope)
                if is_in_scope and not is_out_scope:
                    return func(*args, **kwargs)
        return wrapper
    return decorator


settings = Settings()
scope = partial(
    scope_decorator, in_scope=settings.in_scope, out_scope=settings.out_scope
)


def scope_filters() -> str:
    view_filter = ""
    if not settings.view_filter_include_hosts:
        view_filter = "~all"
    else:
        include_hosts_filter = ""
        for filter_host in settings.view_filter_include_hosts:
            if len(include_hosts_filter):
                include_hosts_filter += " | "
            include_hosts_filter += f"~d {filter_host}"
        view_filter += f"((( FILTER:SCOPE | {include_hosts_filter} )))"

    exclude_hosts_filter = ""
    for filter_host in settings.view_filter_exclude_hosts:
        if len(exclude_hosts_filter):
            exclude_hosts_filter += " & "
        exclude_hosts_filter += f"!~d {filter_host}"

    if len(exclude_hosts_filter):
        view_filter += f"& ((( FILTER:SCOPE | {exclude_hosts_filter} )))"
    other_filters = ""
    for filter in settings.view_filters:
        if other_filters:
            other_filters += " & "
        other_filters += filter
    if len(other_filters):
        view_filter += f"& ({other_filters})"
    return view_filter


def load(loader):
    ctx.options.update_known(
        anticache=True,
        view_order="time",
        view_order_reversed=True,
        view_filter=scope_filters(),
        ssl_insecure=True,
    )


@scope()
def request(flow: http.HTTPFlow):
    flow.request.headers.setdefault("x-mitm-trace-id", flow.id)
    for header_key, header_value in settings.include_headers:
        flow.request.headers[header_key] = header_value
    for h in settings.remove_headers:
        flow.request.headers.pop(h, None)
    if settings.user_agent_suffix:
        user_agent = flow.request.headers.get("User-Agent", "")
        modified_ua = user_agent + f" {settings.user_agent_suffix}"
        flow.request.headers["User-Agent"] = modified_ua


def toggle_filter(filter: str) -> None:
    view_filter = ctx.options.view_filter
    filter = f"((({filter})))"
    if filter not in view_filter:
        if view_filter:
            view_filter += " & " + filter
        else:
            view_filter = filter
    else:
        view_filter = view_filter.replace(f" & {filter}", "")
    ctx.options.view_filter = view_filter.strip()


@command.command("noimage")
def no_image_cmd() -> None:
    no_image_view_filter = (
        "FILTER:NO_IMAGE |"
        " !~hs content-type:.*image/.*"
        " & !~u .*\\.jpg.*"
        " & !~u .*\\.jpeg.*"
        " & !~u .*\\.png.*"
    )
    toggle_filter(no_image_view_filter)


@command.command("nostyle")
def no_style() -> None:
    no_style_view_filter = (
        "FILTER:NO_STYLE |"
        " !~hs content-type:.*text/css"
        " & !~u .*\\.css.*"
        " & !~u .*\\.scss.*"
        " & !~u .*\\.ttf.*"
        " & !~u .*\\.woff.*"
        " & !~u .*\\.woff2.*"
        " & !~u .*\\.otf.*"
        " & !~u .*\\.pbf.*"
    )
    toggle_filter(no_style_view_filter)


@command.command("nojs")
def no_js_cmd() -> None:
    no_js_view_filter = (
        "FILTER:NO_JS |"
        " !~hs content-type:.*application/javascript.*"
        " & !~hs content-type:.*text/javascript.*"
        " & !~u .*\\.js.*"
        " & !~u .*\\.js\\.map.*"
    )
    toggle_filter(no_js_view_filter)


@command.command("save")
def save_flows() -> None:
    date_str = str(datetime.now().strftime("%Y-%m-%d"))
    ctx.master.commands.call_strings(
        "save.file", ["@shown", f"./files/mitm/flows.{date_str}"]
    )
