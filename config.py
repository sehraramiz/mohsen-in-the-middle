import json
import re
from typing import Callable
from functools import partial
from datetime import datetime
from pathlib import Path

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import http


class Settings:
    def __init__(self) -> None:
        self.project_name: str = "ProxyProject"
        self.user_agent_suffix: str = ""
        self.in_scope: list[str] = []
        self.out_scope: list[str] = []
        self.view_filter_include_hosts: list[str] = []
        self.view_filter_exclude_hosts: list[str] = []
        self.view_filters: list[str] = []
        self.include_headers: list[list[str]] = []
        self.remove_headers: list[str] = []
        self._load_env()

    def _load_env(self) -> None:
        env_path = Path(".env")
        if not env_path.exists():
            return
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if not hasattr(self, key):
                    continue
                try:
                    parsed = json.loads(value)
                except json.JSONDecodeError:
                    parsed = value
                setattr(self, key, parsed)


def scope_decorator(in_scope: list[str], out_scope: list[str]):
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            flow = None
            if len(args) == 1 and type(args[0]) is http.HTTPFlow:
                flow = args[0]
            if len(args) > 1 and type(args[1]) is http.HTTPFlow:
                flow = args[1]
            if flow is None:
                return
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
data_dir = Path(f"./{settings.project_name}_data")
data_dir.mkdir(exist_ok=True)


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
        if settings.user_agent_suffix not in user_agent:
            modified_ua = user_agent + f" {settings.user_agent_suffix}"
            flow.request.headers["User-Agent"] = modified_ua


@command.command("save")
def save_flows() -> None:
    date_str = str(datetime.now().strftime("%Y-%m-%d"))
    ctx.master.commands.call_strings(
        "save.file", ["@shown", f"./files/mitm/flows.{date_str}"]
    )
