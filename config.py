import json
import re
import logging
from typing import Callable
from functools import partial
from datetime import datetime
from pathlib import Path

from mitmproxy.log import ALERT
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.addonmanager import Loader


class Settings:
    def __init__(self) -> None:
        self.project_name = Path.cwd().name
        self.user_agent_suffix: str = ""
        self.in_scope: list[str] = []
        self.out_scope: list[str] = []
        self.view_filter_include_hosts: list[str] = []
        self.view_filter_exclude_hosts: list[str] = []
        self.view_filters: list[str] = []
        self.include_headers: list[list[str]] = []
        self.remove_headers: list[str] = []
        self.remove_cookies: list[str] = []
        self._load_env()
        self._load_scope_files()

    def _load_scope_files(self) -> None:
        for fname, target in [("inscope", self.in_scope), ("outscope", self.out_scope)]:
            path = Path(fname)
            if not path.exists():
                continue
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pattern = re.escape(line).replace(r"\*", ".*") + "$"
                    target.append(pattern)

    def reload(self) -> list[str]:
        changed = []
        fresh = Settings()
        fresh.project_name = self.project_name
        for key, value in vars(fresh).items():
            current = getattr(self, key)
            if isinstance(current, list) and isinstance(value, list):
                snapshot = list(current)
                current[:] = value
                if snapshot != value:
                    changed.append(key)
            elif current != value:
                setattr(self, key, value)
                changed.append(key)
        return changed

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


def host_in_scope(host: str) -> bool:
    in_scope = any(re.search(p, host) for p in settings.in_scope)
    out_scope = any(re.search(p, host) for p in settings.out_scope)
    return in_scope and not out_scope


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

session_start = datetime.now()


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
        view_filter += f"((({include_hosts_filter})))"

    exclude_hosts_filter = ""
    for filter_host in settings.view_filter_exclude_hosts:
        if len(exclude_hosts_filter):
            exclude_hosts_filter += " & "
        exclude_hosts_filter += f"!~d {filter_host}"

    if len(exclude_hosts_filter):
        view_filter += f"& ((({exclude_hosts_filter})))"
    other_filters = ""
    for filter in settings.view_filters:
        if other_filters:
            other_filters += " & "
        other_filters += filter
    if len(other_filters):
        view_filter += f"& ({other_filters})"
    return view_filter


def load(loader: Loader) -> None:
    ctx.options.update_known(
        anticache=True,
        view_order="time",
        view_order_reversed=True,
        view_filter=scope_filters(),
        ssl_insecure=True,
    )


def request(flow: http.HTTPFlow) -> None:
    if settings.remove_cookies:
        cookie = flow.request.headers.get("Cookie", "")
        if cookie:
            parts = [c.strip() for c in cookie.split(";") if c.strip()]
            kept = [
                p
                for p in parts
                if not any(
                    re.search(pat, p.split("=", 1)[0].strip())
                    for pat in settings.remove_cookies
                )
            ]
            if kept:
                flow.request.headers["Cookie"] = "; ".join(kept)
            else:
                flow.request.headers.pop("Cookie", None)


@scope()
def request(flow: http.HTTPFlow) -> None:
    flow.request.headers.setdefault("x-mitm-trace-id", flow.id)

    for header_key, header_value in settings.include_headers:
        flow.request.headers[header_key.lower()] = header_value
    for h in settings.remove_headers:
        flow.request.headers.pop(h, None)
    if settings.user_agent_suffix:
        user_agent = flow.request.headers.get("User-Agent", "")
        if settings.user_agent_suffix not in user_agent:
            modified_ua = user_agent + f" {settings.user_agent_suffix}"
            flow.request.headers["User-Agent"] = modified_ua


def response(flow: http.HTTPFlow) -> None:
    if not settings.remove_cookies:
        return
    set_cookies = flow.response.headers.get_all("set-cookie")
    if not set_cookies:
        return
    kept = [
        sc
        for sc in set_cookies
        if not any(
            re.search(pat, sc.split("=", 1)[0].strip())
            for pat in settings.remove_cookies
        )
    ]
    if kept:
        flow.response.headers.set_all("set-cookie", kept)
    else:
        flow.response.headers.pop("set-cookie", None)


@command.command("scopes")
def show_scopes() -> None:
    lines = ["Scope patterns:"]
    lines.append("")
    lines.append("  In-scope:")
    if settings.in_scope:
        for p in settings.in_scope:
            lines.append(f"    {p}")
    else:
        lines.append("    (none)")
    lines.append("")
    lines.append("  Out-scope:")
    if settings.out_scope:
        for p in settings.out_scope:
            lines.append(f"    {p}")
    else:
        lines.append("    (none)")
    logging.log(ALERT, "\n".join(lines))


@command.command("reload.env")
def reload_env() -> None:
    global derived_view_filter
    changed = settings.reload()
    new_filter = scope_filters()
    if ctx.options.view_filter in ("", derived_view_filter):
        ctx.options.update_known(view_filter=new_filter)
        filter_note = "view filter refreshed"
    else:
        filter_note = "view filter left as-is (changed manually)"
    derived_view_filter = new_filter

    lines = ["Reloaded .env + inscope/outscope."]
    if not Path(".env").exists():
        lines.append("  .env not found — settings reset to defaults.")
    if changed:
        lines.append(f"  updated: {', '.join(changed)}")
    else:
        lines.append("  no changes")
    lines.append(f"  {filter_note}")
    logging.log(ALERT, "\n".join(lines))


@command.command("save")
def save_flows() -> None:
    date_str = str(datetime.now().strftime("%Y-%m-%d"))
    ctx.master.commands.call_strings(
        "save.file", ["@shown", f"./files/mitm/flows.{date_str}"]
    )


def done() -> None:
    elapsed = datetime.now() - session_start
    hours = elapsed.total_seconds() / 3600
    log_path = data_dir / "sessions.log"
    with open(log_path, "a") as f:
        f.write(
            f"{session_start.isoformat()},{datetime.now().isoformat()},{hours:.2f},{settings.project_name}\n"
        )
    logging.log(ALERT, f"Session ended: {hours:.2f}h")
