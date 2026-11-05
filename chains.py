"""Chains (`:chains`): show how the requests in a window are linked.

Record a window of traffic, then let the addon work out which responses handed
a value to which later requests. This is the in-process, single-session version
of the raavi graph: no database, no export step, no second tool.

    :chains.start   begin recording
    :chains.end     stop; work out the links
    :chains         show the chain (focused flow -> one chain, otherwise all)
    :chains.draw    write the chain to an interactive HTML graph and open it
    :chains.clear   remove the view filter, keeping the capture
    :chains.wipe    throw the window and its tags away
"""

import json
import logging
import re
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, unquote, unquote_plus, urlparse

from mitmproxy import command, ctx, http
from mitmproxy.log import ALERT

# Values shorter than this are too generic to be a useful link (an upload id is
# often short, so this is deliberately lower than raavi's 16).
MIN_VALUE_LEN = 8

# A value seen in more than this many later requests is ambient boilerplate
# (a session token, a feature flag), not a link in a chain.
MAX_CONSUMERS = 10

# Request bodies larger than this are not scanned for values (file uploads).
BODY_SCAN_LIMIT = 1_000_000

# Tag applied to the flows that make up a shown chain.
CHAINS_BLOCK = '((~meta "chains: 1"))'

HOSTNAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}$")


def _filter_add(block: str) -> None:
    """AND `block` into the current view filter, preserving the existing expression."""
    try:
        current = ctx.options.view_filter or ""
    except AttributeError:
        return
    current = current.replace(block, "").strip(" &")
    if current and current != "~all":
        ctx.options.view_filter = f"{block} & {current}"
    else:
        ctx.options.view_filter = block


def _filter_remove(block: str | None) -> None:
    """Drop `block`, restoring `~all` when nothing else remains."""
    try:
        current = ctx.options.view_filter or ""
    except AttributeError:
        return
    if block:
        current = current.replace(block, "").strip(" &")
    ctx.options.view_filter = current or "~all"


def _location_params(location: str) -> list[tuple[str, str]]:
    """Every (name, value) pair carried by a Location header, query and fragment."""
    fragment = ""
    if "#" in location:
        location, fragment = location.split("#", 1)

    found = [
        (name, value)
        for name, values in parse_qs(urlparse(location).query).items()
        for value in values
    ]
    for pair in fragment.split("&"):
        if "=" in pair:
            name, value = pair.split("=", 1)
            found.append((unquote_plus(name), unquote_plus(value)))
    return found


@dataclass
class Link:
    """One causal edge between two flows in the captured window."""

    src: int
    dst: int
    kind: str  # "value" or "redirect"
    values: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


def _is_hostname(value: str) -> bool:
    # Require lowercase: hostnames in bodies are normalised, while a JWT
    # ("eyJ…payload.sig") is dot-separated and otherwise passes the pattern.
    if value != value.lower():
        return False
    return bool(HOSTNAME_RE.match(value))


def _scalar_strings(obj, out: set[str] | None = None) -> set[str]:
    """Collect every string value in a JSON structure that is long enough to be a token."""
    if out is None:
        out = set()
    if isinstance(obj, dict):
        for value in obj.values():
            _scalar_strings(value, out)
    elif isinstance(obj, list):
        for value in obj:
            _scalar_strings(value, out)
    elif isinstance(obj, str):
        if len(obj) >= MIN_VALUE_LEN and not _is_hostname(obj):
            out.add(obj)
    return out


def _text(message) -> str:
    """Message body as text, or an empty string for binaries and broken bodies."""
    try:
        return message.get_text(strict=False) or ""
    except Exception:
        return ""


def _location_values(flow: http.HTTPFlow) -> list[tuple[str, str]]:
    """Values carried by the Location header.

    Not just redirects: a 302 callback hands forward `code`/`state`, a 201 Created hands
    forward the URL of the resource it made, and a fragment carries `access_token` in the
    implicit flow. Only the params are kept; the URL itself would duplicate the redirect
    edge.
    """
    if flow.response is None:
        return []

    location = flow.response.headers.get("Location")
    if not location:
        return []

    return [
        (value, "location")
        for _, value in _location_params(location)
        if len(value) >= MIN_VALUE_LEN and not _is_hostname(value)
    ]


def _response_values(flow: http.HTTPFlow) -> list[tuple[str, str]]:
    """Values this response hands forward, tagged with where they came from."""
    if flow.response is None:
        return []

    found: list[tuple[str, str]] = []

    for cookie in flow.response.headers.get_all("set-cookie"):
        first = cookie.split(";", 1)[0]
        if "=" in first:
            value = first.split("=", 1)[1].strip()
            if len(value) >= MIN_VALUE_LEN:
                found.append((value, "cookie"))

    found.extend(_location_values(flow))

    content_type = (flow.response.headers.get("content-type") or "").lower()
    if "json" in content_type:
        try:
            body = json.loads(_text(flow.response))
        except (TypeError, ValueError):
            body = None
        for value in _scalar_strings(body):
            found.append((value, "json"))

    return found


def _request_haystack(flow: http.HTTPFlow) -> str:
    """Everything a request carries, flattened into one searchable string."""
    request = flow.request
    parts = [
        request.url,
        request.headers.get("Cookie", ""),
        "\n".join(f"{name}: {value}" for name, value in request.headers.items()),
    ]

    body = request.content or b""
    if 0 < len(body) <= BODY_SCAN_LIMIT:
        parts.append(_text(request))

    return "\n".join(parts)


def _path_of(url: str) -> str:
    path = urlparse(url).path or "/"
    return path if path.startswith("/") else f"/{path}"


def _redirect_links(flows: list[http.HTTPFlow]) -> list[Link]:
    """A 3xx response points at the next request that hits its Location path."""
    links: list[Link] = []

    for index, flow in enumerate(flows):
        if flow.response is None or not 300 <= flow.response.status_code < 400:
            continue
        location = flow.response.headers.get("Location")
        if not location:
            continue
        target = _path_of(location)
        for later in range(index + 1, len(flows)):
            if _path_of(flows[later].request.url) == target:
                links.append(Link(index, later, "redirect"))
                break

    return links


def _value_links(
    flows: list[http.HTTPFlow],
    haystacks: list[str],
    decoded: list[str],
    decoded_plus: list[str],
) -> list[Link]:
    """A value produced by one response and carried by a later request.

    Matching is exact first, then on percent-decoded forms. The same token often
    travels encoded in a URL/form body and decoded in a JSON body, so a byte
    comparison alone silently drops real hand-offs.
    """
    links: dict[tuple[int, int], Link] = {}

    for index, flow in enumerate(flows):
        for value, origin in _response_values(flow):
            plain = unquote(value)
            form = unquote_plus(value)
            extra = [(plain, decoded)]
            if form != plain:
                extra.append((form, decoded_plus))

            consumers = [
                later
                for later in range(index + 1, len(flows))
                if value in haystacks[later]
                or any(f and f in stacks[later] for f, stacks in extra)
            ]
            if not consumers or len(consumers) > MAX_CONSUMERS:
                continue
            for later in consumers:
                link = links.setdefault((index, later), Link(index, later, "value"))
                if value not in link.values:
                    link.values.append(value)
                if origin not in link.evidence:
                    link.evidence.append(origin)

    return list(links.values())


def derive(flows: list[http.HTTPFlow]) -> list[Link]:
    """Work out every link between the flows, in capture order."""
    haystacks = [_request_haystack(flow) for flow in flows]
    decoded = [unquote(haystack) for haystack in haystacks]
    decoded_plus = [unquote_plus(haystack) for haystack in haystacks]
    return _redirect_links(flows) + _value_links(
        flows, haystacks, decoded, decoded_plus
    )


def _components(links: list[Link]) -> list[list[int]]:
    """Group linked flows together, following links in both directions.

    A group is everything reachable from any of its flows, so it contains the
    steps before and after a value hand-off. Flows that link to nothing are left
    out; they are not part of any chain.
    """
    involved = {link.src for link in links} | {link.dst for link in links}
    parent = {index: index for index in involved}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for link in links:
        left, right = find(link.src), find(link.dst)
        if left != right:
            parent[right] = left

    groups: dict[int, list[int]] = {}
    for index in involved:
        groups.setdefault(find(index), []).append(index)

    return [sorted(group) for group in groups.values()]


def _short(value: str, limit: int = 40) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "…"


def _link_label(link: Link, source_position: int) -> str:
    if link.kind == "redirect":
        label = "→ redirect"
    else:
        shown = ", ".join(_short(value) for value in link.values[:2])
        if len(link.values) > 2:
            shown += f" +{len(link.values) - 2}"
        evidence = ", ".join(link.evidence)
        label = f"← {shown} [{evidence}]"
    return f"{label} (from #{source_position})"


def _format_chain(
    chain: list[int], flows: list[http.HTTPFlow], links: list[Link]
) -> list[str]:
    position_of = {index: position + 1 for position, index in enumerate(chain)}
    lines: list[str] = []

    for position, index in enumerate(chain):
        request = flows[index].request
        line = f"  #{position + 1}  {request.method:<4} {request.pretty_host}{request.path}"

        # A step may consume a value from anywhere earlier in the chain, not
        # just the row above it, so label every incoming link.
        incoming = [
            link
            for link in links
            if link.dst == index and link.src in position_of and link.src != index
        ]
        labels = [_link_label(link, position_of[link.src]) for link in incoming]
        if labels:
            line += "   " + "  ".join(labels)

        lines.append(line)

    return lines


DRAW_BODY_LIMIT = 200_000
TEXT_TYPES = (
    "text/",
    "json",
    "xml",
    "javascript",
    "x-www-form-urlencoded",
    "graphql",
    "yaml",
    "csv",
)


def _body_record(message) -> dict | None:
    """A body as text when it looks textual, otherwise a size placeholder."""
    if message is None:
        return None

    raw = message.content or b""
    if not raw:
        return {"text": ""}

    content_type = (message.headers.get("content-type") or "").lower()
    text_like = not content_type or any(t in content_type for t in TEXT_TYPES)
    if not text_like or b"\x00" in raw[:1024]:
        return {"binary": True, "size": len(raw), "content_type": content_type}

    text = _text(message)
    return {
        "text": text[:DRAW_BODY_LIMIT],
        "truncated": len(text) > DRAW_BODY_LIMIT,
        "size": len(raw),
    }


def _headers_record(message) -> list[list[str]]:
    return [[name, value] for name, value in message.headers.items(multi=True)]


def _flow_record(index: int, step: int, flow: http.HTTPFlow) -> dict:
    request = flow.request
    response = flow.response
    created = flow.timestamp_created
    return {
        "index": index,
        "step": step,
        "method": request.method,
        "scheme": request.scheme,
        "host": request.pretty_host,
        "port": request.port,
        "path": request.path,
        "url": request.url,
        "status": response.status_code if response else None,
        "reason": response.reason if response else "",
        "ts": datetime.fromtimestamp(created).isoformat(sep=" ", timespec="seconds")
        if created
        else "",
        "req": {
            "headers": _headers_record(request),
            "body": _body_record(request),
        },
        "resp": {
            "headers": _headers_record(response),
            "body": _body_record(response),
        }
        if response
        else None,
    }


def _status_color(status: int | None) -> str:
    if status is None:
        return "#eeeeee"
    if 200 <= status < 300:
        return "#c8e6c9"
    if 300 <= status < 400:
        return "#ffe0b2"
    return "#ffcdd2"


def _parsed_json(message) -> object | None:
    content_type = (message.headers.get("content-type") or "").lower()
    if "json" not in content_type:
        return None
    try:
        return json.loads(_text(message))
    except (TypeError, ValueError):
        return None


def _json_paths(obj, needle: str, path: str = "", depth: int = 0) -> list[str]:
    """Dotted paths of every string leaf equal to `needle`."""
    if depth > 12:
        return []

    found: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else str(key)
            found.extend(_json_paths(value, needle, child, depth + 1))
    elif isinstance(obj, list):
        for position, value in enumerate(obj):
            found.extend(_json_paths(value, needle, f"{path}[{position}]", depth + 1))
    elif isinstance(obj, str) and obj == needle:
        found.append(path or "body")
    return found


def _source_facts(flow: http.HTTPFlow, value: str) -> list[dict]:
    """Where in the response this value came from: cookie name, Location param or JSON key."""
    if flow.response is None:
        return []

    facts: list[dict] = []
    for cookie in flow.response.headers.get_all("set-cookie"):
        first = cookie.split(";", 1)[0]
        if "=" not in first:
            continue
        name, _, cookie_value = first.partition("=")
        if cookie_value.strip() == value:
            facts.append({"name": name.strip(), "origin": "cookie"})

    location = flow.response.headers.get("Location")
    if location:
        fragment = ""
        if "#" in location:
            location, fragment = location.split("#", 1)
        for name, values in parse_qs(urlparse(location).query).items():
            if value in values:
                facts.append({"name": name, "origin": "location"})
        for pair in fragment.split("&"):
            if "=" in pair:
                name, _, fragment_value = pair.partition("=")
                if unquote_plus(fragment_value) == value:
                    facts.append({"name": name, "origin": "location"})

    body = _parsed_json(flow.response)
    if body is not None:
        for path in _json_paths(body, value):
            facts.append({"name": path, "origin": "json"})

    seen = set()
    unique = []
    for fact in facts:
        key = (fact["name"], fact["origin"])
        if key not in seen:
            seen.add(key)
            unique.append(fact)
    return unique


def _carrier_facts(flow: http.HTTPFlow, value: str) -> list[str]:
    """Where the consuming request carries the value: query, cookie, header or body."""
    request = flow.request
    facts: list[str] = []

    for name, values in parse_qs(urlparse(request.url).query).items():
        if value in values:
            facts.append(f"query: {name}")

    for name, cookie_value in request.cookies.items():
        if value in cookie_value:
            facts.append(f"Cookie: {name}")

    for name, header_value in request.headers.items(multi=True):
        if name.lower() in ("cookie", "content-length", "content-type"):
            continue
        if value in header_value:
            facts.append(f"{name} header")

    body = _parsed_json(request)
    if body is not None:
        for path in _json_paths(body, value):
            facts.append(f"body: {path}")
    elif value in _text(request):
        facts.append("request body")

    if not facts and (value in request.url or unquote(value) in unquote(request.url)):
        facts.append("URL")

    return list(dict.fromkeys(facts))


def _draw_payload(
    chains: list[list[int]], flows: list[http.HTTPFlow], links: list[Link]
) -> dict:
    """Everything the HTML needs: one self-contained graph per chain."""
    step_of: dict[str, int] = {}
    chain_of: dict[str, int] = {}
    chain_records: list[dict] = []
    flow_records: list[dict] = []
    link_records: list[dict] = []
    search: dict[str, str] = {}

    for chain_index, chain in enumerate(chains):
        lanes: dict[str, int] = {}
        for index in chain:
            lanes.setdefault(flows[index].request.pretty_host, len(lanes))

        step_map = {index: step + 1 for step, index in enumerate(chain)}
        for index, step in step_map.items():
            step_of[str(index)] = step
            chain_of[str(index)] = chain_index

        nodes = []
        for index in chain:
            flow = flows[index]
            request = flow.request
            status = flow.response.status_code if flow.response else None
            nodes.append(
                {
                    "data": {
                        "id": str(index),
                        "label": (
                            f"#{step_map[index]}  {request.method} "
                            f"{_short(request.path, 26)}\n{request.pretty_host}"
                        ),
                        "host": request.pretty_host,
                        "status": status,
                        "color": _status_color(status),
                        "step": step_map[index],
                        "lane": lanes[request.pretty_host],
                    }
                }
            )
            flow_records.append(_flow_record(index, step_map[index], flow))
            search[str(index)] = (
                f"#{step_map[index]} {request.method} "
                f"{request.pretty_host}{request.path} {request.url} "
                f"{status if status is not None else ''}"
            ).lower()

        edges = []
        for link in links:
            if link.src not in step_map or link.dst not in step_map:
                continue

            status = None
            location = ""
            why = []
            if link.kind == "redirect":
                response = flows[link.src].response
                status = response.status_code if response else None
                location = (response.headers.get("Location") or "") if response else ""
                label = f"{status} redirect" if status else "redirect"
            else:
                for value in link.values:
                    sources = _source_facts(flows[link.src], value)
                    if not sources:
                        sources = [
                            {
                                "name": None,
                                "origin": link.evidence[0] if link.evidence else "",
                            }
                        ]
                    why.append(
                        {
                            "value": value,
                            "sources": sources,
                            "carriers": _carrier_facts(flows[link.dst], value),
                        }
                    )
                names = [
                    source["name"]
                    for record in why
                    for source in record["sources"]
                    if source["name"]
                ]
                label = names[0] if names else _short(link.values[0], 20)
                if len(link.values) > 1:
                    label += f" +{len(link.values) - 1}"

            edge_id = f"e{link.src}-{link.dst}-{link.kind}"
            edges.append(
                {
                    "data": {
                        "id": edge_id,
                        "source": str(link.src),
                        "target": str(link.dst),
                        "kind": link.kind,
                        "label": label,
                    }
                }
            )
            link_records.append(
                {
                    "id": edge_id,
                    "src": link.src,
                    "dst": link.dst,
                    "kind": link.kind,
                    "values": link.values,
                    "evidence": link.evidence,
                    "why": why,
                    "status": status,
                    "location": location,
                }
            )

        chain_records.append(
            {
                "index": chain_index,
                "steps": len(chain),
                "hosts": list(lanes),
                "flowIds": [str(index) for index in chain],
                "elements": {"nodes": nodes, "edges": edges},
            }
        )

    return {
        "meta": (
            f"{len(chain_records)} chain(s) · {len(flow_records)} step(s) · "
            f"{len(link_records)} link(s) · "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ),
        "stepOf": step_of,
        "chainOf": chain_of,
        "flows": flow_records,
        "links": link_records,
        "chains": chain_records,
        "search": search,
    }


CHAINS_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>chains</title>
<style>
  :root{--fg:#1d1d1f;--muted:#6e6e73;--line:#e2e2e7}
  *{box-sizing:border-box}
  html,body{height:100%}
  body{font:13px/1.45 ui-sans-serif,system-ui,sans-serif;margin:0;color:var(--fg);
    display:flex;flex-direction:column}
  header{padding:9px 14px;border-bottom:1px solid var(--line);display:flex;gap:12px;
    align-items:baseline;flex-wrap:wrap}
  header b{font-size:14px}
  header span{color:var(--muted);font-size:12px}
  #legend{margin-left:auto;display:flex;gap:14px;align-items:center}
  #legend i{display:inline-block;width:20px;margin-right:5px;vertical-align:middle}
  #q{font:12px ui-monospace,monospace;padding:4px 8px;border:1px solid var(--line);
    border-radius:6px;width:200px;outline:none}
  #q:focus{border-color:#8ab}
  #hits{font-size:11px;color:var(--muted);min-width:64px}
  main{flex:1;display:flex;min-height:0}
  #left{flex:1;min-width:0;overflow:auto;padding:10px 14px}
  #detail{width:400px;min-width:320px;border-left:1px solid var(--line);overflow:auto;
    padding:12px 14px}
  #detail h2{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
    margin:16px 0 6px}
  #detail .title{font:12px ui-monospace,monospace;font-weight:600;word-break:break-all}
  #detail code,#detail pre{font:11px ui-monospace,monospace}
  pre{background:#f6f6f8;padding:8px;border-radius:6px;overflow:auto;max-height:34vh;
    white-space:pre-wrap;word-break:break-word;margin:4px 0}
  table.h{width:100%;border-collapse:collapse}
  table.h td{border-bottom:1px solid #f0f0f2;padding:2px 4px;
    font:11px ui-monospace,monospace;vertical-align:top;word-break:break-all}
  table.h td:first-child{color:var(--muted);white-space:nowrap;width:38%}
  .rel{font:11px ui-monospace,monospace;padding:2px 0;cursor:pointer;color:#a35a00}
  .rel:hover{text-decoration:underline}
  .whyhead{font:11px ui-monospace,monospace;color:#7a4a12;margin-top:6px;
    word-break:break-all}
  .val{font:11px ui-monospace,monospace;background:#f6f6f8;border-radius:4px;
    padding:3px 6px;margin:2px 0 6px;word-break:break-all}
  .status{font:11px ui-monospace,monospace;margin-bottom:4px}
  .muted{color:var(--muted)}
  .chain{border:1px solid var(--line);border-radius:8px;margin-bottom:8px;background:#fff}
  .chain.hidden{display:none}
  .chead{display:flex;gap:10px;align-items:baseline;padding:8px 11px;cursor:pointer;
    background:#fafafb;border-radius:8px;flex-wrap:wrap}
  .chain.open .chead{border-bottom:1px solid var(--line);border-radius:8px 8px 0 0}
  .cname{font:600 12px ui-monospace,monospace}
  .cmeta{color:var(--muted);font-size:11px}
  .ccaret{margin-left:auto;color:var(--muted);font-size:11px}
  .graph{width:100%}
  .graph .empty{padding:24px;text-align:center}
  button{font:11px ui-monospace,monospace;padding:3px 8px;border:1px solid var(--line);
    background:#fff;border-radius:6px;cursor:pointer;color:var(--fg)}
  button:hover:not(:disabled){border-color:#8ab}
  button:disabled{opacity:.4;cursor:default}
  #hiddenbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;
    padding:6px 14px;border-bottom:1px solid var(--line);background:#fffbe8}
  #hiddenbar[hidden]{display:none}
  #hiddenbar .lbl{font:11px ui-monospace,monospace;color:var(--muted)}
  .chip{font:11px ui-monospace,monospace;border:1px solid #e5d7ae;background:#fff;
    border-radius:11px;padding:2px 8px;cursor:pointer;color:#7a5a10;white-space:nowrap}
  .chip:hover{border-color:#c9a44a}
  .chip.off{text-decoration:line-through;opacity:.5}
  .chosts{display:flex;gap:4px;flex-wrap:wrap;align-items:center}
  .chead .chip{font-size:10px;padding:1px 7px}
  .acts{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0 2px}
</style>
</head>
<body>
<header><b>chains</b><span id="meta"></span>
<input id="q" placeholder="search steps…" autocomplete="off"/>
<span id="hits"></span>
<span id="legend">
  <span><i style="border-top:2px solid #3a9"></i>redirect</span>
  <span><i style="border-top:2px dashed #c9884a"></i>value</span>
</span>
<button id="reset" disabled title="restore every hidden step and host">reset view</button>
<span id="hint">click a chain to expand · click a step to follow · hide via chips or right-click</span></header>
<div id="hiddenbar" hidden><span class="lbl">hidden</span><span id="hiddenchips"></span></div>
<main>
  <div id="left"><div id="chains"></div></div>
  <aside id="detail"><p class="muted">click a step or a link to see why</p></aside>
</main>
<script>__CYTOSCAPE__</script>
<script>
const DATA = __PAYLOAD__;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const flows = Object.fromEntries(DATA.flows.map(f => [String(f.index), f]));
const links = Object.fromEntries(DATA.links.map(l => [l.id, l]));
const state = {
  open: DATA.chains.length ? 0 : null,
  focus: null,
  hiddenHosts: new Set(),
  hiddenSteps: {},
  visibleIds: new Set()
};
const graphEl = document.createElement("div");
graphEl.className = "graph";
graphEl.addEventListener("contextmenu", event => event.preventDefault());
let cy = null;
const q = $("q");
const hitsEl = $("hits");
$("meta").textContent = DATA.meta;

const STYLE = [
  { selector: "node", style: {
      "background-color": "data(color)", "border-width": 1,
      "border-color": "#1d1d1f22", "label": "data(label)",
      "font-family": "ui-monospace,monospace", "font-size": 12,
      "text-wrap": "wrap", "text-max-width": 200, "text-overflow": "ellipsis",
      "text-valign": "center", "text-halign": "center", "width": 220, "height": 50,
      "shape": "round-rectangle" } },
  { selector: "node:selected", style: {
      "border-width": 3, "border-color": "#c98a00", "background-color": "#ffe9a8" } },
  { selector: "node.hit", style: {
      "border-width": 3, "border-color": "#2a7ae2" } },
  { selector: "node.dim", style: { "opacity": 0.15 } },
  { selector: "edge.dim", style: { "opacity": 0.08 } },
  { selector: "edge", style: {
      "width": 1.8, "curve-style": "unbundled-bezier",
      "control-point-distances": 30, "control-point-weights": 0.5,
      "target-arrow-shape": "triangle", "arrow-scale": 0.8,
      "line-color": "#9aa", "target-arrow-color": "#9aa",
      "label": "data(label)", "font-family": "ui-monospace,monospace",
      "font-size": 11, "color": "#5a3a10", "text-rotation": "autorotate",
      "text-background-color": "#ffffff", "text-background-opacity": 1,
      "text-background-padding": 2, "text-max-width": 130,
      "text-overflow": "ellipsis" } },
  { selector: 'edge[kind = "redirect"]', style: {
      "line-color": "#3a9", "target-arrow-color": "#3a9",
      "control-point-distances": -30 } },
  { selector: 'edge[kind = "value"]', style: {
      "line-color": "#c9884a", "target-arrow-color": "#c9884a",
      "line-style": "dashed" } },
  { selector: "edge:selected", style: { "width": 3 } }
];

function hiddenStepsOf(index) {
  return state.hiddenSteps[index] || (state.hiddenSteps[index] = new Set());
}

function visibleElements(chain, index) {
  const hidden = hiddenStepsOf(index);
  const nodes = chain.elements.nodes.filter(
    n => !state.hiddenHosts.has(n.data.host) && !hidden.has(n.data.id));
  const ids = new Set(nodes.map(n => n.data.id));
  const edges = chain.elements.edges.filter(
    e => ids.has(e.data.source) && ids.has(e.data.target));
  return { nodes, edges, ids };
}

function compactPositions(nodes) {
  const steps = [...new Set(nodes.map(n => n.data.step))].sort((a, b) => a - b);
  const lanes = [...new Set(nodes.map(n => n.data.lane))].sort((a, b) => a - b);
  const stepRank = new Map(steps.map((s, i) => [s, i + 1]));
  const laneRank = new Map(lanes.map((l, i) => [l, i]));
  const positions = {};
  nodes.forEach(n => {
    positions[n.data.id] = {
      x: stepRank.get(n.data.step) * 300,
      y: laneRank.get(n.data.lane) * 150
    };
  });
  return { positions, lanes: lanes.length };
}

function toggleHost(host) {
  if (state.hiddenHosts.has(host)) state.hiddenHosts.delete(host);
  else state.hiddenHosts.add(host);
  rebuild();
}

function hideStep(index, id) {
  if (index === null || index === undefined || !id) return;
  hiddenStepsOf(index).add(id);
  if (state.focus === id) state.focus = null;
  rebuild();
}

function buildGraph(chain, index) {
  if (cy) { cy.destroy(); cy = null; }
  graphEl.innerHTML = "";
  const visible = visibleElements(chain, index);
  state.visibleIds = visible.ids;
  if (state.focus && !state.visibleIds.has(state.focus)) state.focus = null;
  if (!visible.nodes.length) {
    graphEl.style.height = "120px";
    graphEl.innerHTML = '<p class="muted empty">all steps hidden — reset view</p>';
    return;
  }
  const { positions, lanes } = compactPositions(visible.nodes);
  graphEl.style.height =
    Math.max(170, Math.min(900, (lanes - 1) * 150 + 170)) + "px";
  cy = cytoscape({
    container: graphEl,
    elements: { nodes: visible.nodes, edges: visible.edges },
    layout: { name: "preset", positions, fit: true, padding: 40 },
    wheelSensitivity: 0.2,
    style: STYLE
  });
  cy.on("tap", "node", e => {
    state.focus = e.target.id();
    showNode(e.target.id());
    applyVisibility();
  });
  cy.on("tap", "edge", e => showEdge(e.target.id()));
  cy.on("tap", e => {
    if (e.target === cy) { state.focus = null; applyVisibility(); }
  });
  cy.on("cxttap", "node", e => {
    if (e.originalEvent) e.originalEvent.preventDefault();
    hideStep(index, e.target.id());
  });
  fitGraph();
}

function fitGraph() {
  if (!cy) return;
  cy.resize();
  cy.fit(cy.elements(), 40);
  if (cy.zoom() < 0.7) {
    cy.zoom(0.8);
    cy.center();
    const first = cy.nodes().toArray()
      .sort((a, b) => a.data("step") - b.data("step"))[0];
    if (first) {
      const left = first.renderedPosition("x") - first.renderedOuterWidth() / 2;
      cy.panBy({ x: 40 - left, y: 0 });
    }
  }
}

function rebuild() {
  if (cy) { cy.destroy(); cy = null; graphEl.innerHTML = ""; }
  const list = $("chains");
  list.innerHTML = "";
  DATA.chains.forEach((chain, i) => {
    const card = document.createElement("section");
    card.className = "chain";
    card.dataset.chain = String(i);
    const open = state.open === i;
    const visible = visibleElements(chain, i).nodes.length;
    const meta = visible === chain.steps
      ? `${chain.steps} step(s)`
      : `${visible}/${chain.steps} step(s)`;
    const head = document.createElement("header");
    head.className = "chead";
    head.innerHTML = `<span class="cname">chain ${i + 1}</span>` +
      `<span class="cmeta">${meta}</span>` +
      `<span class="chosts"></span>` +
      `<span class="ccaret">${open ? "▾" : "▸"}</span>`;
    const chosts = head.querySelector(".chosts");
    chain.hosts.forEach(host => {
      const hidden = state.hiddenHosts.has(host);
      const chip = document.createElement("span");
      chip.className = "chip" + (hidden ? " off" : "");
      chip.textContent = host;
      chip.title = hidden
        ? "click to restore this host" : "click to hide this host";
      chip.onclick = event => {
        event.stopPropagation();
        toggleHost(host);
      };
      chosts.appendChild(chip);
    });
    head.onclick = () => {
      state.open = open ? null : i;
      state.focus = null;
      rebuild();
    };
    card.appendChild(head);
    if (open) {
      const body = document.createElement("div");
      body.className = "cbody";
      body.appendChild(graphEl);
      card.appendChild(body);
    }
    list.appendChild(card);
  });
  if (state.open !== null) buildGraph(DATA.chains[state.open], state.open);
  filterCards();
  applyVisibility();
  renderHidden();
}

function renderHidden() {
  const chips = [];
  state.hiddenHosts.forEach(host => chips.push({
    kind: "host", value: host, label: `host ${host}`
  }));
  Object.entries(state.hiddenSteps).forEach(([chainIndex, ids]) => {
    ids.forEach(id => chips.push({
      kind: "step", chain: Number(chainIndex), value: String(id),
      label: `chain ${Number(chainIndex) + 1} #${DATA.stepOf[id] ?? id}`
    }));
  });
  const box = $("hiddenchips");
  box.innerHTML = "";
  chips.forEach(c => {
    const el = document.createElement("span");
    el.className = "chip";
    el.textContent = c.label + " ✕";
    el.title = "click to restore";
    el.onclick = () => {
      if (c.kind === "host") state.hiddenHosts.delete(c.value);
      else hiddenStepsOf(c.chain).delete(c.value);
      rebuild();
    };
    box.appendChild(el);
  });
  $("hiddenbar").hidden = chips.length === 0;
  $("reset").disabled = chips.length === 0;
}

$("reset").onclick = () => {
  state.hiddenHosts.clear();
  state.hiddenSteps = {};
  rebuild();
};

function filterCards() {
  const term = q.value.trim().toLowerCase();
  if (!term) {
    document.querySelectorAll(".chain").forEach(c => c.classList.remove("hidden"));
    hitsEl.textContent = "";
    return;
  }
  let total = 0;
  DATA.chains.forEach((chain, i) => {
    const card = document.querySelector(`.chain[data-chain="${i}"]`);
    if (!card) return;
    const matches = [...visibleElements(chain, i).ids].filter(
      id => (DATA.search[id] || "").includes(term));
    total += matches.length;
    card.classList.toggle("hidden", matches.length === 0);
  });
  hitsEl.textContent = `${total} match${total === 1 ? "" : "es"}`;
}

function applyVisibility() {
  if (!cy) return;
  cy.elements().removeClass("hit dim");
  const term = q.value.trim().toLowerCase();
  let searchIds = null;
  if (term) {
    const hits = cy.nodes().filter(
      n => (DATA.search[n.id()] || "").includes(term));
    searchIds = new Set(hits.map(n => n.id()));
    hits.addClass("hit");
  }
  let focusIds = null;
  if (state.focus && cy.getElementById(state.focus).nonempty()) {
    const node = cy.getElementById(state.focus);
    const path = node.predecessors().union(node.successors()).union(node);
    focusIds = new Set(path.map(el => el.id()));
  }
  cy.nodes().forEach(n => {
    const id = n.id();
    const ok = (!searchIds || searchIds.has(id)) &&
      (!focusIds || focusIds.has(id));
    if (!ok) n.addClass("dim");
  });
  cy.edges().forEach(e => {
    if (e.source().hasClass("dim") || e.target().hasClass("dim"))
      e.addClass("dim");
  });
}

function kv(headers) {
  return (headers || []).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("");
}

function bodyHtml(body) {
  if (!body) return "";
  if (body.binary)
    return `<p class="muted">[binary ${body.size} bytes` +
      (body.content_type ? ` · ${esc(body.content_type)}` : "") + `]</p>`;
  if (!body.text) return `<p class="muted">[empty]</p>`;
  return `<pre>${esc(body.text)}</pre>` +
    (body.truncated ? `<p class="muted">[truncated]</p>` : "");
}

function whyHtml(link) {
  if (link.kind === "redirect")
    return `<div class="whyhead">${esc(link.status ?? "")} → ` +
      `${esc(link.location || "redirect")}</div>`;
  const rows = (link.why || []).map(w => {
    const source = (w.sources || []).map(s =>
      s.name
        ? `<b>${esc(s.name)}</b> <span class="muted">(${esc(s.origin)})</span>`
        : `<span class="muted">${esc(s.origin || "value")}</span>`).join(", ");
    const carriers = (w.carriers || []).length
      ? w.carriers.map(esc).join(", ")
      : '<span class="muted">carrier not found</span>';
    return `<div class="whyhead">${source} → ${carriers}</div>` +
      `<div class="val">${esc(w.value)}</div>`;
  }).join("");
  return rows || `<div class="val">${esc((link.values || []).join(", "))}</div>`;
}

function linkHtml(link, direction) {
  const other = direction === "in" ? link.src : link.dst;
  const step = DATA.stepOf[String(other)];
  const head = direction === "in" ? "from" : "to";
  const kind = link.kind === "redirect" ? "redirect" : "value";
  return `<div class="rel" data-goto="${other}">${head} #${step} · ${kind}</div>` +
    whyHtml(link);
}

function goTo(id) {
  const chain = DATA.chainOf[String(id)];
  if (chain === undefined) return;
  if (q.value) {
    q.value = "";
    filterCards();
  }
  if (state.open !== chain) {
    state.open = chain;
    state.focus = null;
    rebuild();
  }
  if (cy) {
    const node = cy.getElementById(String(id));
    if (node.nonempty()) {
      cy.elements().unselect();
      node.select();
      cy.animate(
        { center: { eles: node }, zoom: Math.max(cy.zoom(), 0.9) },
        { duration: 200 }
      );
    }
  }
  showNode(id);
  applyVisibility();
}

function wireJumps() {
  const detail = $("detail");
  detail.querySelectorAll("[data-goto]").forEach(el => {
    el.onclick = () => goTo(el.dataset.goto);
  });
  detail.querySelectorAll("[data-hide-step]").forEach(el => {
    el.onclick = () => hideStep(
      DATA.chainOf[el.dataset.hideStep], el.dataset.hideStep);
  });
  detail.querySelectorAll("[data-hide-host]").forEach(el => {
    el.onclick = () => toggleHost(el.dataset.hideHost);
  });
}

function showNode(id) {
  const f = flows[id];
  if (!f) return;
  const incoming = DATA.links.filter(l => String(l.dst) === id);
  const outgoing = DATA.links.filter(l => String(l.src) === id);
  $("detail").innerHTML = `
    <div class="title">#${f.step} ${esc(f.method)} ${esc(f.host)}${esc(f.path)}</div>
    <div class="muted" style="font:11px ui-monospace,monospace;word-break:break-all">
      ${esc(f.ts)} · ${esc(f.url)}</div>
    <div class="acts">
      <button data-hide-step="${esc(id)}">hide this step</button>
      <button data-hide-host="${esc(f.host)}">hide ${esc(f.host)}</button>
    </div>
    <h2>imports</h2>
    ${incoming.length ? incoming.map(l => linkHtml(l, "in")).join("") :
      '<p class="muted">none</p>'}
    <h2>exports</h2>
    ${outgoing.length ? outgoing.map(l => linkHtml(l, "out")).join("") :
      '<p class="muted">none</p>'}
    <h2>request</h2>
    <table class="h">${kv(f.req.headers)}</table>
    ${bodyHtml(f.req.body)}
    <h2>response</h2>
    <div class="status">${f.status ?? ""} ${esc(f.reason || "")}</div>
    <table class="h">${kv(f.resp ? f.resp.headers : [])}</table>
    ${bodyHtml(f.resp ? f.resp.body : null)}
  `;
  wireJumps();
}

function showEdge(id) {
  const l = links[id];
  if (!l) return;
  $("detail").innerHTML = `
    <div class="title">#${DATA.stepOf[String(l.src)]} → #${DATA.stepOf[String(l.dst)]}</div>
    <div class="muted">${l.kind === "redirect" ? "redirect" : "value hand-off"}</div>
    <h2>why</h2>
    ${whyHtml(l)}
    <h2>steps</h2>
    <div class="rel" data-goto="${l.src}">from #${DATA.stepOf[String(l.src)]}</div>
    <div class="rel" data-goto="${l.dst}">to #${DATA.stepOf[String(l.dst)]}</div>
  `;
  wireJumps();
}

q.addEventListener("input", () => {
  filterCards();
  const term = q.value.trim().toLowerCase();
  if (term) {
    const openCard = state.open === null
      ? null
      : document.querySelector(`.chain[data-chain="${state.open}"]`);
    if (!openCard || openCard.classList.contains("hidden")) {
      const first = DATA.chains.findIndex(
        (c, idx) => [...visibleElements(c, idx).ids].some(
          id => (DATA.search[id] || "").includes(term)));
      if (first !== -1) {
        state.open = first;
        state.focus = null;
        rebuild();
        return;
      }
    }
  }
  applyVisibility();
});

q.addEventListener("keydown", event => {
  if (event.key === "Enter" && cy) {
    const hits = cy.nodes(".hit");
    if (hits.length)
      cy.animate({ fit: { eles: hits, padding: 80 } }, { duration: 250 });
  } else if (event.key === "Escape") {
    if (q.value) {
      q.value = "";
      filterCards();
    } else {
      state.focus = null;
    }
    applyVisibility();
    q.blur();
  }
});

window.addEventListener("resize", fitGraph);

rebuild();
</script>
</body>
</html>
"""


def _cytoscape_source() -> str:
    try:
        base = Path(__file__).resolve().parent
    except NameError:
        base = Path.cwd()
    return (base / "vendor" / "cytoscape.min.js").read_text(encoding="utf-8")


class Chains:
    def __init__(self) -> None:
        self.active = False
        self.flows: list[http.HTTPFlow] = []
        self.links: list[Link] = []

    def start(self) -> None:
        self.flows = []
        self.links = []
        self.active = True
        self._set_filter(False)
        logging.log(ALERT, "chains: recording — do the action, then run `:chains.end`")

    def end(self) -> None:
        if not self.active:
            logging.log(ALERT, "chains: not recording — run `:chains.start` first")
            return

        self.active = False
        self.flows.sort(key=lambda flow: flow.timestamp_created or 0)
        self.links = derive(self.flows)
        logging.log(
            ALERT,
            f"chains: {len(self.flows)} flow(s), {len(self.links)} link(s) "
            "— run `:chains` to see the chain",
        )

    def show(self) -> None:
        if not self.flows:
            logging.log(
                ALERT,
                "chains: nothing captured — run `:chains.start`, do the action, then `:chains.end`",
            )
            return

        if not self.links:
            logging.log(ALERT, f"chains: {len(self.flows)} flow(s), no links found")
            return

        chains = _components(self.links)
        focused = self._focused_index()
        if focused is not None:
            chains = [group for group in chains if focused in group] or [[focused]]

        self._tag(chains)

        lines = [f"chains: {len(self.flows)} flow(s), {len(self.links)} link(s)"]
        for chain in chains:
            lines.append("")
            lines.extend(_format_chain(chain, self.flows, self.links))

        logging.log(ALERT, "\n".join(lines))

    def draw(self) -> None:
        if not self.flows:
            logging.log(
                ALERT,
                "chains: nothing captured — run `:chains.start`, do the action, then `:chains.end`",
            )
            return

        chains = _components(self.links)
        focused = self._focused_index()
        if chains and focused is not None:
            chains = [group for group in chains if focused in group] or [[focused]]
        if not chains:
            chains = [list(range(len(self.flows)))]
        chains.sort(key=lambda group: group[0])

        try:
            cytoscape = _cytoscape_source()
        except OSError:
            logging.log(
                ALERT,
                "chains.draw: vendor/cytoscape.min.js missing — download it with "
                "`curl -L -o vendor/cytoscape.min.js "
                "https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js`",
            )
            return

        payload = _draw_payload(chains, self.flows, self.links)
        html = CHAINS_TEMPLATE.replace(
            "__CYTOSCAPE__", cytoscape.replace("</script", "<\\/script")
        ).replace("__PAYLOAD__", json.dumps(payload).replace("</", "<\\/"))

        out_dir = Path(f"./{Path.cwd().name}_data/chains")
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"chains-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
        path.write_text(html, encoding="utf-8")

        try:
            webbrowser.open(path.resolve().as_uri())
        except Exception:
            pass

        logging.log(
            ALERT,
            f"chains: drew {len(payload['flows'])} step(s) in {len(chains)} chain(s), "
            f"{len(payload['links'])} link(s) → {path}",
        )

    def clear(self) -> None:
        self._set_filter(False)
        logging.log(ALERT, "chains: filter removed (capture kept)")

    def wipe(self) -> None:
        for flow in self.flows:
            flow.metadata.pop("chains", None)
        self.flows = []
        self.links = []
        self.active = False
        self._set_filter(False)
        logging.log(ALERT, "chains: wiped")

    def response(self, flow: http.HTTPFlow) -> None:
        if self.active and flow.response is not None:
            self.flows.append(flow)

    def _focused_index(self) -> int | None:
        focused = ctx.master.view.focus.flow
        if focused is None:
            return None
        for index, flow in enumerate(self.flows):
            if flow.id == focused.id:
                return index
        return None

    def _tag(self, chains: list[list[int]]) -> None:
        shown = {index for chain in chains for index in chain}
        for index, flow in enumerate(self.flows):
            if index in shown:
                flow.metadata["chains"] = "1"
            else:
                flow.metadata.pop("chains", None)
        self._set_filter(True)

    def _set_filter(self, on: bool) -> None:
        if on:
            _filter_add(CHAINS_BLOCK)
        else:
            _filter_remove(CHAINS_BLOCK)


addon = Chains()


@command.command("chains.start")
def chains_start() -> None:
    """Start recording a window of flows."""
    addon.start()


@command.command("chains.end")
def chains_end() -> None:
    """Stop recording and work out how the flows link."""
    addon.end()


@command.command("chains")
def chains_show() -> None:
    """Show the chain between the recorded flows."""
    addon.show()


@command.command("chains.draw")
def chains_draw() -> None:
    """Write the captured chains to an interactive HTML graph and open it."""
    addon.draw()


@command.command("chains.clear")
def chains_clear() -> None:
    """Remove the chains view filter, keeping the capture."""
    addon.clear()


@command.command("chains.wipe")
def chains_wipe() -> None:
    """Wipe the recorded window, its tags and the view filter."""
    addon.wipe()


addons = [addon]
