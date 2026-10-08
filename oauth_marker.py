import html
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote_plus, urlparse

from mitmproxy import ctx, command, http
from mitmproxy.log import ALERT

WINDOW = 50
MIN_TRACK_LEN = 8
MAX_FORM_BODY = 500_000

RELEVANT_PARAMS: set[str] = {
    "response_type",
    "client_id",
    "redirect_uri",
    "id_token",
    "token_type",
    "expires_in",
    "grant_type",
    "scope",
    "client_secret",
    "code_challenge",
    "code_challenge_method",
    "code_verifier",
    "prompt",
    "response_mode",
    "ui_locales",
    "claims_locales",
    "id_token_hint",
    "login_hint",
    "acr_values",
    "session_state",
    "device_code",
    "user_code",
    "verification_uri",
    "client_assertion",
    "client_assertion_type",
    "assertion",
    "authorization_details",
    "dpop_jkt",
    "requested_token_type",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "issued_token_type",
    "resource",
    "audience",
    "vtr",
    "req_cnf",
    "rs_cnf",
    "cnf",
    "ticket",
    "claim_token",
    "pct",
    "rpt",
    "trust_chain",
    "wallet_nonce",
    "vp_token",
    "response_uri",
    "dcql_query",
    "client_metadata",
    "request_uri_method",
    "transaction_data",
    "verifier_info",
    "expected_origins",
    "post_logout_redirect_uri",
}

TRACKED_PARAMS: set[str] = {
    "code",
    "state",
    "nonce",
    "id_token",
    "access_token",
    "refresh_token",
    "session_state",
    "code_verifier",
    "code_challenge",
    "device_code",
    "user_code",
    "client_assertion",
}

_INPUT_TAG = re.compile(r"<input\b[^>]*>", re.I)
_INPUT_ATTR = re.compile(
    r"\b(name|value)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I
)


@dataclass
class TrackedEntry:
    param_name: str
    last_seen: int


def _classify(params: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    relevant = {k: v for k, v in params.items() if k in RELEVANT_PARAMS and v}
    tracked = {k: v for k, v in params.items() if k in TRACKED_PARAMS and v}
    return relevant, tracked


def _extract_query(flow: http.HTTPFlow) -> dict[str, str]:
    return dict(flow.request.query)


def _extract_post(flow: http.HTTPFlow) -> dict[str, str]:
    req = flow.request
    if req.method != "POST":
        return {}
    ct = req.headers.get("Content-Type", "")
    try:
        text = req.get_text()
    except Exception:
        return {}
    if not text:
        return {}

    if "json" in ct:
        try:
            raw = json.loads(text)
        except Exception:
            return {}
        if isinstance(raw, dict):
            return {str(k): str(v) for k, v in raw.items() if isinstance(v, str)}
        return {}

    if "urlencoded" in ct:
        body: dict[str, str] = {}
        for part in text.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                body[unquote_plus(k)] = unquote_plus(v)
        return body

    return {}


def _extract_location(flow: http.HTTPFlow) -> dict[str, str]:
    resp = flow.response
    if not resp:
        return {}
    location = resp.headers.get("Location", "")
    if not location:
        return {}

    fragment = ""
    if "#" in location:
        location, fragment = location.split("#", 1)

    found: dict[str, str] = {}

    parsed = urlparse(location)
    for k, vals in parse_qs(parsed.query).items():
        if vals:
            found[k] = vals[0]

    if fragment:
        for pair in fragment.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                found[unquote_plus(k)] = unquote_plus(v)

    return found


def _extract_json_body(flow: http.HTTPFlow) -> dict[str, str]:
    resp = flow.response
    if not resp:
        return {}
    ct = resp.headers.get("Content-Type", "")
    if "json" not in ct:
        return {}
    try:
        body = json.loads(resp.get_text())
    except Exception:
        return {}
    if not isinstance(body, dict):
        return {}
    return {str(k): str(v) for k, v in body.items() if isinstance(v, str)}


def _extract_form_post(flow: http.HTTPFlow) -> dict[str, str]:
    resp = flow.response
    if not resp:
        return {}
    ct = resp.headers.get("Content-Type", "")
    if "html" not in ct:
        return {}
    cl = resp.headers.get("Content-Length", "")
    if cl.isdigit() and int(cl) > MAX_FORM_BODY:
        return {}
    try:
        text = resp.get_text()
    except Exception:
        return {}
    if not text or len(text) > MAX_FORM_BODY or "<input" not in text.lower():
        return {}

    found: dict[str, str] = {}
    for tag in _INPUT_TAG.findall(text):
        attrs: dict[str, str] = {}
        for m in _INPUT_ATTR.finditer(tag):
            val = m.group(2) or m.group(3) or m.group(4) or ""
            attrs[m.group(1).lower()] = html.unescape(val)
        name = attrs.get("name")
        if name:
            found[name] = attrs.get("value", "")
    return found


def _auth_value(value: str) -> str:
    parts = value.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() in ("bearer", "dpop"):
        return parts[1]
    return value


def _collect_request_values(flow: http.HTTPFlow) -> set[str]:
    values: set[str] = set()

    for v in flow.request.query.values():
        values.add(v)

    ct = flow.request.headers.get("Content-Type", "")
    text = ""
    if "urlencoded" in ct or "json" in ct:
        try:
            text = flow.request.get_text()
        except Exception:
            text = ""
    if text and "urlencoded" in ct:
        for part in text.split("&"):
            if "=" in part:
                _, v = part.split("=", 1)
                values.add(unquote_plus(v))
    if text and "json" in ct:
        try:
            raw = json.loads(text)
        except Exception:
            raw = None
        if isinstance(raw, dict):
            for v in raw.values():
                if isinstance(v, str):
                    values.add(v)

    for name, value in flow.request.headers.items():
        if name.lower() == "authorization":
            values.add(_auth_value(value))
        else:
            values.add(value)

    cookie = flow.request.headers.get("Cookie", "")
    if cookie:
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                _, val = part.split("=", 1)
                values.add(val.strip())

    return values


def _collect_response_values(flow: http.HTTPFlow) -> set[str]:
    values: set[str] = set()
    resp = flow.response

    location = resp.headers.get("Location", "")
    if location:
        frag = ""
        if "#" in location:
            location, frag = location.split("#", 1)
        parsed = urlparse(location)
        qs = parse_qs(parsed.query)
        for vals in qs.values():
            for v in vals:
                values.add(v)
        if frag:
            for pair in frag.split("&"):
                if "=" in pair:
                    _, v = pair.split("=", 1)
                    values.add(unquote_plus(v))

    ct = resp.headers.get("Content-Type", "")
    if "json" in ct:
        try:
            body = json.loads(resp.get_text())
        except Exception:
            body = None
        if isinstance(body, dict):
            for v in body.values():
                if isinstance(v, str):
                    values.add(v)

    for name, value in resp.headers.items():
        if name.lower() == "authorization":
            values.add(_auth_value(value))
        else:
            values.add(value)

    for sc in resp.headers.get_all("set-cookie"):
        first = sc.split(";", 1)[0]
        if "=" in first:
            _, val = first.split("=", 1)
            values.add(val.strip())

    return values


class OAuthMarker:
    def __init__(self) -> None:
        self._count: int = 0
        self._counter: int = 0
        self._known_values: dict[str, TrackedEntry] = {}

    def _register(self, value: str, param_name: str) -> None:
        self._known_values[value] = TrackedEntry(
            param_name=param_name, last_seen=self._counter
        )

    def _sweep(self) -> None:
        stale = [
            v
            for v, e in self._known_values.items()
            if self._counter - e.last_seen > WINDOW
        ]
        for v in stale:
            del self._known_values[v]

    def _match_known(self, candidates: set[str]) -> dict[str, str]:
        matches: dict[str, str] = {}
        for value, entry in self._known_values.items():
            if value in candidates:
                matches[value] = entry.param_name
                entry.last_seen = self._counter
        return matches

    def request(self, flow: http.HTTPFlow) -> None:
        if not flow.request or flow.request.host is None:
            return
        self._counter += 1

        extracted: dict[str, str] = {}
        extracted.update(_extract_query(flow))
        extracted.update(_extract_post(flow))

        self._process(flow, extracted, _collect_request_values(flow))
        self._sweep()

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        self._counter += 1

        extracted: dict[str, str] = {}
        extracted.update(_extract_location(flow))
        extracted.update(_extract_json_body(flow))
        extracted.update(_extract_form_post(flow))

        self._process(flow, extracted, _collect_response_values(flow))
        self._sweep()

    def _process(
        self, flow: http.HTTPFlow, extracted: dict[str, str], candidates: set[str]
    ) -> None:
        registered_matches = self._match_known(candidates)
        relevant, tracked = _classify(extracted)

        if not relevant and not registered_matches and len(tracked) < 2:
            return

        for name, value in tracked.items():
            if len(value) >= MIN_TRACK_LEN:
                self._register(value, name)

        params = set(relevant) | set(tracked)
        for value, orig_param in registered_matches.items():
            params.add(f"_matched:{orig_param}")

        self._mark(flow, params)

    def _mark(self, flow: http.HTTPFlow, params: set[str]) -> None:
        if flow.metadata.get("oauth_marked", False):
            existing = set(flow.metadata.get("oauth_params", []))
            new_only = params - existing
            if not new_only:
                return
            flow.metadata["oauth_params"] = sorted(existing | params)
            return

        flow.metadata["highlight_color"] = "pink"
        flow.metadata["oauth_marked"] = True
        flow.metadata["oauth_params"] = sorted(params)
        self._count += 1
        url = f"{flow.request.host}{flow.request.path}"
        ctx.log(f"[oauth-marker] {url} — {', '.join(sorted(params))}")

    @command.command("oauth")
    def filter_oauth(self) -> None:
        current = ctx.options.view_filter or ""
        if "oauth_marked" in current:
            ctx.log("OAuth filter already active", ALERT)
            return
        marker = '~meta "oauth_marked: [Tt]rue"'
        new_filter = f"{current} & {marker}" if current.strip() else marker
        ctx.master.commands.call_strings("set", ["view_filter", new_filter])
        ctx.log(f"Showing {self._count} OAuth-marked flows", ALERT)

    @command.command("oauth.clear")
    def clear_marks(self) -> None:
        cleared = 0
        for flow in ctx.master.view:
            if flow.metadata.pop("oauth_marked", False):
                flow.metadata.pop("oauth_params", None)
                flow.metadata.pop("highlight_color", None)
                cleared += 1
        self._count = 0
        self._known_values.clear()
        ctx.log(f"Cleared OAuth marks on {cleared} flows", ALERT)


addons = [OAuthMarker()]
