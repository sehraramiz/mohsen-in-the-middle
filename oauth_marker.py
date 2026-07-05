import json
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse, unquote_plus

from mitmproxy import ctx, command, http
from mitmproxy.log import ALERT

WINDOW = 50

RELEVANT_PARAMS: set[str] = {
    "response_type",
    "client_id",
    "redirect_uri",
    "id_token",
    "token_type",
    "expires_in",
    "grant_type",
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


@dataclass
class TrackedEntry:
    param_name: str
    last_seen: int


def _relevant(d: dict[str, str]) -> dict[str, str]:
    return {k: v for k, v in d.items() if k in RELEVANT_PARAMS}


def _find_in_query(flow: http.HTTPFlow) -> dict[str, str]:
    return _relevant(dict(flow.request.query))


def _find_in_post(flow: http.HTTPFlow) -> dict[str, str]:
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

    body: dict[str, str] = {}
    if "json" in ct:
        try:
            raw = json.loads(text)
        except Exception:
            return {}
        if isinstance(raw, dict):
            body = {str(k): str(v) for k, v in raw.items() if isinstance(v, str)}
        else:
            return {}
    elif "urlencoded" in ct:
        for part in text.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                body[unquote_plus(k)] = unquote_plus(v)
    else:
        return {}

    return _relevant(body)


def _find_in_location(flow: http.HTTPFlow) -> dict[str, str]:
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
    qs = parse_qs(parsed.query)
    for k, vals in qs.items():
        if k in RELEVANT_PARAMS and vals:
            found[k] = vals[0]

    if fragment:
        for pair in fragment.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                if k in RELEVANT_PARAMS:
                    found[k] = v

    return found


def _find_in_json_body(flow: http.HTTPFlow) -> dict[str, str]:
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
    return _relevant({str(k): str(v) for k, v in body.items() if isinstance(v, str)})


def _collect_request_values(flow: http.HTTPFlow) -> set[str]:
    values: set[str] = set()

    for v in flow.request.query.values():
        values.add(v)

    ct = flow.request.headers.get("Content-Type", "")
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
        if name.lower() == "authorization" and value.startswith("Bearer "):
            values.add(value[7:])
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
                    values.add(v)

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
        if name.lower() == "authorization" and value.startswith("Bearer "):
            values.add(value[7:])
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

        registered_matches = self._match_known(_collect_request_values(flow))
        detected = {}
        detected.update(_find_in_query(flow))
        detected.update(_find_in_post(flow))

        if detected or registered_matches:
            self._mark(flow, detected, registered_matches)

        self._sweep()

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        self._counter += 1

        registered_matches = self._match_known(_collect_response_values(flow))
        detected = {}
        detected.update(_find_in_location(flow))
        detected.update(_find_in_json_body(flow))

        if detected or registered_matches:
            self._mark(flow, detected, registered_matches)

        self._sweep()

    def _mark(
        self,
        flow: http.HTTPFlow,
        detected: dict[str, str],
        registered_matches: dict[str, str],
    ) -> None:
        for name, value in detected.items():
            if name in TRACKED_PARAMS and value:
                self._register(value, name)

        params = set(detected.keys())
        for value, orig_param in registered_matches.items():
            params.add(f"_matched:{orig_param}")

        if flow.metadata.get("oauth_marked", False):
            existing = set(flow.metadata.get("oauth_params", []))
            new_only = params - existing
            if not new_only:
                return
            flow.metadata["oauth_params"] = list(existing | params)
            return

        flow.metadata["highlight_color"] = "pink"
        flow.metadata["oauth_marked"] = True
        flow.metadata["oauth_params"] = list(params)
        self._count += 1
        url = f"{flow.request.host}{flow.request.path}"
        ctx.log(f"[oauth-marker] {url} — {', '.join(sorted(params))}")

    @command.command("oauth")
    def filter_oauth(self) -> None:
        current = ctx.options.view_filter or ""
        if "~meta oauth_marked: true" in current:
            ctx.log("OAuth filter already active", ALERT)
            return
        ctx.master.commands.call_strings(
            "set", ["view_filter", f"{current} & ~meta oauth_marked: true"]
        )
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
