import hashlib
import json
import logging
import threading
import time
from urllib.parse import urlparse

from mitmproxy import command, ctx, http
from mitmproxy.log import ALERT

from cdp_registry import get as get_cdp

logger = logging.getLogger(__name__)

# Correlate a CDP request with a proxied flow by matching method + URL and
# picking the closest timestamp within this window (seconds).
WINDOW = 3.0
# How long initiator records are kept around for later lookups.
TTL = 180.0
MAX_FLOWS = 10000
MAX_STACK = 12
SWEEP_THRESHOLD = 3000

_DEFAULT_PORTS = {"http": 80, "https": 443}

_META_KEYS = (
    "caller",
    "caller_script",
    "caller_type",
    "caller_kind",
    "caller_page",
    "caller_line",
    "caller_col",
    "caller_stack",
)


def _norm_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return url
    netloc = parsed.hostname or ""
    if port and _DEFAULT_PORTS.get(parsed.scheme) != port:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return f"{parsed.scheme}://{netloc}{path}" + (
        f"?{parsed.query}" if parsed.query else ""
    )


def _key(method: str, url: str) -> str:
    return f"{method} {_norm_url(url)}"


def _id_for(source: str) -> str:
    return hashlib.sha1(source.encode("utf-8", "replace")).hexdigest()[:8]


class CallerId:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_key: dict[str, list[dict]] = {}
        self._flows: dict[str, http.HTTPFlow] = {}
        self._total: int = 0
        self._active_block: str | None = None

    def running(self) -> None:
        cm = get_cdp()
        if cm:
            cm.on_request(self._on_cdp_request)
            logger.warning("caller_id: CDP initiator capture enabled")
        else:
            logger.warning(
                "caller_id: CDP manager not available (load cdp_manager.py first)"
            )

    def _on_cdp_request(self, record: dict) -> None:
        rec = self._prepare(record)
        if rec is None:
            return

        key = rec["key"]
        with self._lock:
            self._by_key.setdefault(key, []).append(rec)
            self._total += 1
            if self._total > SWEEP_THRESHOLD:
                self._sweep_locked(rec["_t"])
            flows = list(self._flows.values())

        for flow in flows:
            if flow.metadata.get("caller") or rec.get("_used"):
                continue
            if _key(flow.request.method, flow.request.pretty_url) != key:
                continue
            if abs(rec["_t"] - flow.request.timestamp_start) <= WINDOW:
                rec["_used"] = True
                self._apply(flow, rec)

    def _prepare(self, record: dict) -> dict | None:
        method = record.get("method", "") or ""
        url = record.get("url", "") or ""
        if not url:
            return None

        frames = record.get("stack") or []
        if frames:
            top = frames[0]
            script = (
                top.get("url")
                or record.get("initiator_url")
                or record.get("document_url", "")
            )
            line = top.get("lineNumber")
            col = top.get("columnNumber")
        else:
            script = record.get("initiator_url") or record.get("document_url", "")
            line = record.get("initiator_line")
            col = record.get("initiator_column")
        script = script or ""

        try:
            ts = float(record.get("wall_time"))
        except (TypeError, ValueError):
            ts = 0.0
        if not ts:
            ts = time.time()

        return {
            "key": _key(method, url),
            "method": method,
            "url": url,
            "id": _id_for(script) if script else "",
            "script": script,
            "line": line,
            "col": col,
            "type": record.get("type", ""),
            "initiator_type": record.get("initiator_type", ""),
            "frame": record.get("document_url", ""),
            "stack": frames[:MAX_STACK],
            "_t": ts,
            "_used": False,
        }

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request is None:
            return
        with self._lock:
            self._flows[flow.id] = flow
            if len(self._flows) > MAX_FLOWS:
                self._flows.clear()
                self._flows[flow.id] = flow
            rec = self._claim_locked(
                flow.request.method,
                flow.request.pretty_url,
                flow.request.timestamp_start,
            )
        if rec:
            self._apply(flow, rec)

    def _claim_locked(self, method: str, url: str, ts: float) -> dict | None:
        recs = self._by_key.get(_key(method, url))
        if not recs:
            return None
        best: dict | None = None
        best_delta: float | None = None
        for rec in recs:
            if rec.get("_used"):
                continue
            delta = abs(rec["_t"] - ts)
            if delta > WINDOW:
                continue
            if best_delta is None or delta < best_delta:
                best = rec
                best_delta = delta
        if best is not None:
            best["_used"] = True
        return best

    def _sweep_locked(self, now: float) -> None:
        cutoff = now - TTL
        total = 0
        for key in list(self._by_key):
            recs = [r for r in self._by_key[key] if r["_t"] >= cutoff]
            if recs:
                self._by_key[key] = recs
                total += len(recs)
            else:
                del self._by_key[key]
        self._total = total

    def _apply(self, flow: http.HTTPFlow, rec: dict) -> None:
        caller_id = rec.get("id") or ""
        if not caller_id:
            return
        flow.metadata["caller"] = caller_id
        flow.metadata["caller_script"] = rec.get("script", "")
        flow.metadata["caller_type"] = rec.get("type", "")
        if rec.get("initiator_type"):
            flow.metadata["caller_kind"] = rec["initiator_type"]
        if rec.get("frame"):
            flow.metadata["caller_page"] = rec["frame"]
        if rec.get("line") is not None:
            flow.metadata["caller_line"] = str((rec["line"] or 0) + 1)
        if rec.get("col") is not None:
            flow.metadata["caller_col"] = str((rec["col"] or 0) + 1)
        frames = rec.get("stack") or []
        if frames:
            flow.metadata["caller_stack"] = json.dumps(
                [
                    {
                        "fn": f.get("functionName", ""),
                        "url": f.get("url", ""),
                        "line": (f.get("lineNumber") or 0) + 1,
                        "col": (f.get("columnNumber") or 0) + 1,
                    }
                    for f in frames
                ],
                ensure_ascii=False,
            )

    def _ensure_tagged(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("caller"):
            return
        with self._lock:
            rec = self._claim_locked(
                flow.request.method,
                flow.request.pretty_url,
                flow.request.timestamp_start,
            )
        if rec:
            self._apply(flow, rec)

    def _stored_frames(self, flow: http.HTTPFlow) -> list[dict]:
        raw = flow.metadata.get("caller_stack", "")
        if not raw:
            return []
        try:
            frames = json.loads(raw)
        except Exception:
            return []
        return frames if isinstance(frames, list) else []

    def _render_frame(self, frame: dict) -> str:
        fn = frame.get("fn") or "(anonymous)"
        url = frame.get("url") or "(inline)"
        return f"{fn} ({url}:{frame.get('line')}:{frame.get('col')})"

    def _describe(self, flow: http.HTTPFlow, max_frames: int = 3) -> list[str]:
        req = flow.request
        lines = [f"caller_id: {req.method} {req.pretty_url}"]
        script = flow.metadata.get("caller_script", "") or "(unknown)"
        line = flow.metadata.get("caller_line", "")
        col = flow.metadata.get("caller_col", "")
        loc = script + (f":{line}" if line else "") + (f":{col}" if col else "")
        lines.append(f"  fired by  {loc}")

        kind = " ".join(
            b
            for b in (
                flow.metadata.get("caller_kind", ""),
                flow.metadata.get("caller_type", ""),
            )
            if b
        )
        frame = flow.metadata.get("caller_page", "")
        if kind or frame:
            lines.append(
                f"  kind      {kind or '?'}" + (f"   page {frame}" if frame else "")
            )

        if max_frames:
            frames = self._stored_frames(flow)
            if frames:
                rendered = [self._render_frame(f) for f in frames[:max_frames]]
                lines.append("  stack     " + " <- ".join(rendered))
        return lines

    @command.command("caller")
    def caller(self) -> None:
        """Show which JS file/line fired the focused flow; filter to the same script."""
        flow = ctx.master.view.focus.flow
        if not flow:
            logging.log(ALERT, "caller_id: no focused flow")
            return

        self._ensure_tagged(flow)
        caller_id = flow.metadata.get("caller")
        if not caller_id:
            logging.log(
                ALERT,
                "caller_id: no initiator recorded for the focused flow "
                "(CDP off, or the request was not fired by a page script)",
            )
            return

        for other in list(ctx.master.view):
            self._ensure_tagged(other)

        self._set_filter(caller_id)
        matches = sum(
            1 for f in ctx.master.view if f.metadata.get("caller") == caller_id
        )
        lines = self._describe(flow)
        lines.append(f"  {matches} flow(s) tagged caller:{caller_id}")
        logging.log(ALERT, "\n".join(lines))

    @command.command("caller.stack")
    def caller_stack(self) -> None:
        """Print the full recorded JS call stack for the focused flow."""
        flow = ctx.master.view.focus.flow
        if not flow:
            logging.log(ALERT, "caller_id: no focused flow")
            return

        self._ensure_tagged(flow)
        if not flow.metadata.get("caller"):
            logging.log(ALERT, "caller_id: no initiator recorded for the focused flow")
            return

        lines = self._describe(flow, max_frames=0)
        frames = self._stored_frames(flow)
        if not frames:
            lines.append("  stack     (no call stack captured)")
        for i, frame in enumerate(frames):
            lines.append(f"    #{i} {self._render_frame(frame)}")
        logging.log(ALERT, "\n".join(lines))

    @command.command("caller.clear")
    def caller_clear(self) -> None:
        """Clear caller tags and remove the caller view filter."""
        try:
            current = ctx.options.view_filter or "~all"
        except AttributeError:
            current = "~all"
        if self._active_block:
            current = current.replace(self._active_block, "").strip(" &")
        self._active_block = None
        try:
            ctx.options.view_filter = current or "~all"
        except AttributeError:
            pass

        cleared = 0
        for flow in ctx.master.view:
            if flow.metadata.get("caller"):
                cleared += 1
            for key in _META_KEYS:
                flow.metadata.pop(key, None)
        logging.log(ALERT, f"caller_id: cleared tags on {cleared} flow(s)")

    @command.command("caller.status")
    def caller_status(self) -> None:
        """Show CDP initiator capture status."""
        cm = get_cdp()
        with self._lock:
            records = sum(len(v) for v in self._by_key.values())
        tagged = sum(1 for f in ctx.master.view if f.metadata.get("caller"))

        if cm is None:
            cdp = "unavailable"
        elif not getattr(cm, "_enabled", False):
            cdp = "disabled"
        elif getattr(cm, "_chrome_up", False):
            cdp = "connected"
        else:
            cdp = "waiting for Chrome"

        logging.log(
            ALERT,
            f"caller_id: CDP {cdp}, {records} initiator record(s) tracked, "
            f"{tagged} tagged flow(s)",
        )

    def _set_filter(self, caller_id: str) -> None:
        try:
            current = ctx.options.view_filter or "~all"
        except AttributeError:
            return
        if self._active_block:
            current = current.replace(self._active_block, "").strip(" &")
        block = f'((~meta "caller: {caller_id}"))'
        self._active_block = block
        if current and current != "~all":
            ctx.options.view_filter = f"{block} & {current}"
        else:
            ctx.options.view_filter = block


addons = [CallerId()]
