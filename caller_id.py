import hashlib
import json
import logging
import threading
import time
from collections import deque
from urllib.parse import urlparse

from mitmproxy import command, ctx, http
from mitmproxy.log import ALERT

from cdp_registry import get as get_cdp

logger = logging.getLogger(__name__)

WINDOW = 3.0
TTL = 20.0
MAX_RECORDS = 20000
FLOW_TTL = 15.0
MAX_FLOWS = 10000
MAX_STACK = 12
SWEEP_THRESHOLD = 3000
CHUNK = 500
IDLE_POLL = 0.5
BATCH_PAUSE = 0.02
SWEEP_INTERVAL = 1.0

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
    """Tag flows with the JS that fired them.

    Both sides of the correlation (CDP initiator records and proxied flows) are
    queued and matched on a single background thread. The proxy hook only stores
    a tuple, and flows are indexed by request key, so each flow is parsed and
    examined once instead of rescanning the whole capture per CDP event.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._by_key: dict[str, list[dict]] = {}
        self._flows_by_key: dict[str, dict[str, tuple[http.HTTPFlow, float]]] = {}
        self._pending_flows: deque[tuple[str, str, float, http.HTTPFlow]] = deque()
        self._pending_records: deque[dict] = deque()
        self._total = 0
        self._flow_count = 0
        self._last_sweep = 0.0
        self._flush_event = threading.Event()
        self._flush_pending = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active_block: str | None = None

    def running(self) -> None:
        cm = get_cdp()
        if cm is None:
            logger.warning(
                "caller_id: CDP manager not available (load cdp_manager.py first)"
            )
            return
        cm.on_request(self._on_cdp_request)
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="caller_id", daemon=True
            )
            self._thread.start()
        logger.warning("caller_id: CDP initiator capture enabled")

    def done(self) -> None:
        self._stop.set()
        with self._cond:
            self._cond.notify_all()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
            self._thread = None

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request is None or self._thread is None:
            return
        with self._cond:
            self._pending_flows.append(
                (
                    flow.request.method,
                    flow.request.pretty_url,
                    flow.request.timestamp_start,
                    flow,
                )
            )
            self._cond.notify()

    def _on_cdp_request(self, record: dict) -> None:
        if self._thread is None:
            return
        rec = self._prepare(record)
        if rec is None:
            return
        with self._cond:
            self._pending_records.append(rec)
            self._cond.notify()

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

    def _run(self) -> None:
        while not self._stop.is_set():
            with self._cond:
                if not self._pending_flows and not self._pending_records:
                    self._cond.wait(IDLE_POLL)
                flows = [
                    self._pending_flows.popleft()
                    for _ in range(min(CHUNK, len(self._pending_flows)))
                ]
                records = [
                    self._pending_records.popleft()
                    for _ in range(min(CHUNK, len(self._pending_records)))
                ]
                now = time.time()
                if now - self._last_sweep >= SWEEP_INTERVAL:
                    self._last_sweep = now
                    self._sweep_flows_locked(now)
                    if self._total > SWEEP_THRESHOLD:
                        self._sweep_records_locked(now)

            for rec in records:
                self._ingest_record(rec)
            for method, url, ts, flow in flows:
                self._match_flow(method, url, ts, flow)

            with self._cond:
                if self._flush_pending and not self._pending_flows:
                    if not self._pending_records:
                        self._flush_pending = False
                        self._flush_event.set()

            if flows or records:
                time.sleep(BATCH_PAUSE)

    def _ingest_record(self, rec: dict) -> None:
        key = rec["key"]
        flow: http.HTTPFlow | None = None
        with self._cond:
            self._by_key.setdefault(key, []).append(rec)
            self._total += 1
            bucket = self._flows_by_key.get(key)
            if bucket:
                flow = self._claim_flow_locked(key, bucket, rec["_t"])
                if flow is not None:
                    rec["_used"] = True
        if flow is not None:
            self._apply(flow, rec)

    def _match_flow(
        self, method: str, url: str, ts: float, flow: http.HTTPFlow
    ) -> None:
        key = _key(method, url)
        with self._cond:
            rec = self._claim_record_locked(key, ts)
            if rec is None:
                self._index_flow_locked(key, flow)
        if rec is not None:
            self._apply(flow, rec)

    def _claim_record_locked(self, key: str, ts: float) -> dict | None:
        recs = self._by_key.get(key)
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

    def _claim_flow_locked(
        self, key: str, bucket: dict[str, tuple[http.HTTPFlow, float]], ts: float
    ) -> http.HTTPFlow | None:
        best_id: str | None = None
        best_delta: float | None = None
        for fid, (flow, _expires) in bucket.items():
            if flow.metadata.get("caller"):
                continue
            delta = abs(ts - flow.request.timestamp_start)
            if delta > WINDOW:
                continue
            if best_delta is None or delta < best_delta:
                best_id = fid
                best_delta = delta
        if best_id is None:
            return None
        flow, _expires = bucket.pop(best_id)
        self._flow_count -= 1
        if not bucket:
            del self._flows_by_key[key]
        return flow

    def _index_flow_locked(self, key: str, flow: http.HTTPFlow) -> None:
        bucket = self._flows_by_key.setdefault(key, {})
        if flow.id in bucket:
            return
        bucket[flow.id] = (flow, time.time() + FLOW_TTL)
        self._flow_count += 1
        if self._flow_count > MAX_FLOWS:
            self._sweep_flows_locked(time.time())
            if self._flow_count > MAX_FLOWS:
                self._flows_by_key.clear()
                self._flow_count = 0

    def _drop_flow_locked(self, key: str, flow_id: str) -> None:
        bucket = self._flows_by_key.get(key)
        if not bucket or bucket.pop(flow_id, None) is None:
            return
        self._flow_count -= 1
        if not bucket:
            del self._flows_by_key[key]

    def _sweep_flows_locked(self, now: float) -> None:
        for key in list(self._flows_by_key):
            bucket = self._flows_by_key[key]
            for fid, (flow, expires) in list(bucket.items()):
                if expires <= now or flow.metadata.get("caller"):
                    del bucket[fid]
                    self._flow_count -= 1
            if not bucket:
                del self._flows_by_key[key]

    def _sweep_records_locked(self, now: float) -> None:
        cutoff = now - TTL
        total = 0
        for key in list(self._by_key):
            recs = [
                r for r in self._by_key[key] if not r.get("_used") and r["_t"] >= cutoff
            ]
            if recs:
                self._by_key[key] = recs
                total += len(recs)
            else:
                del self._by_key[key]
        self._total = total
        if total > MAX_RECORDS:
            self._trim_records_locked()

    def _trim_records_locked(self) -> None:
        flat = sorted(
            ((r["_t"], key, r) for key, recs in self._by_key.items() for r in recs),
            key=lambda item: item[0],
        )
        kept = flat[len(flat) - MAX_RECORDS :]
        self._by_key = {}
        for _ts, key, rec in kept:
            self._by_key.setdefault(key, []).append(rec)
        self._total = len(kept)

    def _flush(self, timeout: float = 2.0) -> None:
        """Process everything queued so far (used by the commands)."""
        if self._thread is None:
            return
        with self._cond:
            self._flush_event.clear()
            self._flush_pending = True
            self._cond.notify()
        if not self._flush_event.wait(timeout):
            with self._cond:
                self._flush_pending = False

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
        key = _key(flow.request.method, flow.request.pretty_url)
        with self._cond:
            rec = self._claim_record_locked(key, flow.request.timestamp_start)
            if rec is not None:
                self._drop_flow_locked(key, flow.id)
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

        self._flush()
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

        self._flush()
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
        _filter_remove(self._active_block)
        self._active_block = None

        with self._cond:
            self._pending_flows.clear()
            self._flows_by_key.clear()
            self._flow_count = 0

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
        self._flush()
        cm = get_cdp()
        with self._cond:
            records = sum(len(v) for v in self._by_key.values())
            pending = len(self._pending_flows) + len(self._pending_records)
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
            f"{pending} queued, {tagged} tagged flow(s)",
        )

    def _set_filter(self, caller_id: str) -> None:
        _filter_remove(self._active_block)
        self._active_block = f'((~meta "caller: {caller_id}"))'
        _filter_add(self._active_block)


addons = [CallerId()]
