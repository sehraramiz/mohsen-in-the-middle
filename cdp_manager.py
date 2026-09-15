import functools
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import websockets.sync.client

from mitmproxy import command
from cdp_registry import register
from config import host_in_scope, settings

logger = logging.getLogger(__name__)

CDP_HOST: str = getattr(settings, "cdp_host", "127.0.0.1")
CDP_PORT: int = getattr(settings, "cdp_port", 9222)
CDP_POLL_INTERVAL: float = getattr(settings, "cdp_poll_interval", 2.0)
CDP_TIMEOUT: float = getattr(settings, "cdp_timeout", 10.0)
CDP_MAX_RECONNECT_DELAY: float = getattr(settings, "cdp_max_reconnect_delay", 30.0)
CDP_RECONNECT_TIMEOUT: float = getattr(settings, "cdp_reconnect_timeout", 2.0)
CDP_AUTO_LAUNCH: bool = getattr(settings, "cdp_auto_launch", True)
CDP_USER_DATA_DIR: str = getattr(
    settings, "cdp_user_data_dir", "$HOME/.config/google-chrome-debug"
)

DATA_DIR: Path = Path(f"./{settings.project_name}_data/cdp_scripts")
DATA_DIR.mkdir(parents=True, exist_ok=True)

_CHROME_CANDIDATES: list[str] = [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
]
_chrome_path: str | None = next(
    (c for c in _CHROME_CANDIDATES if shutil.which(c)), None
)

_TARGET_TYPES: tuple[str, ...] = (
    "page",
    "iframe",
    "service_worker",
    "worker",
    "shared_worker",
)

_EXTENSION_SCHEMES: frozenset[str] = frozenset(
    {"chrome-extension", "moz-extension", "edge-extension"}
)

_executor = ThreadPoolExecutor(max_workers=4)

_index_lock = threading.Lock()
INDEX_FILE: Path = DATA_DIR / "index.jsonl"


def _slug(value: str, max_len: int = 40) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "_", value or "")
    value = re.sub(r"_+", "_", value).strip("_")
    if len(value) > max_len:
        value = value[:max_len].rstrip("._-")
    return value


def _page_dir(frame_url: str) -> Path:
    parsed = urlparse(frame_url)
    host_seg: str = _slug(parsed.hostname or "") or "unknown_page"
    parts: list[str] = [_slug(p) for p in parsed.path.split("/") if _slug(p)]
    return DATA_DIR.joinpath(host_seg, *parts)


def _script_name(url: str) -> str:
    parsed = urlparse(url)
    name: str = Path(parsed.path).name if parsed.path else ""
    name = _slug(name, max_len=60)
    if name.endswith(".js"):
        name = name[:-3]
    return name or "inline"


def _initiator_segment(initiator_url: str) -> str:
    if not initiator_url:
        return "unknown"
    parsed = urlparse(initiator_url)
    host: str = _slug(parsed.hostname or "") or "unknown"
    name: str = _slug(Path(parsed.path).name) or "root"
    return _slug(f"{host}_{name}", max_len=60)


def _fit_name(parts: list[str], content_hash: str, limit: int = 200) -> str:
    suffix: str = f"__{content_hash}.js"
    for cut in range(len(parts)):
        candidate: str = "__".join(parts[:1] + parts[1 + cut :]) + suffix
        if len(candidate.encode()) <= limit:
            return candidate
    return f"script{suffix}"


def _write_index(record: dict) -> None:
    line: str = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        with _index_lock:
            with open(INDEX_FILE, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception as e:
        logger.warning("cdp: failed to write index (%s)", e)


class Tab:
    def __init__(
        self,
        ws_url: str,
        target_info: dict,
        timeout: float,
        on_script: Callable[[str, str, str, dict], None],
    ):
        self.ws_url: str = ws_url
        self.target_id: str = target_info.get("id", ws_url)
        self.url: str = target_info.get("url", "")
        self.timeout: float = timeout
        self._on_script: Callable[[str, str, str, dict], None] = on_script
        self._ws: websockets.sync.client.ClientConnection | None = None
        self._msg_id: int = 0
        self._pending: dict[int, tuple[str, str, dict]] = {}
        self._seen_script_ids: set[str] = set()
        self._ready: bool = False
        self._enable_msg_id: int | None = None
        self._frame_tree_msg_id: int | None = None
        self._contexts: dict[int, dict] = {}
        self._frames: dict[str, dict] = {}
        self._connected: bool = False
        self._stop: bool = False

    def _send(self, method: str, params: dict | None = None) -> int | None:
        if not self._ws:
            return None
        self._msg_id += 1
        msg: dict = {"id": self._msg_id, "method": method}
        if params:
            msg["params"] = params
        try:
            self._ws.send(json.dumps(msg))
        except Exception:
            return None
        return self._msg_id

    def connect(self, timeout: float | None = None) -> bool:
        try:
            self._ws = websockets.sync.client.connect(
                self.ws_url,
                max_size=2**30,
                ping_interval=None,
                open_timeout=self.timeout if timeout is None else timeout,
                close_timeout=1,
            )
        except Exception as e:
            logger.warning("cdp: connect failed %s (%s)", self.url, e)
            return False
        self._contexts.clear()
        self._frames.clear()
        self._send("Page.enable")
        self._send("Runtime.enable")
        self._frame_tree_msg_id = self._send("Page.getFrameTree")
        mid: int | None = self._send("Debugger.enable")
        if mid is None:
            self.close()
            return False
        self._enable_msg_id = mid
        self._connected = True
        logger.info("cdp: connected to %s", self.url)
        return True

    def run(self) -> None:
        first: bool = True
        while not self._stop:
            try:
                timeout: float = self.timeout if first else CDP_RECONNECT_TIMEOUT
                first = False
                if self.connect(timeout=timeout):
                    self._event_loop()
            except Exception as e:
                logger.warning("cdp: tab error %s (%s)", self.url, e)
            finally:
                self.close()
            if not self._stop:
                time.sleep(1)

    def _event_loop(self) -> None:
        while self._connected and not self._stop:
            try:
                data: dict = json.loads(self._ws.recv(timeout=1.0))
            except TimeoutError:
                continue
            except Exception as e:
                logger.warning("cdp: connection lost %s (%s)", self.url, e)
                self._connected = False
                return
            self._dispatch(data)

    def _dispatch(self, data: dict) -> None:
        msg_id: int | None = data.get("id")
        method: str | None = data.get("method")
        params: dict = data.get("params", {})

        if msg_id is not None and msg_id == self._enable_msg_id:
            self._enable_msg_id = None
            if "error" not in data:
                self._ready = True
                logger.info("cdp: debugger enabled on %s", self.url)
            else:
                logger.warning("cdp: Debugger.enable failed for %s", self.url)
                self._connected = False
            return

        if msg_id is not None and msg_id == self._frame_tree_msg_id:
            self._frame_tree_msg_id = None
            if "error" not in data:
                self._ingest_frame_tree(data.get("result", {}).get("frameTree", {}))
            return

        if method == "Runtime.executionContextCreated":
            self._handle_context_created(params)
        elif method == "Runtime.executionContextDestroyed":
            self._contexts.pop(params.get("executionContextId"), None)
        elif method == "Runtime.executionContextsCleared":
            self._contexts.clear()
        elif method == "Page.frameNavigated":
            self._handle_frame_navigated(params)
        elif method == "Page.frameDetached":
            self._frames.pop(params.get("frameId"), None)
        elif method == "Debugger.scriptParsed" and self._ready:
            self._handle_script_parsed(params)
        elif method == "Debugger.paused":
            self._send("Debugger.resume")

        if msg_id is not None and msg_id in self._pending:
            self._handle_pending_response(msg_id, data)

    def _handle_script_parsed(self, params: dict) -> None:
        script_id: str = params.get("scriptId", "")
        if not script_id or script_id in self._seen_script_ids:
            return
        self._seen_script_ids.add(script_id)
        mid: int | None = self._send(
            "Debugger.getScriptSource", {"scriptId": script_id}
        )
        if mid is None:
            return
        script_url: str = params.get("url", "")
        meta: dict = {
            "execution_context_id": params.get("executionContextId"),
            "execution_context_aux_data": params.get("executionContextAuxData") or {},
            "stack_trace": params.get("stackTrace") or {},
            "is_module": bool(params.get("isModule")),
            "source_map_url": params.get("sourceMapURL", ""),
            "hash": params.get("hash", ""),
            "embedder_name": params.get("embedderName", ""),
        }
        ctx: dict = self._contexts.get(meta["execution_context_id"]) or {}
        aux: dict = meta["execution_context_aux_data"] or ctx.get("auxData") or {}
        meta["is_isolated_world"] = aux.get("isDefault") is False
        self._pending[mid] = (script_id, script_url, meta)

    def _handle_pending_response(self, msg_id: int, data: dict) -> None:
        sid, url, meta = self._pending.pop(msg_id)
        if "error" in data:
            if url:
                logger.warning("cdp: getScriptSource failed for %s", url)
            return
        source: str = data.get("result", {}).get("scriptSource", "")
        if source:
            frame_id: str = self._frame_id_for(meta)
            meta["frame_id"] = frame_id
            meta["frame_url"] = self._resolve_frame_url(frame_id) or self.url
            meta["initiator_url"] = self._resolve_initiator(
                meta.get("stack_trace") or {}
            )
            self._on_script(source, url, sid, meta)

    def _handle_context_created(self, params: dict) -> None:
        context: dict = params.get("context") or {}
        context_id = context.get("id")
        if context_id is not None:
            self._contexts[context_id] = context

    def _handle_frame_navigated(self, params: dict) -> None:
        frame: dict = params.get("frame") or {}
        frame_id: str = frame.get("id", "")
        if not frame_id:
            return
        self._frames[frame_id] = frame
        if not frame.get("parentId") and frame.get("url"):
            self.url = frame["url"]

    def _ingest_frame_tree(self, node: dict) -> None:
        if not node:
            return
        self._handle_frame_navigated({"frame": node.get("frame") or {}})
        for child in node.get("childFrames", []) or []:
            self._ingest_frame_tree(child)

    def _frame_id_for(self, meta: dict) -> str:
        frame_id: str = (meta.get("execution_context_aux_data") or {}).get(
            "frameId", ""
        )
        if not frame_id:
            context = self._contexts.get(meta.get("execution_context_id"))
            if context:
                frame_id = (context.get("auxData") or {}).get("frameId", "")
        return frame_id

    def _resolve_frame_url(self, frame_id: str) -> str:
        if frame_id:
            frame = self._frames.get(frame_id)
            if frame and frame.get("url"):
                return frame["url"]
        return ""

    def _resolve_initiator(self, stack: dict) -> str:
        for frame in stack.get("callFrames", []) or []:
            url = frame.get("url")
            if url:
                return url
        parent = stack.get("parent")
        if parent:
            return self._resolve_initiator(parent)
        return ""

    def close(self) -> None:
        self._connected = False
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None

    def shutdown(self) -> None:
        self._stop = True
        self.close()


class CdpManager:
    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._tabs: dict[str, tuple[Tab, threading.Thread]] = {}
        self._script_callbacks: list[Callable[[str, str, str], None]] = []
        self._script_count: int = 0
        self._enabled: bool = False
        self._user_disabled: bool = False
        self._launched_chrome: bool = False
        self._chrome_up: bool = False
        self._stop: bool = False
        register(self)

    def on_script(self, callback: Callable[[str, str, str], None]) -> None:
        self._script_callbacks.append(callback)

    def running(self) -> None:
        if not self._user_disabled:
            self._start()

    def done(self) -> None:
        self._stop = True
        for tab, _ in self._tabs.values():
            tab.shutdown()
        self._tabs.clear()
        self._enabled = False

    def _start(self) -> None:
        if self._enabled:
            return
        self._enabled = True
        self._stop = False
        threading.Thread(target=self._poll_loop, daemon=True).start()
        logger.info("cdp: started, scanning %s:%d", CDP_HOST, CDP_PORT)

    def _launch_chrome(self) -> None:
        if not _chrome_path:
            logger.warning("cdp: chrome binary not found")
            return
        self._launched_chrome = True
        logger.warning(
            "cdp: launching %s --remote-debugging-port=%d",
            _chrome_path,
            CDP_PORT,
        )
        args = [_chrome_path, f"--remote-debugging-port={CDP_PORT}"]
        user_dir = os.path.expanduser(os.path.expandvars(CDP_USER_DATA_DIR))
        if user_dir:
            args.append(f"--user-data-dir={user_dir}")
        subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _poll_loop(self) -> None:
        delay: float = 1.0
        while not self._stop:
            targets: list[dict] | None = self._fetch_targets()
            if targets is not None:
                self._chrome_up = True
                self._sync_tabs(targets)
                delay = 1.0
            else:
                self._chrome_up = False
                self._sync_tabs([])
                if CDP_AUTO_LAUNCH and not self._launched_chrome:
                    self._launch_chrome()
                logger.warning(
                    "cdp: Chrome unreachable on %s:%d, retrying in %ds...",
                    CDP_HOST,
                    CDP_PORT,
                    int(delay),
                )
                time.sleep(delay)
                delay = min(delay * 2, CDP_MAX_RECONNECT_DELAY)
                continue
            time.sleep(CDP_POLL_INTERVAL)

    def _fetch_targets(self) -> list[dict] | None:
        try:
            req = urllib.request.Request(
                f"http://{CDP_HOST}:{CDP_PORT}/json",
                headers={"User-Agent": "mitmproxy-cdp"},
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=CDP_TIMEOUT) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    def _sync_tabs(self, targets: list[dict]) -> None:
        current_ids: set[str] = set()
        for t in targets:
            target_type: str = t.get("type") or "page"
            if target_type not in _TARGET_TYPES:
                continue
            tid: str | None = t.get("id")
            ws_url: str | None = t.get("webSocketDebuggerUrl")
            if not tid or not ws_url:
                continue
            current_ids.add(tid)
            if tid not in self._tabs:
                self._connect_tab(ws_url, t, target_type)

        dead_ids: set[str] = set(self._tabs) - current_ids
        for tid in dead_ids:
            tab, _ = self._tabs.pop(tid)
            logger.info("cdp: tab closed %s", tab.url)
            tab.shutdown()

    def _connect_tab(self, ws_url: str, target_info: dict, target_type: str) -> None:
        on_script = functools.partial(self._on_script_internal, target_type)
        tab: Tab = Tab(ws_url, target_info, CDP_TIMEOUT, on_script)
        thread: threading.Thread = threading.Thread(target=tab.run, daemon=True)
        self._tabs[target_info["id"]] = (tab, thread)
        thread.start()

    def _on_script_internal(
        self, target_type: str, source: str, url: str, script_id: str, meta: dict
    ) -> None:
        if urlparse(url).scheme in _EXTENSION_SCHEMES:
            return
        if meta.get("is_isolated_world"):
            return
        script_host: str = urlparse(url).hostname or ""
        frame_url: str = meta.get("frame_url", "")
        initiator_url: str = meta.get("initiator_url", "")
        frame_host: str = urlparse(frame_url).hostname or ""
        initiator_host: str = urlparse(initiator_url).hostname or ""

        if not (
            host_in_scope(script_host)
            or host_in_scope(frame_host)
            or host_in_scope(initiator_host)
        ):
            return

        content_hash: str = hashlib.sha256(source.encode()).hexdigest()[:16]

        page_dir: Path = _page_dir(frame_url)
        script_name: str = _script_name(url)
        script_host_seg: str = _slug(script_host) or "inline"
        initiator_seg: str = _initiator_segment(initiator_url)
        file_name: str = _fit_name(
            [script_host_seg, f"from_{initiator_seg}", target_type, script_name],
            content_hash,
        )
        filepath: Path = page_dir / file_name
        if filepath.exists():
            return
        try:
            page_dir.mkdir(parents=True, exist_ok=True)
            filepath.write_text(source, encoding="utf-8")
        except Exception as e:
            logger.warning("cdp: failed to save script %s (%s)", filepath, e)
            return

        self._script_count += 1
        _write_index(
            {
                "file": str(filepath),
                "script_url": url,
                "frame_url": frame_url,
                "initiator_url": initiator_url,
                "stack": (meta.get("stack_trace") or {}).get("callFrames", []),
                "execution_context_id": meta.get("execution_context_id"),
                "frame_id": meta.get("frame_id", ""),
                "target_type": target_type,
                "is_module": meta.get("is_module", False),
                "source_map_url": meta.get("source_map_url", ""),
                "hash": meta.get("hash", ""),
                "content_hash": content_hash,
                "timestamp": time.time(),
            }
        )

        for cb in self._script_callbacks:
            _executor.submit(cb, source, url, script_id)

    @command.command("cdp")
    def cdp_command(self, action: str = "") -> None:
        if action == "off":
            self._user_disabled = True
            self.done()
            logger.warning("cdp: disabled")
        elif action == "on":
            self._user_disabled = False
            self._start()
            logger.warning("cdp: enabled")
        elif action == "launch":
            self._launch_chrome()
            logger.warning("cdp: launch requested")
        elif action == "status":
            if self._enabled:
                if self._chrome_up:
                    logger.warning(
                        "cdp: connected (%d tabs, %d scripts saved)",
                        len(self._tabs),
                        self._script_count,
                    )
                else:
                    logger.warning(
                        "cdp: Chrome unreachable on %s:%d (try :cdp launch) — %d scripts saved",
                        CDP_HOST,
                        CDP_PORT,
                        self._script_count,
                    )
            elif self._user_disabled:
                logger.warning("cdp: disabled by user")
            else:
                logger.warning(
                    "cdp: not started (Chrome reachable on %s:%d?)",
                    CDP_HOST,
                    CDP_PORT,
                )
        else:
            logger.warning("usage: :cdp on|off|status|launch")


addons: list[CdpManager] = [CdpManager.instance()]
