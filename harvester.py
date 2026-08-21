from typing import Any
import json
import logging
from pathlib import Path

from mitmproxy.http import HTTPFlow
from config import settings, scope

MAX_JSON_SIZE = 1_048_576


def get_all_keys(d: dict[str, Any]) -> set[str]:
    keys: set[str] = set()

    def recurse(obj: Any):
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(k)
                recurse(v)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(d)
    return keys


class Harvester:
    def __init__(self) -> None:
        self.keywords = set()
        self.header_keywords = set()
        self.xheader_keywords = set()
        self.cookie_keywords = set()
        self.ws_keywords = set()
        self._dirty = False
        self.data_dir_name = f"{settings.project_name}_data"

        self.words_path = Path(
            f"./{self.data_dir_name}/{settings.project_name}.words.txt"
        )
        self.header_words_path = Path(
            f"./{self.data_dir_name}/{settings.project_name}.header.words.txt"
        )
        self.xheader_words_path = Path(
            f"./{self.data_dir_name}/{settings.project_name}.xheader.words.txt"
        )
        self.cookie_words_path = Path(
            f"./{self.data_dir_name}/{settings.project_name}.cookie.words.txt"
        )
        self.ws_words_path = Path(
            f"./{self.data_dir_name}/{settings.project_name}.websocket.words.txt"
        )
        for path in [
            self.words_path,
            self.header_words_path,
            self.xheader_words_path,
            self.cookie_words_path,
            self.ws_words_path,
        ]:
            if not path.parent.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.touch()
        self.load_words()

    def load_words(self) -> None:
        for path, target in [
            (self.words_path, self.keywords),
            (self.header_words_path, self.header_keywords),
            (self.xheader_words_path, self.xheader_keywords),
            (self.cookie_words_path, self.cookie_keywords),
            (self.ws_words_path, self.ws_keywords),
        ]:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    target.add(line.strip())

    def persist(self) -> None:
        if not self._dirty:
            return
        for path, source in [
            (self.words_path, self.keywords),
            (self.header_words_path, self.header_keywords),
            (self.xheader_words_path, self.xheader_keywords),
            (self.cookie_words_path, self.cookie_keywords),
            (self.ws_words_path, self.ws_keywords),
        ]:
            with open(path, "w", encoding="utf-8") as f:
                for word in sorted(source):
                    f.write(f"{word}\n")
        self._dirty = False

    def _mark_dirty(self, container: set, candidates: set | list) -> None:
        before = len(container)
        container.update(candidates)
        if len(container) > before:
            self._dirty = True

    def _extract_json_text(self, text: str, host: str) -> set[str]:
        if not text or text[0] not in "[{":
            return set()
        if len(text) > MAX_JSON_SIZE:
            return set()
        try:
            return get_all_keys(json.loads(text))
        except Exception:
            logging.exception("Error extracting JSON keys from %s", host)
            return set()

    def _extract_json_keywords(self, flow_item, host: str) -> None:
        content_type = flow_item.headers.get("content-type", "")
        if "json" not in content_type:
            return
        if not flow_item.content:
            return
        keys = self._extract_json_text(flow_item.content.decode("utf-8"), host)
        self._mark_dirty(self.keywords, keys)

    def _extract_header_keywords(self, headers: list[str]) -> None:
        self._mark_dirty(self.header_keywords, headers)
        x_headers = {h for h in headers if h.lower().startswith("x")}
        self._mark_dirty(self.xheader_keywords, x_headers)

    def _extract_cookie_keywords(self, cookies) -> None:
        names = list(cookies.keys())
        self._mark_dirty(self.keywords, names)
        self._mark_dirty(self.cookie_keywords, names)

    @scope()
    def request(self, flow: HTTPFlow):
        self._extract_header_keywords(list(flow.request.headers.keys()))
        self._extract_json_keywords(flow.request, host=flow.request.host)
        self._extract_cookie_keywords(flow.request.cookies)

        query_params = list(flow.request.query.keys())
        self._mark_dirty(self.keywords, query_params)
        self.persist()

    @scope()
    def response(self, flow: HTTPFlow):
        self._extract_header_keywords(list(flow.response.headers.keys()))
        self._extract_json_keywords(flow.response, host=flow.request.host)
        self._extract_cookie_keywords(flow.response.cookies)
        self.persist()

    @scope()
    def websocket_message(self, flow: HTTPFlow):
        if not flow.websocket:
            return
        message = flow.websocket.messages[-1]
        if not message.is_text or not message.content:
            return
        keys = self._extract_json_text(message.text, flow.request.host)
        if keys:
            self._mark_dirty(self.ws_keywords, keys)
            self.persist()

addons = [Harvester()]
