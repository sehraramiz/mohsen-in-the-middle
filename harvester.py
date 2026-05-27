from typing import Any
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
        for path in [self.words_path, self.header_words_path, self.xheader_words_path]:
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

    def _extract_json_keywords(self, flow_item, host: str) -> None:
        try:
            content_type = flow_item.headers.get("content-type", "")
            if "json" not in content_type:
                return
            if not flow_item.content:
                return
            if len(flow_item.content) > MAX_JSON_SIZE:
                return
            text = flow_item.content.decode("utf-8")
            if not text or text[0] not in "[{":
                return
            keys = get_all_keys(flow_item.json())
            self._mark_dirty(self.keywords, keys)
        except Exception:
            logging.exception(
                "Error extracting JSON keys from %s %s",
                host,
                getattr(flow_item, "path", ""),
            )

    def _extract_header_keywords(self, headers: list[str]) -> None:
        self._mark_dirty(self.header_keywords, headers)
        x_headers = {h for h in headers if h.lower().startswith("x")}
        self._mark_dirty(self.xheader_keywords, x_headers)

    @scope()
    def request(self, flow: HTTPFlow):
        self._extract_header_keywords(list(flow.request.headers.keys()))
        self._extract_json_keywords(flow.request, host=flow.request.host)

        query_params = list(flow.request.query.keys())
        self._mark_dirty(self.keywords, query_params)
        self.persist()

    @scope()
    def response(self, flow: HTTPFlow):
        self._extract_header_keywords(list(flow.response.headers.keys()))
        self._extract_json_keywords(flow.response, host=flow.request.host)
        self.persist()


addons = [Harvester()]
