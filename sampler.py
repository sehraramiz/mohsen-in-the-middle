import re
from typing import Any
import logging
from pathlib import Path

from mitmproxy.http import HTTPFlow
from config import settings, scope


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


class Sampler:
    def __init__(self) -> None:
        self.keywords = set()
        self.header_keywords = set()
        self.xheader_keywords = set()
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
        with open(self.words_path, "r") as words_file:
            for word in words_file:
                self.keywords.add(word.strip())
        with open(self.header_words_path, "r") as words_file:
            for word in words_file:
                self.header_keywords.add(word.strip())
        with open(self.xheader_words_path, "r") as words_file:
            for word in words_file:
                self.xheader_keywords.add(word.strip())

    def add_to_keywords(self) -> None:
        with open(self.words_path, "w") as words_file:
            for word in self.keywords:
                words_file.write(f"{word}\n")
        with open(self.header_words_path, "w") as words_file:
            for word in self.header_keywords:
                words_file.write(f"{word}\n")
        with open(self.xheader_words_path, "w") as words_file:
            for word in self.xheader_keywords:
                words_file.write(f"{word}\n")

    def _extract_json_keywords(self, flow_item, host: str) -> None:
        try:
            if "json" not in flow_item.headers.get("content-type", ""):
                return
            # Ignore this }]
            if flow_item.content and flow_item.content.decode()[0] in "[{":
                keys = list(get_all_keys(flow_item.json()))
                self.keywords.update(keys)
                self.add_to_keywords()
        except Exception as e:
            logging.error(
                "error {} {} {}".format(host, getattr(flow_item, "path", ""), e)
            )

    def _extract_header_keywords(self, headers: list[str]) -> None:
        self.header_keywords.update(headers)
        x_headers_set = {h for h in headers if h.lower().startswith("x")}
        self.xheader_keywords.update(x_headers_set)

    @scope()
    def request(self, flow: HTTPFlow):
        self._extract_header_keywords(list(flow.request.headers.keys()))

        if not any(re.search(p, flow.request.host) for p in settings.in_scope):
            return

        self._extract_json_keywords(flow.request, host=flow.request.host)

        query_params = list(flow.request.query.keys())
        self.keywords.update(query_params)
        self.add_to_keywords()

    @scope()
    def response(self, flow: HTTPFlow):
        self._extract_header_keywords(list(flow.response.headers.keys()))
        if not any(re.search(p, flow.request.host) for p in settings.in_scope):
            return
        self._extract_json_keywords(flow.response, host=flow.request.host)


addons = [Sampler()]
