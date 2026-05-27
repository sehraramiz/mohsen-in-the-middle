import re

from mitmproxy.http import HTTPFlow
from mitmproxy import ctx

from config import scope, data_dir

_FLUSH_INTERVAL = 10

CDN_CACHE_HEADERS = {
    "cf-cache-status",
    "x-cache",
    "x-cache-remote",
    "x-cache-lookup",
    "x-varnish-action",
    "x-proxy-cache",
    "x-amz-cf-pop",
    "x-amz-rid",
}

_CACHE_VALUE_PAT = re.compile(
    r"(hit|miss|stale|fresh|expired|bypass|dynamic|tcp_hit|tcp_miss|"
    r"tcp_refresh_hit|tcp_ims_hit|tcp_denied|served_from|hit_from|miss_from)"
)

_CDN_KEY_PAT = re.compile(
    r"(cache|edge|cdn|proxy|varnish|upstream|result|status|x-cache|x-hit)"
)


class CacheOracle:
    def __init__(self) -> None:
        self._log_buffer: list[str] = []

    def load(self, loader):
        loader.add_option(
            name="cache_header_regex",
            typespec=str | None,
            default=None,
            help="Regex to match custom cache related headers",
        )

    def _flush_log(self, path) -> None:
        if not self._log_buffer:
            return
        with open(path, "a") as f:
            f.writelines(self._log_buffer)
        self._log_buffer.clear()

    @scope()
    def response(self, flow: HTTPFlow):
        cache_log_file = data_dir / "cache_oracles.log"
        log_parts: list[str] = []
        headers = flow.response.headers
        cache_header_regex = ctx.options.cache_header_regex

        found_cdn = False
        found_custom = cache_header_regex is None
        found_hit = False
        found_token = False
        found_age = False
        found_maxage = False

        for k, v in headers.items():
            key_lower = k.lower()
            val_lower = v.lower()

            if not found_cdn and key_lower in CDN_CACHE_HEADERS:
                log_parts.append(f"{key_lower}: {val_lower}")
                found_cdn = True

            if not found_custom and re.search(
                cache_header_regex, f"{key_lower}: {val_lower}"
            ):
                log_parts.append(f"{key_lower}: {val_lower}")
                found_custom = True

            if (
                not found_hit
                and _CACHE_VALUE_PAT.search(val_lower)
                and _CDN_KEY_PAT.search(key_lower)
            ):
                log_parts.append(f"{key_lower}: {val_lower}")
                found_hit = True

            if not found_token and _CACHE_VALUE_PAT.match(val_lower):
                log_parts.append(f"{key_lower}: {val_lower}")
                found_token = True

            if not found_age and key_lower == "age" and val_lower != "0":
                log_parts.append(f"{key_lower}: {val_lower}")
                found_age = True

            if (
                not found_maxage
                and key_lower == "cache-control"
                and "max-age=" in val_lower
                and "max-age=0" not in val_lower
            ):
                log_parts.append(f"{key_lower}: {val_lower}")
                found_maxage = True

            if found_cdn and found_custom and found_hit and found_token and found_age and found_maxage:
                break

        if log_parts:
            self._log_buffer.append(
                f"{flow.id}|{flow.request.pretty_url}|{'|'.join(log_parts)}\n"
            )
            if len(self._log_buffer) >= _FLUSH_INTERVAL:
                self._flush_log(cache_log_file)

    def done(self):
        self._flush_log(data_dir / "cache_oracles.log")


addons = [CacheOracle()]
