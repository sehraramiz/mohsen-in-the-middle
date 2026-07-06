import logging

from cdp_registry import get as get_cdp

logger = logging.getLogger(__name__)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def _script_type(url: str, script_id: str) -> str:
    if not url:
        return "inline"
    if script_id.isdigit() and url.startswith(""):
        return "external"
    return "eval"


class CdpTestConsumer:
    def __init__(self) -> None:
        self._count: int = 0

    def running(self) -> None:
        cm = get_cdp()
        if cm:
            cm.on_script(self._handle_script)
        logger.warning("cdp_test: registered script consumer")

    def _handle_script(self, source: str, url: str, script_id: str) -> None:
        self._count += 1
        logger.warning(
            "[#%d] script_id=%s url=%s size=%s type=%s",
            self._count,
            script_id,
            url or "(inline)",
            _human_size(len(source)),
            _script_type(url, script_id),
        )


addons = [CdpTestConsumer()]
