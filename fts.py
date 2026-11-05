import logging
import sqlite3

from mitmproxy import addonmanager, command, ctx, http
from mitmproxy.addonmanager import Loader
from mitmproxy.log import ALERT

FIELDS = ("method", "host", "path", "url", "headers", "req_body", "resp_body")
TEXT_TYPES = ("json", "text", "xml", "javascript", "urlencoded")
FTS_BLOCK = '((~meta "fts: 1"))'
RESULT_LIMIT = 2000
SUMMARY_LIMIT = 15


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


_scope_fn = None


def _resolve_scope():
    global _scope_fn
    if _scope_fn is not None:
        return _scope_fn
    try:
        for a in addonmanager.traverse(ctx.master.addons.chain):
            fn = getattr(a, "host_in_scope", None)
            if callable(fn):
                _scope_fn = fn
                break
    except Exception:
        pass
    return _scope_fn


def _host_in_scope(host: str) -> bool:
    fn = _resolve_scope()
    return fn(host) if fn is not None else True


def _term_expr(query: str, raw: bool, minlen: int = 0) -> str | None:
    if raw:
        return query or None
    terms = [t for t in query.split() if len(t) >= minlen]
    if not terms:
        return None
    return " AND ".join('"' + t.replace('"', '""') + '"' for t in terms)


def _text(msg, cap: int) -> str:
    ct = (msg.headers.get("content-type") or "").lower()
    if not any(t in ct for t in TEXT_TYPES):
        return ""
    t = msg.get_text(strict=False)
    return t[:cap] if t else ""


class FTS:
    def __init__(self) -> None:
        self.con = sqlite3.connect(":memory:", isolation_level=None)
        for table in ("flows_word", "flows_gram"):
            self.con.execute(
                f"CREATE VIRTUAL TABLE {table} USING fts5("
                "id UNINDEXED, method, host, path, url, headers, req_body, resp_body, "
                + (
                    "tokenize='unicode61')"
                    if table == "flows_word"
                    else "tokenize='trigram')"
                )
            )
        self.flows: dict[str, http.HTTPFlow] = {}
        self.rowid_of: dict[str, int] = {}
        self._next_rowid = 1
        self.max_body = 50000
        self.fields: set[str] | None = None
        self.leading = "flows_word"
        self.scope_only = False
        self.active_query: str | None = None
        self.raw_mode = False

    def load(self, loader: Loader) -> None:
        loader.add_option(
            "fts_max_body", int, 50000, "max body bytes to index (0 = none)"
        )
        loader.add_option(
            "fts_fields",
            str,
            "",
            "comma list of fields to index, empty = all: " + ", ".join(FIELDS),
        )
        loader.add_option(
            "fts_tokenizer",
            str,
            "unicode61",
            "leading index for results: unicode61 (words) or trigram (substring/IDs)",
            choices=["unicode61", "trigram"],
        )
        loader.add_option(
            "fts_scope_only",
            bool,
            False,
            "index only flows in config.py scope (requires config.py loaded first)",
        )

    def _apply_options(self) -> None:
        try:
            self.max_body = ctx.options.fts_max_body
            self.fields = {
                f.strip() for f in ctx.options.fts_fields.split(",") if f.strip()
            } or None
            self.leading = (
                "flows_gram" if ctx.options.fts_tokenizer == "trigram" else "flows_word"
            )
            self.scope_only = ctx.options.fts_scope_only
        except Exception:
            pass

    def _index(self, flow: http.HTTPFlow) -> None:
        req, resp = flow.request, flow.response

        def f(name: str, value: str) -> str:
            return value if self.fields is None or name in self.fields else ""

        headers = "\n".join(
            [f"{k}: {v}" for k, v in req.headers.items()]
            + [f"{k}: {v}" for k, v in resp.headers.items()]
        )
        values = (
            flow.id,
            f("method", req.method),
            f("host", req.host),
            f("path", req.path),
            f("url", req.pretty_url),
            f("headers", headers),
            f("req_body", _text(req, self.max_body)),
            f("resp_body", _text(resp, self.max_body)),
        )

        rowid = self.rowid_of.get(flow.id)
        if rowid is None:
            rowid = self._next_rowid
            self._next_rowid += 1
            self.rowid_of[flow.id] = rowid
        for table in ("flows_word", "flows_gram"):
            self.con.execute(f"DELETE FROM {table} WHERE rowid = ?", (rowid,))
            self.con.execute(
                f"INSERT INTO {table} (rowid, id, method, host, path, url, headers, "
                "req_body, resp_body) VALUES (?,?,?,?,?,?,?,?,?)",
                (rowid, *values),
            )

    def _raw_query(self, table: str, expr: str, id_filter: str | None = None):
        sql = f"SELECT id, method, host, path FROM {table} WHERE {table} MATCH ?"
        params: list = [expr]
        if id_filter is not None:
            sql += " AND id = ?"
            params.append(id_filter)
        sql += " ORDER BY rank LIMIT ?"
        params.append(RESULT_LIMIT)
        return self.con.execute(sql, params).fetchall()

    def _query(self, query: str) -> list[tuple]:
        word_expr = _term_expr(query, self.raw_mode)
        gram_expr = _term_expr(query, self.raw_mode, minlen=3)
        word = self._raw_query("flows_word", word_expr) if word_expr else []
        gram = self._raw_query("flows_gram", gram_expr) if gram_expr else []
        leading, other = (gram, word) if self.leading == "flows_gram" else (word, gram)
        merged: dict[str, tuple] = {}
        for row in leading + other:
            merged.setdefault(row[0], row)
        return list(merged.values())

    def _flow_matches(self, flow_id: str) -> bool:
        word_expr = _term_expr(self.active_query, self.raw_mode)
        gram_expr = _term_expr(self.active_query, self.raw_mode, minlen=3)
        for table, expr in (("flows_word", word_expr), ("flows_gram", gram_expr)):
            if not expr:
                continue
            if self._raw_query(table, expr, id_filter=flow_id):
                return True
        return False

    def _set_filter(self, on: bool) -> None:
        if on:
            _filter_add(FTS_BLOCK)
        else:
            _filter_remove(FTS_BLOCK)

    def search(self, query: str, raw: bool = False) -> None:
        self._apply_options()
        self.active_query = query
        self.raw_mode = raw
        rows = self._query(query)
        ids = {r[0] for r in rows}
        for flow in self.flows.values():
            if flow.id in ids:
                flow.metadata["fts"] = "1"
            else:
                flow.metadata.pop("fts", None)
        self._set_filter(True)

        lines = [f"fts: {len(rows)} match(es) for {query!r}"]
        for _, method, host, path in rows[:SUMMARY_LIMIT]:
            lines.append(f"  {method} {host}{path}")
        if len(rows) > SUMMARY_LIMIT:
            lines.append(f"  … +{len(rows) - SUMMARY_LIMIT} more")
        if (
            not rows
            and self.leading == "flows_word"
            and any(len(t) < 3 for t in query.split())
        ):
            lines.append(
                "  (note: terms shorter than 3 chars don't match the trigram index)"
            )
        logging.log(ALERT, "\n".join(lines))

    def clear(self) -> None:
        self.active_query = None
        self.raw_mode = False
        for flow in self.flows.values():
            flow.metadata.pop("fts", None)
        self._set_filter(False)
        logging.log(ALERT, "fts: cleared")

    def status(self) -> None:
        n = self.con.execute("SELECT count(*) FROM flows_word").fetchone()[0]
        size = (
            self.con.execute("PRAGMA page_count").fetchone()[0]
            * self.con.execute("PRAGMA page_size").fetchone()[0]
        )
        logging.log(
            ALERT,
            f"fts: {n} flows indexed, ~{size / 1024:.0f} KiB, "
            f"active query: {self.active_query or '(none)'}",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        self._apply_options()
        if self.scope_only and not _host_in_scope(flow.request.host):
            return
        self.flows[flow.id] = flow
        self._index(flow)
        if self.active_query is not None:
            if self._flow_matches(flow.id):
                flow.metadata["fts"] = "1"
            else:
                flow.metadata.pop("fts", None)


addon = FTS()


@command.command("fts")
def fts_cmd(query: str) -> None:
    """Full-text search over captured flows; tags matches and filters the view."""
    addon.search(query)


@command.command("fts.raw")
def fts_raw_cmd(query: str) -> None:
    """Full-text search with raw FTS5 query syntax."""
    addon.search(query, raw=True)


@command.command("fts.clear")
def fts_clear_cmd() -> None:
    """Clear fts tags and remove the fts view filter."""
    addon.clear()


@command.command("fts.status")
def fts_status_cmd() -> None:
    """Show indexed flow count and index size."""
    addon.status()


addons = [addon]
