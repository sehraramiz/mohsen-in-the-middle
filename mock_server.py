from mitmproxy import http


def request(flow: http.HTTPFlow) -> None:
    flow.response = http.Response.make(
        200, b"Hello from the mock addon!", {"Content-Type": "text/plain"}
    )
