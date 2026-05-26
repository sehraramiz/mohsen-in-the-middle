import json
import time
import socket
import logging
import urllib.request

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy.log import ALERT
from mitmproxy.http import HTTPFlow


class Rotator:
    def __init__(self) -> None:
        self.requests_with_current_ip = 0

    def load(self, loader):
        loader.add_option(
            name="tor_host",
            typespec=str,
            default="127.0.0.1",
            help="Tor Host",
        )
        loader.add_option(
            name="tor_http_port",
            typespec=int,
            default=9080,
            help="Tor Port",
        )
        loader.add_option(
            name="tor_control_port",
            typespec=int,
            default=9051,
            help="Tor Control Port",
        )
        loader.add_option(
            name="tor_control_password",
            typespec=str,
            default="",
            help="Tor Control Password",
        )
        loader.add_option(
            name="requests_per_ip",
            typespec=int,
            default=100,
            help="After how many requests you want a new ip",
        )

    def running(self):
        self.tor_host = ctx.options.tor_host
        self.tor_http_port = ctx.options.tor_http_port
        self.tor_control_port = ctx.options.tor_control_port
        self.tor_control_password = ctx.options.tor_control_password
        assert self.tor_control_password, "Must set tor control password"
        assert (
            self._tor_is_available()
        ), f"Check if tor control protocol is available at {self.tor_host} {self.tor_control_port}"
        assert (
            self._get_current_tor_ip()
        ), f"Check if tor proxy is available at {self.tor_host} {self.tor_http_port}"

        upstream = f"upstream:http://{self.tor_host}:{self.tor_http_port}"
        if not any(upstream in mode for mode in ctx.options.mode):
            ctx.options.update_known(mode=[upstream])

    def _get_current_tor_ip(self) -> str | None:
        proxy_url = f"http://{self.tor_host}:{self.tor_http_port}"
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url,
            "https": proxy_url,
        })
        opener = urllib.request.build_opener(proxy_handler)
        try:
            with opener.open("https://check.torproject.org/api/ip", timeout=10) as resp:
                data = json.loads(resp.read())
                return data.get("IP")
        except Exception as e:
            logging.error(f"Tor ip fetch failed: {e}")
            return None

    def _tor_is_available(self) -> bool:
        try:
            return self._tor_control("PROTOCOLINFO")
        except Exception as e:
            logging.error(f"Tor availability check failed: {e}")
            return False

    def _tor_control(self, command) -> bool:
        """Send command to Tor control port"""

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.tor_host, self.tor_control_port))

        s.send(f'AUTHENTICATE "{self.tor_control_password}"\r\n'.encode())
        response = s.recv(1024)

        if b"250" not in response:
            logging.error("Tor control authentication failed")
            return False

        s.send(f"{command}\r\n".encode())
        response = s.recv(1024)
        s.close()
        return b"250" in response

    def _get_new_ip(self) -> None:
        logging.log(ALERT, "rotating ip...")
        current_tor_ip = self._get_current_tor_ip()
        if current_tor_ip is None:
            return
        logging.log(ALERT, f"current ip: {current_tor_ip}")
        if not self._tor_control("SIGNAL NEWNYM"):
            return
        for _ in range(10):
            new_ip = self._get_current_tor_ip()
            if new_ip and current_tor_ip != new_ip:
                logging.log(ALERT, f"new ip: {new_ip}")
                break
            time.sleep(0.2)

    def request(self, flow: HTTPFlow) -> None:
        # TODO: add more rotation conditions, for example rotate if the response status code is 429
        if self.requests_with_current_ip >= ctx.options.requests_per_ip:
            self._get_new_ip()
            self.requests_with_current_ip = 0
        else:
            self.requests_with_current_ip += 1

    @command.command("rotate")
    def rotate_ip(self) -> None:
        self._get_new_ip()


addons = [Rotator()]
