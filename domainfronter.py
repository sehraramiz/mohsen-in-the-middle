from pathlib import Path

import mitmproxy
from mitmproxy import ctx

from geosite_checker import GeoSiteChecker


# TODO: fix domain that shows in flow list. it is currently showing the fake sni for all requests
domain_group_mapper: dict[str, str] = {"google": "www.google.com"}


class DomainFronter:
    def load(self, loader):
        loader.add_option(
            name="geosite_file_path",
            typespec=str,
            default="./geosite.dat",
            help="geosite.dat file path",
        )

    def running(self):
        geosite_file_path = Path(mitmproxy.ctx.options.geosite_file_path)
        if not geosite_file_path.exists():
            raise ValueError(f"Geosite file not found. {geosite_file_path}")

        self.domain_checker = GeoSiteChecker(geosite_file_path)

    def server_connect(
        self, data: mitmproxy.proxy.server_hooks.ServerConnectionHookData
    ):
        original_address = data.server.address[0]
        for domain_group, target_domain in domain_group_mapper.items():
            if self.domain_checker.check(original_address, domain_group):
                data.server.address = (target_domain, 443)
                ctx.log.info(
                    f"swapped server address {original_address} with {target_domain}"
                )
                return


addons = [DomainFronter()]
