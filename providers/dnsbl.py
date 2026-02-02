"""DNSBL blacklist provider."""

import socket

from providers.base import BaseProvider
from utils import is_valid_public_ip


DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "psbl.surriel.com",
    "spam.abuse.ch",
    "rbl.interserver.net",
]


class DNSBLProvider(BaseProvider):
    """Provider for DNSBL blacklist lookups."""

    name = "dnsbl"
    requires_api_key = False
    key_cache_file = ""
    headers = ["DNSBL-Count"]
    dependencies = []

    @classmethod
    def add_arguments(cls, parser):
        """Add DNSBL specific arguments."""
        parser.add_argument(
            "--use-dnsbl",
            action="store_true",
            default=False,
            help="Lookup IP in DNSBL blacklists and report number of occurrences"
        )

    def initialize(self, args):
        """Initialize the DNSBL provider."""
        if args.use_dnsbl:
            self.enabled = True
        return True

    def enrich(self, ip, context):
        """Lookup IP in DNSBL blacklists."""
        if not is_valid_public_ip(ip):
            return [""]

        reversed_ip = ".".join(reversed(ip.split(".")))
        count = 0
        for dnsbl in DNSBL_SERVERS:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                socket.gethostbyname(query)
                count += 1
            except socket.gaierror:
                pass
        return [str(count)]
