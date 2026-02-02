"""ipinfo.io hostname provider."""

import json
import sys
import urllib.request
import urllib.error

from providers.base import BaseProvider
from utils import is_valid_public_ip


class IPInfoProvider(BaseProvider):
    """Provider for ipinfo.io hostname lookups."""

    name = "ipinfo"
    requires_api_key = False
    key_cache_file = ""
    headers = ["Hostname"]
    dependencies = []

    @classmethod
    def add_arguments(cls, parser):
        """Add ipinfo specific arguments."""
        parser.add_argument(
            "--use-ipinfo",
            action="store_true",
            default=False,
            help="Use ipinfo.io API to get hostname"
        )

    def initialize(self, args):
        """Initialize the ipinfo provider."""
        if args.use_ipinfo:
            self.enabled = True
        return True

    def enrich(self, ip, context):
        """Lookup hostname for IP via ipinfo.io."""
        if not is_valid_public_ip(ip):
            return [""]

        url = f"https://ipinfo.io/{ip}/json"
        try:
            with urllib.request.urlopen(url) as response:
                data = json.loads(response.read().decode())
                hostname = data.get("hostname", "")
                # Store hostname in context for dnsdumpster
                if hostname:
                    context['hostname'] = hostname
                return [hostname]
        except urllib.error.HTTPError as e:
            print(f"ipinfo.io API error for {ip}: {e}", file=sys.stderr)
            return [""]
        except urllib.error.URLError as e:
            print(f"Error connecting to ipinfo.io API: {e}", file=sys.stderr)
            return [""]
