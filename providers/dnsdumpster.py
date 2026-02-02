"""DNSDumpster banner provider."""

import json
import sys
import urllib.request
import urllib.error

from providers.base import BaseProvider


class DNSDumpsterProvider(BaseProvider):
    """Provider for DNSDumpster banner lookups."""

    name = "dnsdumpster"
    requires_api_key = True
    key_cache_file = ".enrichip-dnsdumpster-key"
    headers = ["Banners"]
    dependencies = ["ipinfo"]  # Requires hostname from ipinfo

    @classmethod
    def add_arguments(cls, parser):
        """Add DNSDumpster specific arguments."""
        parser.add_argument(
            "--use-dnsdumpster",
            action="store_true",
            default=False,
            help="Use DNSDumpster API for enrichment to get banners. This will cause one api-call per ip."
        )
        parser.add_argument(
            "--dnsdumpster-api",
            type=str,
            help="API key for DNSDumpster"
        )

    def initialize(self, args):
        """Initialize the DNSDumpster provider."""
        if not args.use_dnsdumpster:
            return True

        self.enabled = True

        # Check dependency
        if not args.use_ipinfo:
            print("Error: --use-dnsdumpster requires --use-ipinfo", file=sys.stderr)
            sys.exit(1)

        # Load API key
        return self._load_api_key(args, 'dnsdumpster_api', 'DNSDumpster')

    def enrich(self, ip, context):
        """Get banners for hostname via DNSDumpster."""
        hostname = context.get('hostname')
        if not hostname:
            return [""]

        url = f"https://api.dnsdumpster.com/domain/{hostname}"
        req = urllib.request.Request(url)
        req.add_header("X-API-Key", self.api_key)
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                banners = set()
                for a in data.get('a', []):
                    for ips in a.get('ips', []):
                        for key, val in ips.get('banners', {}).items():
                            if key == 'ip':
                                continue
                            banners.add(key)
                return [",".join(list(banners))]
        except urllib.error.HTTPError as e:
            print(f"DNSDumpster API error for {hostname}: {e}", file=sys.stderr)
            return [""]
        except urllib.error.URLError as e:
            print(f"Error connecting to DNSDumpster API: {e}", file=sys.stderr)
            return [""]
