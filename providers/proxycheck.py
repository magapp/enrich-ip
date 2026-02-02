"""proxycheck.io provider."""

import json
import sys
import urllib.request
import urllib.parse
import urllib.error

from providers.base import BaseProvider
from utils import is_valid_public_ip


class ProxycheckProvider(BaseProvider):
    """Provider for proxycheck.io proxy/VPN detection."""

    name = "proxycheck"
    requires_api_key = True
    key_cache_file = ".enrichip-proxycheck-key"
    headers = ["Proxy", "Proxy-Type", "Risk", "Country", "City", "Organisation", "Operator", "Traceable", "Attack-History"]
    dependencies = []

    @classmethod
    def add_arguments(cls, parser):
        """Add proxycheck specific arguments."""
        parser.add_argument(
            "--use-proxycheck",
            action="store_true",
            default=False,
            help="Use proxycheck.io API for proxy/VPN detection"
        )
        parser.add_argument(
            "--proxycheck-api",
            type=str,
            help="API key for proxycheck.io"
        )

    def initialize(self, args):
        """Initialize the proxycheck provider."""
        if not args.use_proxycheck:
            return True

        self.enabled = True
        return self._load_api_key(args, 'proxycheck_api', 'proxycheck.io')

    def enrich(self, ip, context):
        """Lookup IP in proxycheck.io."""
        if not is_valid_public_ip(ip):
            return [""] * 9

        params = urllib.parse.urlencode({
            "key": self.api_key,
            "vpn": 1,
            "asn": 1,
            "port": 1,
            "risk": 2
        })
        url = f"https://proxycheck.io/v2/{ip}?{params}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                if data.get("status") != "ok":
                    print(f"proxycheck.io API error for {ip}: {data.get('message', 'Unknown error')}", file=sys.stderr)
                    return [""] * 9
                result = data.get(ip, {})
                proxy = result.get("proxy", "")
                proxy_type = result.get("type", "")
                risk = str(result.get("risk", ""))
                country = result.get("country", "")
                city = result.get("city", "")
                organisation = result.get("organisation", "")
                # Operator is a nested dict with VPN provider details
                operator_data = result.get("operator", {})
                if isinstance(operator_data, dict):
                    operator_name = operator_data.get("name", "")
                    policies = operator_data.get("policies", {})
                    traceable = policies.get("traceable_ownership", "")
                else:
                    operator_name = ""
                    traceable = ""
                # Attack history is a dict with attack types and counts
                attack_history = result.get("attack history", {})
                if isinstance(attack_history, dict):
                    # Format as "type:count, type:count" excluding Total
                    attacks = [f"{k}:{v}" for k, v in attack_history.items() if k != "Total"]
                    attack_history_str = ", ".join(attacks)
                else:
                    attack_history_str = str(attack_history) if attack_history else ""
                return [str(proxy), proxy_type, risk, country, city, organisation, operator_name, str(traceable), attack_history_str]
        except urllib.error.HTTPError as e:
            print(f"proxycheck.io API error for {ip}: {e}", file=sys.stderr)
            return [""] * 9
        except urllib.error.URLError as e:
            print(f"Error connecting to proxycheck.io API: {e}", file=sys.stderr)
            return [""] * 9
