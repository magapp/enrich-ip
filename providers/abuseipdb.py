"""AbuseIPDB provider."""

import json
import sys
import urllib.request
import urllib.parse
import urllib.error

from providers.base import BaseProvider
from utils import is_valid_public_ip


class AbuseIPDBProvider(BaseProvider):
    """Provider for AbuseIPDB abuse information."""

    name = "abuseipdb"
    requires_api_key = True
    key_cache_file = ".enrichip-abuseipdb-key"
    headers = ["Abuse-Score", "Abuse-Reports", "Abuse-Country"]
    dependencies = []

    @classmethod
    def add_arguments(cls, parser):
        """Add AbuseIPDB specific arguments."""
        parser.add_argument(
            "--use-abuseipdb",
            action="store_true",
            default=False,
            help="Use AbuseIPDB API for enrichment"
        )
        parser.add_argument(
            "--abuseipdb-api",
            type=str,
            help="API key for AbuseIPDB"
        )

    def initialize(self, args):
        """Initialize the AbuseIPDB provider."""
        if not args.use_abuseipdb:
            return True

        self.enabled = True
        return self._load_api_key(args, 'abuseipdb_api', 'AbuseIPDB')

    def enrich(self, ip, context):
        """Lookup IP in AbuseIPDB."""
        if not is_valid_public_ip(ip):
            return ["", "", ""]

        params = urllib.parse.urlencode({
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        })
        url = f"https://api.abuseipdb.com/api/v2/check?{params}"
        req = urllib.request.Request(url)
        req.add_header("Key", self.api_key)
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                result = data.get("data", {})
                score = str(result.get("abuseConfidenceScore", ""))
                reports = str(result.get("totalReports", ""))
                country = result.get("countryCode", "")
                return [score, reports, country]
        except urllib.error.HTTPError as e:
            print(f"AbuseIPDB API error for {ip}: {e}", file=sys.stderr)
            return ["", "", ""]
        except urllib.error.URLError as e:
            print(f"Error connecting to AbuseIPDB API: {e}", file=sys.stderr)
            return ["", "", ""]
