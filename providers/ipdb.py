"""IP-DB geolocation provider."""

import gzip
import json
import sys
import urllib.request
from pathlib import Path

from providers.base import BaseProvider
from utils import is_valid_public_ip


class IPDBProvider(BaseProvider):
    """Provider for IP-DB geolocation data."""

    name = "ip-db"
    requires_api_key = True
    key_cache_file = ".enrichip-ip-db-key"
    headers = ["IP-Country", "IP-City", "IP-Type", "IP-AS-ORG", "IP-ASN", "IP-ISP", "IP-DOMAIN"]
    dependencies = []

    IP_DB_FILE = Path.home() / ".ip-db-full.mmb"

    def __init__(self):
        super().__init__()
        self.db = None
        self.generate_kml = False

    @classmethod
    def add_arguments(cls, parser):
        """Add IP-DB specific arguments."""
        parser.add_argument(
            "--use-ip-db",
            action="store_true",
            help="Use IP database for enrichment",
            default=False
        )
        parser.add_argument(
            "--ip-db-key",
            type=str,
            help="API key for IP database"
        )

    def initialize(self, args):
        """Initialize the IP-DB provider."""
        if not args.use_ip_db:
            return True

        self.enabled = True
        self.generate_kml = getattr(args, 'generate_kml', False)

        # Download database if not present
        if not self.IP_DB_FILE.exists():
            self._download_database(args)

        # Open database
        from geoip2 import database
        self.db = database.Reader(self.IP_DB_FILE)
        return True

    def _download_database(self, args):
        """Download the IP-DB database."""
        key_path = self._get_key_path()

        if args.ip_db_key:
            key_path.write_text(args.ip_db_key)
            print("Storing IP-DB key to cache...")
            api_key = args.ip_db_key
        elif key_path.exists():
            api_key = key_path.read_text().strip()
            print("Retreiving IP-DB key from cache...")
        else:
            print("Error: No IP-DB key provided. Re-run with --ip-db-key", file=sys.stderr)
            sys.exit(1)

        print("IP-DB database not found, downloading from db-ip.com...")
        info_url = f"https://db-ip.com/account/{api_key}/db/ip-to-location-isp/"
        print(info_url)
        try:
            with urllib.request.urlopen(info_url) as response:
                data = json.loads(response.read().decode())
            download_url = data["mmdb"]["url"]
            print(download_url)
            print("Downloading IP database...")
            with urllib.request.urlopen(download_url) as response:
                compressed_data = response.read()
            decompressed_data = gzip.decompress(compressed_data)
            self.IP_DB_FILE.write_bytes(decompressed_data)
            print(f"IP database saved to {self.IP_DB_FILE}")
        except urllib.error.HTTPError as e:
            print(f"Error downloading IP database: {e}", file=sys.stderr)
            sys.exit(1)
        except urllib.error.URLError as e:
            print(f"Error connecting to db-ip.com: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyError:
            print("Error: Invalid response from db-ip.com", file=sys.stderr)
            sys.exit(1)

    def enrich(self, ip, context):
        """Enrich IP with geolocation data."""
        if not is_valid_public_ip(ip):
            print(f"Skipping invalid or non-public IP: '{ip}'")
            return None

        res = self.db.enterprise(ip)
        values = [
            str(res.country.names.get("en", "")).replace("None", ""),
            str(res.city.names.get("en", "")).replace("None", ""),
            str(res.traits.connection_type).replace("None", ""),
            str(res.traits.autonomous_system_organization).replace("None", ""),
            str(res.traits.autonomous_system_number).replace("None", ""),
            str(res.traits.isp).replace("None", ""),
            str(res.traits.domain).replace("None", "")
        ]

        # Store location data in context for KML generation
        if self.generate_kml:
            country = str(res.country.names.get("en", "")).replace("None", "")
            city = str(res.city.names.get("en", "")).replace("None", "")
            context['location'] = (res.location.longitude, res.location.latitude, country, city)

        return values
