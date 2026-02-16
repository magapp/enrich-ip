# enrich-ip

A tool to enrich IP addresses with additional information from various sources. Available as both a command-line tool and a web application.

If you have a list of IP-adresses in a text file or CSV-file, you can run enrich-ip. With help from the sources listed below,
a new CSV-file will be generated with additional columns containting more information about the addresses.

Note that if you use enrich-ip as a forensic tool, some of the services will cause an external API call, meaning that you could expose your own IP address in combination with the IP you're interesstd in.

IP-DB is a database that is downloaded locally so with this one you can probe as much as you want without exposing yourself.

Also note that some of the services requires an API-key.

Enrich-ip is module based, so each service is defined as a "provider" in the the code. You can add your own providers easy by adding a new module.

For example, you have a text file with IP-adresses, like this:

```
195.26.255.37
216.244.66.250
89.21.85.26
169.150.203.202
193.36.225.160
136.144.33.19
188.143.244.141
154.38.185.108
172.190.142.176
34.34.1.42
34.13.202.197
160.187.211.129
188.143.244.145
146.247.137.91
69.10.58.98
149.88.16.131
146.70.192.108
149.88.23.89
4.223.174.255
185.223.152.104
```

The output would be a CSV file like this  (you may need to scroll to the right to see the whole table):

| IP              | IP-Country      | IP-City                           | IP-Type   | IP-AS-ORG                        | IP-ASN | IP-ISP                          | IP-DOMAIN | DNSBL-Count | Hostname                               | Banners | Abuse-Score | Abuse-Reports | Abuse-Country |
|-----------------|-----------------|-----------------------------------|-----------|----------------------------------|--------|---------------------------------|-----------|-------------|----------------------------------------|---------|-------------|---------------|---------------|
| 195.26.255.37   | United States   | St Louis                          | Corporate | Contabo Inc.                     | 40021  | Contabo Inc.                    |           | 0           | ip-37-255-26-195.static.contabo.net    |         | 0           | 0             | US            |
| 216.244.66.250  | United States   | Tukwila (Riverton-Boulevard Park) | Corporate | Wowrack.com                      | 23033  | Wowrack.com                     |           | 0           |                                        |         | 93          | 245           | US            |
| 89.21.85.26     | Indonesia       | Cibinong                          | Corporate | CV Andhika Pratama Sanggoro      | 141892 | CV Andhika Pratama Sanggoro     |           | 0           |                                        |         | 90          | 89            | ID            |
| 169.150.203.202 | United States   | Los Angeles                       | Corporate | Datacamp Limited                 | 212238 | Datacamp Limited                |           | 0           | unn-169-150-203-202.datapacket.com     |         | 100         | 1140          | US            |
| 193.36.225.160  | United States   | Rossmoor                          | Corporate | F.N.S. HOLDINGS LIMITED          | 206092 | F.N.S. HOLDINGS LIMITED         |           | 0           |                                        |         | 92          | 60            | US            |
| 136.144.33.19   | United States   | Rossmoor                          | Cellular  | F.N.S. HOLDINGS LIMITED          | 206092 | F.N.S. HOLDINGS LIMITED         |           | 0           |                                        |         | 100         | 61            | US            |
| 188.143.244.141 | Russia          | St Petersburg                     | Cable/DSL | Petersburg Internet Network ltd. | 44050  | Petersburg Internet Network LLC |           | 2           |                                        |         | 48          | 59            | RU            |
| 154.38.185.108  | United States   | New York                          | Corporate | Contabo Inc.                     | 40021  | Contabo Inc.                    |           | 0           | vmi2888029.contaboserver.net           |         | 0           | 0             | US            |
| 172.190.142.176 | United States   | Washington                        | Corporate | Microsoft Corporation            | 8075   | Microsoft                       |           | 2           |                                        |         | 100         | 6789          | US            |
| 34.34.1.42      | The Netherlands | Groningen                         | Corporate | Google LLC                       | 396982 | Google LLC                      |           | 1           | 42.1.34.34.bc.googleusercontent.com    |         | 0           | 0             | NL            |
| 34.13.202.197   | The Netherlands | Groningen                         | Corporate | Google LLC                       | 396982 | Google LLC                      |           | 1           | 197.202.13.34.bc.googleusercontent.com |         | 0           | 0             | NL            |
| 160.187.211.129 | Malaysia        | Gelang Patah                      | Corporate | Advin Services LLC               | 206216 | Advin Services LLC              |           | 0           |                                        |         | 0           | 1             | MY            |
| 188.143.244.145 | Russia          | St Petersburg                     | Cable/DSL | Petersburg Internet Network ltd. | 44050  | Petersburg Internet Network LLC |           | 2           |                                        |         | 59          | 76            | RU            |
| 146.247.137.91  | Norway          | Oslo                              | Corporate | GlobalConnect AB                 | 12552  | GlobalConnect AB                |           | 0           | newton59.opoint.com                    | ssh     | 0           | 1             | NO            |
| 69.10.58.98     | United States   | Paterson                          | Corporate | Interserver, Inc                 | 19318  | Interserver                     |           | 0           |                                        |         | 0           | 0             | US            |
| 149.88.16.131   | Canada          | Toronto                           | Corporate | Datacamp Limited                 | 212238 | Datacamp Limited                |           | 1           | unn-149-88-16-131.datapacket.com       |         | 23          | 25            | CA            |
| 146.70.192.108  | Singapore       | Punggol                           | Corporate | M247 Europe SRL                  | 9009   | M247 Europe SRL                 |           | 0           |                                        |         | 47          | 84            | SG            |
| 149.88.23.89    | Singapore       | Singapore                         | Corporate | Datacamp Limited                 | 212238 | Datacamp Limited                |           | 1           | unn-149-88-23-89.datapacket.com        |         | 48          | 84            | SG            |
| 4.223.174.255   | Sweden          | Gävle                             | Corporate | Microsoft Corporation            | 8075   | Microsoft Corporation           |           | 0           |                                        |         | 0           | 0             | SE            |
| 185.223.152.104 | United States   | Los Angeles                       | Cellular  | Latitude.sh                      | 396356 | Latitude.sh                     |           | 0           |                                        |         | 100         | 127           | US            |

You can also supply a CSV file with columns, then enrich-ip will add more columns. Note that input CSV file must have its first line as a header row. This is useful, for example, if you have a CSV file generated from another tool with IP adress and text or log info. More columns will be added. Enrich-ip will automatically detect if the input file is a text file or CSV file.

## Features

- [IP-DB](https://ip-db.com/): Geolocation data (country, city, ASN, ISP, domain)
- [DNSBL](https://dnsbl.info):: Check if IP is listed in DNS blacklists
- [ipinfo.io](http://ipinfo.io): Get hostname for IP
- [DNSDumpster](https://dnsdumpster.com): Get services that is running on IP, for example, Apache, Nginx, SSH etc.
- [AbuseIPDB](https://www.abuseipdb.com): Get abuse score and report nbr of occurencies the IP have
- [proxycheck.io](https://proxycheck.io): Detect if IP is a proxy/VPN with risk scoring, VPN provider identification (e.g., NordVPN, Mullvad), and attack history
- [KML Export](https://earth.google.com): Generate Google Earth compatible KML file with coordinates of all IPs in list

## Installation

### Using Python virtual environment

```bash
# Create virtual environment
python3 -m venv env

# Activate environment
source env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run CLI
python enrich-ip.py --help

# Run web app
python app.py
```

### Using Docker

```bash
# Build image
docker compose build

# Run the web app (available at http://localhost:5000)
docker compose up web

# Run CLI with arguments
docker compose run enrich-ip --input-file /data/input.csv --use-dnsbl
```

Place input files in the `data/` directory and reference them as `/data/filename.csv`.

## Web Application

The web interface provides the same enrichment capabilities through a browser.

```bash
python app.py
```

Then open http://localhost:5000. With Docker: `docker compose up web` and open http://localhost:5000.

The web form lets you:
- Upload a `.txt` or `.csv` file (up to 16 MB)
- Configure CSV input/output delimiters and IP column index
- Select which providers to use and enter API keys
- Watch real-time progress as IPs are processed (progress bar with per-IP status)
- View enrichment results in an interactive table directly in the browser
- Download the enriched CSV file

API keys entered through the web form are cached the same way as the CLI (`~/.enrichip-*-key` files), so you only need to provide them once. The web form shows an "API key cached" indicator next to providers where a key is already saved.

## CLI Usage

```bash
python enrich-ip.py --input-file <file> [options]
```

### Required arguments

`--input-file` - Path to input txt or csv file containing IP addresses

### Optional arguments

`--csv-delimiter` - Delimiter for input file (default: `;`)

`--csv-ip-field` - Column index for IP address in CSV file

`--csv-delimiter-output` - Delimiter for output CSV file (default: `;`)

`--use-ip-db` - Use IP database for geolocation enrichment

`--ip-db-key` - API key for IP database (cached after first use)

`--use-dnsbl` - Lookup IP in DNSBL blacklists

`--use-ipinfo` - Use ipinfo.io API to get hostname

`--use-dnsdumpster` - Use DNSDumpster API for banners (requires `--use-ipinfo`)

`--dnsdumpster-api` - API key for DNSDumpster (cached after first use)

`--use-abuseipdb` - Use AbuseIPDB API for abuse information

`--abuseipdb-api` - API key for AbuseIPDB (cached after first use)

`--use-proxycheck` - Use proxycheck.io API for proxy/VPN detection

`--proxycheck-api` - API key for proxycheck.io (cached after first use)

`--generate-kml` - Generate KML file for Google Earth (requires `--use-ip-db`)

`--ascii-output` - Output as ASCII table to stdout instead of CSV file


## Examples

### Basic DNSBL check

```bash
python enrich-ip.py --input-file log_info.csv --use-dnsbl --use-ip-db
```

### Full enrichment with geolocation

```bash
python enrich-ip.py --input-file ips.csv --use-ip-db --ip-db-key YOUR_KEY --use-dnsbl --use-abuseipdb --abuseipdb-api YOUR_KEY
```

### Generate KML for Google Earth

```bash
python enrich-ip.py --input-file ips.txt --use-ip-db --generate-kml
```

### Detect proxies and VPNs

```bash
python enrich-ip.py --input-file ips.txt --use-proxycheck --proxycheck-api YOUR_KEY
```

### Output as ASCII table

```bash
python enrich-ip.py --input-file ips.txt --use-proxycheck --ascii-output
```

### Process CSV with custom delimiter

```bash
python enrich-ip.py --input-file data.csv --csv-delimiter "," --csv-delimiter-output "," --use-dnsbl
```

## Output

The tool creates an output file with the same name as the input file but with `.out.csv` extension. If `--generate-kml` is used, a `.kml` file is also created. Use `--ascii-output` to display results as a formatted ASCII table in the terminal instead of writing to a file.

## API Key Caching

API keys are cached in the home directory after first use:

- `~/.enrichip-ip-db-key`
- `~/.enrichip-dnsdumpster-key`
- `~/.enrichip-abuseipdb-key`
- `~/.enrichip-proxycheck-key`

You only need to provide the API key once; subsequent runs will use the cached key.

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Creating New Provider Modules

The tool uses a modular provider architecture. Each enrichment source is implemented as a separate provider module in the `providers/` directory.

### Provider Architecture

```
enrich-ip.py              # CLI entry point
app.py                    # Flask web application
templates/index.html      # Web form template
providers/
├── __init__.py           # Provider registry
├── base.py               # BaseProvider abstract class
├── ipdb.py               # IP-DB provider
├── dnsbl.py              # DNSBL provider
├── ipinfo.py             # ipinfo.io provider
├── dnsdumpster.py        # DNSDumpster provider
├── abuseipdb.py          # AbuseIPDB provider
└── proxycheck.py         # proxycheck.io provider
tests/
└── test_app.py           # Tests
```

### Creating a New Provider

1. Create a new file in `providers/` (e.g., `providers/myprovider.py`)

2. Implement the provider class:

```python
from providers.base import BaseProvider
from utils import is_valid_public_ip

class MyProvider(BaseProvider):
    """Provider for MyService."""

    name = "myprovider"                         # Used in --use-myprovider flag
    requires_api_key = True                     # Set to False if no API key needed
    key_cache_file = ".enrichip-myprovider-key" # Cache file in home directory
    headers = ["Column1", "Column2"]            # CSV column headers
    dependencies = []                           # Other providers this depends on

    @classmethod
    def add_arguments(cls, parser):
        """Add command line arguments."""
        parser.add_argument(
            "--use-myprovider",
            action="store_true",
            default=False,
            help="Use MyService for enrichment"
        )
        # Add API key argument if required
        parser.add_argument(
            "--myprovider-api",
            type=str,
            help="API key for MyService"
        )

    def initialize(self, args):
        """Initialize the provider."""
        if not args.use_myprovider:
            return True

        self.enabled = True

        # If API key is required, load it
        if self.requires_api_key:
            return self._load_api_key(args, 'myprovider_api', 'MyService')
        return True

    def enrich(self, ip, context):
        """Enrich IP with data from MyService.

        Args:
            ip: The IP address to enrich
            context: Dict for passing data between providers

        Returns:
            List of values matching self.headers, or None on error
        """
        if not is_valid_public_ip(ip):
            return [""] * len(self.headers)

        # Call your API here
        # ...

        # Return values matching headers order
        return ["value1", "value2"]
```

3. Register the provider in `providers/__init__.py`:

```python
from providers.myprovider import MyProvider

ALL_PROVIDERS = [
    # ... existing providers ...
    MyProvider,  # Add your provider here
]
```

### Provider Interface

| Method | Purpose |
|--------|---------|
| `add_arguments(parser)` | Add CLI arguments (--use-X, --X-api) |
| `initialize(args)` | Validate args, load API key, return True/False |
| `get_headers()` | Return list of CSV column headers |
| `enrich(ip, context)` | Enrich IP, return list of values or None |

### Context Dictionary

Providers can share data via the `context` dict passed to `enrich()`:

```python
# In ipinfo provider - store hostname
context['hostname'] = hostname

# In dnsdumpster provider - use hostname
hostname = context.get('hostname')
```

### Provider Dependencies

If your provider depends on another provider running first:

1. Add to `dependencies` list: `dependencies = ["ipinfo"]`
2. Check in `initialize()`:
   ```python
   if not args.use_ipinfo:
       print("Error: --use-myprovider requires --use-ipinfo", file=sys.stderr)
       sys.exit(1)
   ```
3. Ensure provider order in `ALL_PROVIDERS` list (dependencies must come first)

## License

MIT
