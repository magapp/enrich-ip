#!/home/magnus/enrich-ip/env/bin/python3
"""Enrich IP addresses with additional information."""

import argparse
import gzip
import ipaddress
import json
import socket
import sys
from geoip2 import database
import urllib.request
import urllib.parse
from pathlib import Path

IP_DB_KEY_FILE = Path.home() / ".enrichip-ip-db-key"
IP_DB_FILE = Path.home() / ".ip-db-full.mmb"
DNSDUMPSTER_KEY_FILE = Path.home() / ".enrichip-dnsdumpster-key"
ABUSEIPDB_KEY_FILE = Path.home() / ".enrichip-abuseipdb-key"
PROXYCHECK_KEY_FILE = Path.home() / ".enrichip-proxycheck-key"

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Enrich a list or CSV-file with IP-addresses with additional information. "
                    "The list can be a plain text file with one IP on each line or a CSV-file "
                    "where one field contains IP-adress. Additional services can be used to "
                    "enrich the information, such as IP-DB, AbuseIP etc.")
    parser.add_argument( "--input-file", type=argparse.FileType("r"), required=True, help="Path to input txt or csv file containing IP addresses")
    parser.add_argument( "--csv-delimiter", type=str, default=";", help="Delimiter for input file (if csv), default ';'")
    parser.add_argument( "--csv-ip-field", type=int, help="Column index for IP address in CSV file")
    parser.add_argument( "--csv-delimiter-output", type=str, default=";", help="Delimiter for output csv file, default ';'")
    parser.add_argument( "--generate-kml", action="store_true", default=False, help="Generate KML file with coordinates that can be imported to Google Earth")
    parser.add_argument( "--use-ip-db", action="store_true", help="Use IP database for enrichment", default=False)
    parser.add_argument( "--ip-db-key", type=str, help="API key for IP database",)
    parser.add_argument( "--use-dnsdumpster", action="store_true", default=False, help="Use DNSDumpster API for enrichment to get banners. This will cause one api-call per ip.")
    parser.add_argument( "--dnsdumpster-api", type=str, help="API key for DNSDumpster")
    parser.add_argument( "--use-dnsbl", action="store_true", default=False, help="Lookup IP in DNSBL blacklists and report number of occurrences")
    parser.add_argument( "--use-ipinfo", action="store_true", default=False, help="Use ipinfo.io API to get hostname")
    parser.add_argument( "--use-abuseipdb", action="store_true", default=False, help="Use AbuseIPDB API for enrichment")
    parser.add_argument( "--abuseipdb-api", type=str, help="API key for AbuseIPDB")
    parser.add_argument( "--use-proxycheck", action="store_true", default=False, help="Use proxycheck.io API for proxy/VPN detection")
    parser.add_argument( "--proxycheck-api", type=str, help="API key for proxycheck.io")
    return parser.parse_args()

def main():
    location_list = list()
    args = parse_args()

    # Validate dependencies
    if args.generate_kml and not args.use_ip_db:
        print("Error: --generate-kml requires --use-ip-db", file=sys.stderr)
        sys.exit(1)

    if args.use_dnsdumpster and not args.use_ipinfo:
        print("Error: --use-dnsdumpster requires --use-ipinfo", file=sys.stderr)
        sys.exit(1)

    if args.use_dnsdumpster:
        if args.dnsdumpster_api:
            DNSDUMPSTER_KEY_FILE.write_text(args.dnsdumpster_api)
            print("Storing DNSDumpster key to cache...")
        elif DNSDUMPSTER_KEY_FILE.exists():
            args.dnsdumpster_api = DNSDUMPSTER_KEY_FILE.read_text().strip()
            print("Retrieving DNSDumpster key from cache...")
        else:
            print("Error: --use-dnsdumpster requires --dnsdumpster-api", file=sys.stderr)
            sys.exit(1)

    if args.use_abuseipdb:
        if args.abuseipdb_api:
            ABUSEIPDB_KEY_FILE.write_text(args.abuseipdb_api)
            print("Storing AbuseIPDB key to cache...")
        elif ABUSEIPDB_KEY_FILE.exists():
            args.abuseipdb_api = ABUSEIPDB_KEY_FILE.read_text().strip()
            print("Retrieving AbuseIPDB key from cache...")
        else:
            print("Error: --use-abuseipdb requires --abuseipdb-api", file=sys.stderr)
            sys.exit(1)

    if args.use_proxycheck:
        if args.proxycheck_api:
            PROXYCHECK_KEY_FILE.write_text(args.proxycheck_api)
            print("Storing proxycheck.io key to cache...")
        elif PROXYCHECK_KEY_FILE.exists():
            args.proxycheck_api = PROXYCHECK_KEY_FILE.read_text().strip()
            print("Retrieving proxycheck.io key from cache...")
        else:
            print("Error: --use-proxycheck requires --proxycheck-api", file=sys.stderr)
            sys.exit(1)

    # Load IP-DB database
    if args.use_ip_db and not IP_DB_FILE.exists():
        download_ip_db(args)

    # Used if file is csv
    is_csv = False
    csv_input_header = "IP"

    first_line = args.input_file.readline()
    is_csv = args.csv_delimiter in first_line

    if is_csv:
        csv_input_header = first_line
        input_file_lines = args.input_file.readlines()
        if args.csv_ip_field == None:
            args.csv_ip_field = ask_user_about_ip_field(csv_input_header.strip().strip(args.csv_delimiter), args.csv_delimiter)
    else:
        input_file_lines = [first_line] + args.input_file.readlines()

    # Build output filename based on input file and create new output file
    input_filename = Path(args.input_file.name)
    if input_filename.suffix.lower() == ".csv":
        output_filename = input_filename.with_suffix(".out.csv")
    else:
        output_filename = input_filename.with_suffix(input_filename.suffix + ".out.csv")

    try:
        outfile = open(output_filename, "w")
    except PermissionError:
        print(f"Error: Permission denied to create output file: {output_filename}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error: Could not create output file: {output_filename} - {e}", file=sys.stderr)
        sys.exit(1)

    # Build header for output csv file
    csv_output_header = csv_input_header.replace(args.csv_delimiter, args.csv_delimiter_output).strip()

    # If using IP-DB, add headers and open database:
    if args.use_ip_db:
        ip_db_headers = ["IP-Country", "IP-City", "IP-Type", "IP-AS-ORG", "IP-ASN", "IP-ISP", "IP-DOMAIN"]
        csv_output_header = (csv_output_header + args.csv_delimiter_output +
                             args.csv_delimiter_output.join(ip_db_headers))
        ip_db = database.Reader(IP_DB_FILE)

    # If using DNSBL, add header:
    if args.use_dnsbl:
        csv_output_header = csv_output_header + args.csv_delimiter_output + "DNSBL-Count"

    # If using ipinfo, add headers:
    if args.use_ipinfo:
        csv_output_header = (csv_output_header + args.csv_delimiter_output +
                             args.csv_delimiter_output.join(["Hostname"]))

    # If using dnsdumpster, add headers:
    if args.use_dnsdumpster:
        csv_output_header = (csv_output_header + args.csv_delimiter_output +
                             args.csv_delimiter_output.join(["Banners"]))

    # If using AbuseIPDB, add headers:
    if args.use_abuseipdb:
        abuseipdb_headers = ["Abuse-Score", "Abuse-Reports", "Abuse-Country"]
        csv_output_header = (csv_output_header + args.csv_delimiter_output +
                             args.csv_delimiter_output.join(abuseipdb_headers))

    # If using proxycheck.io, add headers:
    if args.use_proxycheck:
        proxycheck_headers = ["Proxy", "Proxy-Type", "Proxy-Risk", "Proxy-Country", "Proxy-ASN", "Proxy-Provider"]
        csv_output_header = (csv_output_header + args.csv_delimiter_output +
                             args.csv_delimiter_output.join(proxycheck_headers))

    # Write header to output file
    if csv_output_header:
        outfile.write(csv_output_header + "\n")

    # Parse input file, line by line
    total_lines = len(input_file_lines)
    last_progress = 0
    for line_num, line in enumerate(input_file_lines, 1):
        # Print progress every 10%
        if total_lines > 0:
            progress = (line_num * 100) // total_lines
            if progress >= last_progress + 10:
                last_progress = (progress // 10) * 10
                print(f"Progress: {last_progress}%")

        line = line.strip(args.csv_delimiter).strip()
        ip = None

        if is_csv:
            ip = line.strip().split(args.csv_delimiter)[args.csv_ip_field]
        else:
            ip = line.strip()

        # Enrich output with info from IP-DB:
        if args.use_ip_db:
            if is_valid_public_ip(ip):
                res = ip_db.enterprise(ip)
                ip_db_values = [
                    str(res.country.names["en"]).replace("None", ""),
                    str(res.city.names["en"]).replace("None", ""),
                    str(res.traits.connection_type).replace("None", ""),
                    str(res.traits.autonomous_system_organization).replace("None", ""),
                    str(res.traits.autonomous_system_number).replace("None", ""),
                    str(res.traits.isp).replace("None", ""),
                    # str(res.traits.organization).replace("None", ""),
                    str(res.traits.domain).replace("None", "")
                ]
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(ip_db_values)

                # Store lon, lat, country, city for later:
                if args.generate_kml:
                    country = str(res.country.names["en"]).replace("None", "")
                    city = str(res.city.names["en"]).replace("None", "")
                    location_list.append((res.location.longitude, res.location.latitude, country, city))
            else:
                print(f"Skipping invalid or non-public IP: '{ip}'")

        # Lookup IP in DNSBL blacklists:
        if args.use_dnsbl:
            if is_valid_public_ip(ip):
                dnsbl_count = lookup_dnsbl(ip)
                line = line + args.csv_delimiter_output + str(dnsbl_count)
            else:
                line = line + args.csv_delimiter_output + ""

        # Lookup IP in ipinfo.io:
        valid_hostname = None  # used later from dnsdumpster
        if args.use_ipinfo:
            if is_valid_public_ip(ip):
                hostname = call_ipinfo_api(ip)
                if hostname:
                    valid_hostname = hostname
                    line = line + args.csv_delimiter_output + args.csv_delimiter_output.join([hostname])
                else:
                    line = line + args.csv_delimiter_output + args.csv_delimiter_output.join([""])
            else:
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join([""])

        # Enrich output with info from DNSDumpster (requires a hostname from ip-info):
        if args.use_dnsdumpster and valid_hostname:
            dnsdumpster_result = call_dnsdumpster_api(valid_hostname, args.dnsdumpster_api)
            if dnsdumpster_result:
                banners = set()
                for a in dnsdumpster_result.get('a', []):
                    for ips in a.get('ips', []):
                        for key, val in ips.get('banners', {}).items():
                            if key == 'ip':
                                continue
                            banners.add(key)

                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(list(banners))
            else:
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join([""])

        # Lookup IP in AbuseIPDB:
        if args.use_abuseipdb:
            if is_valid_public_ip(ip):
                abuseipdb_result = call_abuseipdb_api(ip, args.abuseipdb_api, args.csv_delimiter_output)
                if abuseipdb_result:
                    line = line + args.csv_delimiter_output + abuseipdb_result
                else:
                    line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(["", "", ""])
            else:
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(["", "", ""])

        # Lookup IP in proxycheck.io:
        if args.use_proxycheck:
            if is_valid_public_ip(ip):
                proxycheck_result = call_proxycheck_api(ip, args.proxycheck_api, args.csv_delimiter_output)
                if proxycheck_result:
                    line = line + args.csv_delimiter_output + proxycheck_result
                else:
                    line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(["", "", "", "", "", ""])
            else:
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(["", "", "", "", "", ""])

        outfile.write(line + "\n")

    outfile.close()
    print(f"Output written to: {output_filename}")

    # Generate KML file for Google Earth
    if args.generate_kml and location_list:
        kml_filename = input_filename.with_suffix(".kml")
        generate_kml_file(kml_filename, location_list)

    sys.exit(0)

def call_dnsdumpster_api(hostname, api_key):
    """Call DNSDumpster API for domain information."""
    url = f"https://api.dnsdumpster.com/domain/{hostname}"
    req = urllib.request.Request(url)
    req.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        print(f"DNSDumpster API error for {hostname}: {e}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"Error connecting to DNSDumpster API: {e}", file=sys.stderr)
        return None

def call_ipinfo_api(ip):
    """Call ipinfo.io API for IP information."""
    url = f"https://ipinfo.io/{ip}/json"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            hostname = data.get("hostname", "")
            return hostname
    except urllib.error.HTTPError as e:
        print(f"ipinfo.io API error for {ip}: {e}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"Error connecting to ipinfo.io API: {e}", file=sys.stderr)
        return None

def call_abuseipdb_api(ip, api_key, delimiter):
    """Call AbuseIPDB API for IP abuse information."""
    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    })
    url = f"https://api.abuseipdb.com/api/v2/check?{params}"
    req = urllib.request.Request(url)
    req.add_header("Key", api_key)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            result = data.get("data", {})
            score = str(result.get("abuseConfidenceScore", ""))
            reports = str(result.get("totalReports", ""))
            country = result.get("countryCode", "")
            return delimiter.join([score, reports, country])
    except urllib.error.HTTPError as e:
        print(f"AbuseIPDB API error for {ip}: {e}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"Error connecting to AbuseIPDB API: {e}", file=sys.stderr)
        return None

def call_proxycheck_api(ip, api_key, delimiter):
    """Call proxycheck.io API for proxy/VPN detection."""
    params = urllib.parse.urlencode({
        "key": api_key,
        "vpn": 1,
        "asn": 1,
        "risk": 1
    })
    url = f"https://proxycheck.io/v2/{ip}?{params}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            if data.get("status") != "ok":
                print(f"proxycheck.io API error for {ip}: {data.get('message', 'Unknown error')}", file=sys.stderr)
                return None
            result = data.get(ip, {})
            proxy = result.get("proxy", "")
            proxy_type = result.get("type", "")
            risk = str(result.get("risk", ""))
            country = result.get("country", "")
            asn = result.get("asn", "")
            provider = result.get("provider", "")
            return delimiter.join([str(proxy), proxy_type, risk, country, asn, provider])
    except urllib.error.HTTPError as e:
        print(f"proxycheck.io API error for {ip}: {e}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"Error connecting to proxycheck.io API: {e}", file=sys.stderr)
        return None

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

def lookup_dnsbl(ip):
    """Lookup IP in DNSBL blacklists and return number of occurrences."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    count = 0
    for dnsbl in DNSBL_SERVERS:
        query = f"{reversed_ip}.{dnsbl}"
        try:
            socket.gethostbyname(query)
            count += 1
        except socket.gaierror:
            pass
    return count

def generate_kml_file(kml_filename, location_list):
    """Generate a KML file for Google Earth from location list."""
    try:
        kml_file = open(kml_filename, "w")
    except PermissionError:
        print(f"Error: Permission denied to create KML file: {kml_filename}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error: Could not create KML file: {kml_filename} - {e}", file=sys.stderr)
        sys.exit(1)

    kml_file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    kml_file.write('<kml xmlns="http://www.opengis.net/kml/2.2">\n')
    kml_file.write('  <Document>\n')
    kml_file.write('    <name>IP Locations</name>\n')

    for i, (lon, lat, country, city) in enumerate(location_list):
        if lon is not None and lat is not None:
            name = f"{city}, {country}" if city and country else city or country or f"Location {i + 1}"
            kml_file.write('    <Placemark>\n')
            kml_file.write(f'      <name>{name}</name>\n')
            kml_file.write('      <Point>\n')
            kml_file.write(f'        <coordinates>{lon},{lat},0</coordinates>\n')
            kml_file.write('      </Point>\n')
            kml_file.write('    </Placemark>\n')
    kml_file.write('  </Document>\n')
    kml_file.write('</kml>\n')
    kml_file.close()
    print(f"KML file written to: {kml_filename} You can import this into Google Earth.")


def ask_user_about_ip_field(csv_header, delimiter):
    """Ask user to select which CSV field contains the IP address."""
    fields = csv_header.strip().split(delimiter)
    print("CSV fields found, enter index number that represent IP-adress field:")
    for i, field in enumerate(fields):
        print(f"  {i}: {field}")
    while True:
        try:
            choice = input("Enter the index of the IP address field: ")
            index = int(choice)
            if 0 <= index < len(fields):
                return index
            print(f"Invalid index. Please enter a number between 0 and {len(fields) - 1}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def download_ip_db(args):
    if args.ip_db_key:
        IP_DB_KEY_FILE.write_text(args.ip_db_key)
        print("Storing IP-DB key to cache...")
    elif IP_DB_KEY_FILE.exists():
        args.ip_db_key = IP_DB_KEY_FILE.read_text().strip()
        print("Retreiving IP-DB key from cache...")

    if args.use_ip_db and not args.ip_db_key:
        print("Error: No IP-DB key provided. Re-run with --ip-db-key", file=sys.stderr)
        sys.exit(1)

    print("IP-DB database not found, downloading from db-ip.com...")
    info_url = f"https://db-ip.com/account/{args.ip_db_key}/db/ip-to-location-isp/"
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
        IP_DB_FILE.write_bytes(decompressed_data)
        print(f"IP database saved to {IP_DB_FILE}")
    except urllib.error.HTTPError as e:
        print(f"Error downloading IP database: {e}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Error connecting to db-ip.com: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyError:
        print("Error: Invalid response from db-ip.com", file=sys.stderr)
        sys.exit(1)
    return

def is_valid_public_ip(ip_string):
    """Check if the string is a valid public IP address."""
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_global
    except ValueError:
        return False

def is_private_ip(ip_string):
    """Check if the IP address is in a private subnet."""
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_private
    except ValueError:
        return False


if __name__ == "__main__":
    main()
