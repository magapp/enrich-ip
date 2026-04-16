#!/home/magnus/enrich-ip/env/bin/python3
"""Enrich IP addresses with additional information."""

import argparse
import sys
from pathlib import Path

from providers import create_providers, get_provider_classes
from utils import detect_csv, detect_ip_column, extract_ips_from_text, generate_kml_file, parse_excel_to_csv, print_ascii_table


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract all IPv4/IPv6 addresses from any file and enrich them. "
                    "Additional services can be used to enrich the information, such as IP-DB, AbuseIPDB etc.")
    parser.add_argument("--input-file", type=argparse.FileType("rb"), required=True, help="Path to any file containing IP addresses (text, CSV, or Excel .xlsx)")
    parser.add_argument("--delimiter-output", type=str, default=";", help="Delimiter for output csv file, default ';'")
    parser.add_argument("--generate-kml", action="store_true", default=False, help="Generate KML file with coordinates that can be imported to Google Earth")
    parser.add_argument("--ascii-output", action="store_true", default=False, help="Output as ASCII table to stdout instead of CSV file")

    # Let each provider add its arguments
    for provider_class in get_provider_classes():
        provider_class.add_arguments(parser)

    return parser.parse_args()


def main():
    location_list = []
    args = parse_args()

    # Validate KML dependency
    if args.generate_kml and not args.use_ip_db:
        print("Error: --generate-kml requires --use-ip-db", file=sys.stderr)
        sys.exit(1)

    # Read the input file as bytes, try Excel parse, then decide CSV vs raw mode
    raw_bytes = args.input_file.read()
    content = parse_excel_to_csv(raw_bytes)
    if content is not None:
        print("Excel workbook detected; parsed to CSV.")
    else:
        content = raw_bytes.decode("utf-8", errors="replace")
    csv_info = detect_csv(content)
    csv_mode = False
    if csv_info is not None:
        in_delim, header_line, data_lines = csv_info
        ip_col = detect_ip_column(data_lines, in_delim)
        if ip_col is not None:
            csv_mode = True

    if csv_mode:
        print(f"CSV detected (delimiter '{in_delim}', IP column index {ip_col}, {len(data_lines)} data rows).")
    else:
        ips = extract_ips_from_text(content)
        if not ips:
            print("Error: No IP addresses found in the input file.", file=sys.stderr)
            sys.exit(1)
        print(f"Found {len(ips)} unique IP address(es).")

    # Create and initialize providers
    providers = create_providers()
    enabled_providers = []

    for provider in providers:
        if not provider.initialize(args):
            sys.exit(1)
        if provider.enabled:
            enabled_providers.append(provider)

    delim = args.delimiter_output

    # Build output filename and open output file
    input_filename = Path(args.input_file.name)
    outfile = None
    output_filename = None
    output_rows = []

    if not args.ascii_output:
        output_filename = input_filename.with_suffix(".out.csv")
        try:
            outfile = open(output_filename, "w")
        except PermissionError:
            print(f"Error: Permission denied to create output file: {output_filename}", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"Error: Could not create output file: {output_filename} - {e}", file=sys.stderr)
            sys.exit(1)

    # Collect provider header fields
    provider_headers = []
    for provider in enabled_providers:
        provider_headers.extend(provider.get_headers())

    # Build header
    if csv_mode:
        input_header_fields = [f.strip() for f in header_line.split(in_delim)]
        header_parts = input_header_fields + provider_headers
    else:
        header_parts = ["IP"] + provider_headers

    if args.ascii_output:
        output_rows.append(header_parts)
    else:
        outfile.write(delim.join(header_parts) + "\n")

    # Process rows
    if csv_mode:
        iterable = data_lines
    else:
        iterable = ips

    total = len(iterable)
    last_progress = 0
    for i, item in enumerate(iterable, 1):
        progress = (i * 100) // total
        if progress >= last_progress + 10:
            last_progress = (progress // 10) * 10
            print(f"Progress: {last_progress}%")

        if csv_mode:
            fields = [f.strip() for f in item.split(in_delim)]
            ip = ""
            for field in fields:
                found = extract_ips_from_text(field)
                if found:
                    ip = found[0]
                    break
            row = list(fields)
        else:
            ip = item
            row = [ip]

        context = {}
        for provider in enabled_providers:
            values = provider.enrich(ip, context)
            if values is not None:
                row.extend(values)
            else:
                row.extend([""] * len(provider.get_headers()))

        if 'location' in context:
            location_list.append(context['location'])

        if args.ascii_output:
            output_rows.append(row)
        else:
            outfile.write(delim.join(row) + "\n")

    if args.ascii_output:
        print_ascii_table(output_rows)
    else:
        outfile.close()
        print(f"Output written to: {output_filename}")

    if args.generate_kml and location_list:
        kml_filename = input_filename.with_suffix(".kml")
        generate_kml_file(kml_filename, location_list)

    sys.exit(0)


if __name__ == "__main__":
    main()
