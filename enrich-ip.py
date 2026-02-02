#!/home/magnus/enrich-ip/env/bin/python3
"""Enrich IP addresses with additional information."""

import argparse
import sys
from pathlib import Path

from providers import create_providers, get_provider_classes
from utils import ask_user_about_ip_field, generate_kml_file, print_ascii_table


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Enrich a list or CSV-file with IP-addresses with additional information. "
                    "The list can be a plain text file with one IP on each line or a CSV-file "
                    "where one field contains IP-adress. Additional services can be used to "
                    "enrich the information, such as IP-DB, AbuseIP etc.")
    parser.add_argument("--input-file", type=argparse.FileType("r"), required=True, help="Path to input txt or csv file containing IP addresses")
    parser.add_argument("--csv-delimiter", type=str, default=";", help="Delimiter for input file (if csv), default ';'")
    parser.add_argument("--csv-ip-field", type=int, help="Column index for IP address in CSV file")
    parser.add_argument("--csv-delimiter-output", type=str, default=";", help="Delimiter for output csv file, default ';'")
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

    # Create and initialize providers
    providers = create_providers()
    enabled_providers = []

    for provider in providers:
        if not provider.initialize(args):
            sys.exit(1)
        if provider.enabled:
            enabled_providers.append(provider)

    # Used if file is csv
    is_csv = False
    csv_input_header = "IP"

    first_line = args.input_file.readline()
    is_csv = args.csv_delimiter in first_line

    if is_csv:
        csv_input_header = first_line
        input_file_lines = args.input_file.readlines()
        if args.csv_ip_field is None:
            args.csv_ip_field = ask_user_about_ip_field(csv_input_header.strip().strip(args.csv_delimiter), args.csv_delimiter)
    else:
        input_file_lines = [first_line] + args.input_file.readlines()

    # Build output filename based on input file and create new output file
    input_filename = Path(args.input_file.name)
    outfile = None
    output_filename = None
    output_rows = []  # Used for ASCII output

    if not args.ascii_output:
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

    # Collect headers from enabled providers
    for provider in enabled_providers:
        provider_headers = provider.get_headers()
        if provider_headers:
            csv_output_header = csv_output_header + args.csv_delimiter_output + args.csv_delimiter_output.join(provider_headers)

    # Write header to output file or store for ASCII output
    if csv_output_header:
        if args.ascii_output:
            output_rows.append(csv_output_header.split(args.csv_delimiter_output))
        else:
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

        # Context dict for passing data between providers
        context = {}

        # Enrich with each enabled provider
        for provider in enabled_providers:
            values = provider.enrich(ip, context)
            if values is not None:
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(values)
            else:
                # Provider returned None (e.g., invalid IP), add empty values
                empty_values = [""] * len(provider.get_headers())
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(empty_values)

        # Collect location data for KML generation
        if 'location' in context:
            location_list.append(context['location'])

        if args.ascii_output:
            output_rows.append(line.split(args.csv_delimiter_output))
        else:
            outfile.write(line + "\n")

    if args.ascii_output:
        print_ascii_table(output_rows)
    else:
        outfile.close()
        print(f"Output written to: {output_filename}")

    # Generate KML file for Google Earth
    if args.generate_kml and location_list:
        kml_filename = input_filename.with_suffix(".kml")
        generate_kml_file(kml_filename, location_list)

    sys.exit(0)


if __name__ == "__main__":
    main()
