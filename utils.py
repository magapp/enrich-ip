"""Shared utilities for enrich-ip."""

import ipaddress


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


def print_ascii_table(rows):
    """Print rows as an ASCII table."""
    if not rows:
        return

    # Calculate column widths
    num_cols = max(len(row) for row in rows)
    col_widths = [0] * num_cols
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Build separator line
    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

    # Print table
    for row_idx, row in enumerate(rows):
        # Pad row if necessary
        padded_row = list(row) + [""] * (num_cols - len(row))
        line = "|" + "|".join(f" {str(cell).ljust(col_widths[i])} " for i, cell in enumerate(padded_row)) + "|"
        if row_idx == 0:
            print(separator)
        print(line)
        if row_idx == 0:
            print(separator)
    print(separator)


def generate_kml_file(kml_filename, location_list):
    """Generate a KML file for Google Earth from location list."""
    import sys

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
