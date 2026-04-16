"""Shared utilities for enrich-ip."""

import ipaddress
import re

# IPv4: strict dotted-decimal
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IPv6: broad pattern (at least two colon-separated hex groups), validated below
_IPV6_RE = re.compile(
    r'(?<![:\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![:\w])'
)


def parse_excel_to_csv(data_bytes, delimiter=";"):
    """If data_bytes is an .xlsx Excel file, return it rendered as CSV text.

    Returns None if the data is not an Excel file or cannot be parsed.
    The first sheet is used. Cell values are stringified; any occurrences
    of the delimiter or newlines inside cells are replaced with spaces so
    the resulting CSV text can be parsed with a simple split.
    """
    if not data_bytes.startswith(b"PK\x03\x04"):
        return None
    try:
        import io
        import openpyxl
    except ImportError:
        return None
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data_bytes), read_only=True, data_only=True)
    except Exception:
        return None
    try:
        ws = wb.active
        if ws is None:
            return None
        lines = []
        for row in ws.iter_rows(values_only=True):
            fields = []
            for cell in row:
                if cell is None:
                    fields.append("")
                else:
                    s = str(cell).replace(delimiter, " ").replace("\n", " ").replace("\r", " ").strip()
                    fields.append(s)
            # Skip fully empty rows
            if any(f for f in fields):
                lines.append(delimiter.join(fields))
        if not lines:
            return None
        return "\n".join(lines) + "\n"
    finally:
        wb.close()


def detect_csv(content):
    """Detect if content is a CSV file.

    Returns (delimiter, header_line, data_lines) if it looks like CSV,
    or None if not.
    """
    lines = [l for l in content.splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    first = lines[0]
    for delim in [";", ","]:
        parts = first.split(delim)
        if len(parts) >= 2:
            return delim, lines[0], lines[1:]
    return None


def detect_ip_column(data_lines, delimiter):
    """Return the index of the column most likely containing IP addresses.

    A cell counts as containing an IP if at least one IPv4/IPv6 address can be
    extracted from its text, so cells with surrounding text (e.g. "src=8.8.8.8")
    still match. Scans up to the first 20 data rows. Returns None if nothing matches.
    """
    col_scores: dict[int, int] = {}
    for line in data_lines[:20]:
        fields = line.split(delimiter)
        for i, field in enumerate(fields):
            if extract_ips_from_text(field):
                col_scores[i] = col_scores.get(i, 0) + 1
    if not col_scores:
        return None
    return max(col_scores, key=lambda k: col_scores[k])


def extract_ips_from_text(text):
    """Extract all unique IPv4 and IPv6 addresses from arbitrary text.

    Returns a list of normalised IP strings in document order.
    """
    candidates = []
    for m in _IPV4_RE.finditer(text):
        candidates.append((m.start(), m.group()))
    for m in _IPV6_RE.finditer(text):
        candidates.append((m.start(), m.group()))
    candidates.sort(key=lambda x: x[0])

    seen = set()
    result = []
    for _, raw in candidates:
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


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
