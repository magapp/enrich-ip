"""Flask web application for enrich-ip."""

import json
import os
import queue
import tempfile
import threading
import types
import uuid
from pathlib import Path

from flask import Flask, Blueprint, Response, redirect, render_template, request, send_from_directory, stream_with_context, url_for

from providers import create_providers, get_provider_classes
from utils import detect_csv, detect_ip_column, extract_ips_from_text, parse_excel_to_csv

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

bp = Blueprint("enrich_ip", __name__, url_prefix="/enrich-ip")

TEMP_DIR = os.path.join(tempfile.gettempdir(), "enrich-ip")
os.makedirs(TEMP_DIR, exist_ok=True)


def get_cached_keys():
    """Return a set of provider names that have a cached API key file."""
    cached = set()
    for cls in get_provider_classes():
        if cls.key_cache_file:
            path = Path.home() / cls.key_cache_file
            if path.is_file():
                cached.add(cls.name)
    return cached


def build_args_from_form(form):
    """Convert Flask form data into a namespace matching argparse output."""
    args = types.SimpleNamespace()

    # Not used in web mode but providers may check these
    args.generate_kml = False
    args.ascii_output = False

    # Provider flags
    args.use_ip_db = "use_ip_db" in form
    args.ip_db_key = form.get("ip_db_key", "").strip() or None

    args.use_dnsbl = "use_dnsbl" in form

    args.use_ipinfo = "use_ipinfo" in form

    args.use_dnsdumpster = "use_dnsdumpster" in form
    args.dnsdumpster_api = form.get("dnsdumpster_api", "").strip() or None

    args.use_abuseipdb = "use_abuseipdb" in form
    args.abuseipdb_api = form.get("abuseipdb_api", "").strip() or None

    args.use_proxycheck = "use_proxycheck" in form
    args.proxycheck_api = form.get("proxycheck_api", "").strip() or None

    return args


DELIMITER = ";"


def process_file(content, args, progress_callback=None):
    """Extract IPs from arbitrary content, enrich them, return (output_lines, error).

    output_lines is a list of strings (including the header line).
    error is a string message or None.
    progress_callback, if provided, is called as callback(event, data_dict).
    """
    def report(event, data):
        if progress_callback:
            progress_callback(event, data if isinstance(data, dict) else {"message": data})

    # Pre-validate DNSDumpster dependency on IPInfo
    if args.use_dnsdumpster and not args.use_ipinfo:
        return None, "DNSDumpster requires IPInfo to be enabled."

    # Detect whether this is a CSV file with an identifiable IP column.
    # If so, we preserve the original rows and append enriched columns.
    report("status", "Analysing input file...")
    csv_info = detect_csv(content)
    csv_mode = False
    if csv_info is not None:
        in_delim, header_line, data_lines = csv_info
        ip_col = detect_ip_column(data_lines, in_delim)
        if ip_col is not None:
            csv_mode = True

    if not csv_mode:
        # Fall back to extracting IPs from arbitrary text
        ips = extract_ips_from_text(content)
        if not ips:
            return None, "No IP addresses found in the uploaded file."

    # Create and initialize providers
    providers = create_providers()
    enabled_providers = []

    report("status", "Initializing providers...")

    for provider in providers:
        provider.progress_callback = progress_callback
        try:
            if not provider.initialize(args):
                return None, f"Failed to initialize provider: {provider.name}"
        except SystemExit:
            return None, f"Provider {provider.name} failed to initialize (missing API key or dependency)."
        if provider.enabled:
            enabled_providers.append(provider)

    if not enabled_providers:
        return None, "No providers selected."

    provider_headers = []
    for provider in enabled_providers:
        provider_headers.extend(provider.get_headers())

    if csv_mode:
        # Preserve the original CSV header and rows; append enriched columns.
        # Rejoin fields with DELIMITER in the output.
        input_header_fields = [f.strip() for f in header_line.split(in_delim)]
        output_lines = [DELIMITER.join(input_header_fields + provider_headers)]

        total = len(data_lines)
        for i, line in enumerate(data_lines):
            report("progress", {"current": i + 1, "total": total})
            fields = [f.strip() for f in line.split(in_delim)]
            ip = ""
            for field in fields:
                found = extract_ips_from_text(field)
                if found:
                    ip = found[0]
                    break
            context = {}
            enriched = []
            for provider in enabled_providers:
                values = provider.enrich(ip, context)
                if values is not None:
                    enriched.extend(values)
                else:
                    enriched.extend([""] * len(provider.get_headers()))
            output_lines.append(DELIMITER.join(fields + enriched))
    else:
        # Non-CSV: build a fresh CSV keyed on the extracted IPs.
        output_lines = [DELIMITER.join(["IP"] + provider_headers)]
        total = len(ips)
        for i, ip in enumerate(ips):
            report("progress", {"current": i + 1, "total": total})
            context = {}
            row = [ip]
            for provider in enabled_providers:
                values = provider.enrich(ip, context)
                if values is not None:
                    row.extend(values)
                else:
                    row.extend([""] * len(provider.get_headers()))
            output_lines.append(DELIMITER.join(row))

    return output_lines, None


def _ndjson_line(obj):
    """Encode a dict as an NDJSON line."""
    return json.dumps(obj, ensure_ascii=False) + "\n"


@app.route("/")
def root():
    return redirect(url_for("enrich_ip.index"))


@bp.route("/")
def index():
    return render_template("index.html", cached_keys=get_cached_keys())


@bp.route("/enrich", methods=["POST"])
def enrich():
    uploaded = request.files.get("input_file")
    if not uploaded or uploaded.filename == "":
        return Response(
            _ndjson_line({"event": "error", "message": "No file selected."}),
            content_type="application/x-ndjson",
        )

    try:
        raw_bytes = uploaded.read()
    except Exception as e:
        return Response(
            _ndjson_line({"event": "error", "message": f"Could not read file: {e}"}),
            content_type="application/x-ndjson",
        )

    if not raw_bytes:
        return Response(
            _ndjson_line({"event": "error", "message": "Uploaded file is empty."}),
            content_type="application/x-ndjson",
        )

    # If the file is an Excel workbook, parse it to CSV text; otherwise decode as UTF-8
    content = parse_excel_to_csv(raw_bytes)
    if content is None:
        content = raw_bytes.decode("utf-8", errors="replace")

    if not content.strip():
        return Response(
            _ndjson_line({"event": "error", "message": "Uploaded file is empty."}),
            content_type="application/x-ndjson",
        )

    args = build_args_from_form(request.form)

    progress_queue = queue.Queue()
    result_holder = [None, None]  # (output_lines, error)

    def on_progress(event, data):
        if isinstance(data, dict):
            progress_queue.put({"event": event, **data})
        else:
            progress_queue.put({"event": event, "message": data})

    def worker():
        result_holder[0], result_holder[1] = process_file(
            content, args, progress_callback=on_progress
        )
        progress_queue.put(None)  # sentinel

    def generate():
        t = threading.Thread(target=worker)
        t.start()

        while True:
            msg = progress_queue.get()
            if msg is None:
                break
            yield _ndjson_line(msg)

        t.join()

        output_lines, error = result_holder
        if error:
            yield _ndjson_line({"event": "error", "message": error})
        else:
            # Write output CSV
            result_name = f"{uuid.uuid4().hex}.csv"
            result_path = os.path.join(TEMP_DIR, result_name)
            with open(result_path, "w") as f:
                f.write("\n".join(output_lines) + "\n")

            headers = output_lines[0].split(DELIMITER)
            rows = [line.split(DELIMITER) for line in output_lines[1:]]

            yield _ndjson_line({
                "event": "done",
                "filename": result_name,
                "headers": headers,
                "rows": rows,
            })

    return Response(
        stream_with_context(generate()),
        content_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
    )


@bp.route("/download/<filename>")
def download(filename):
    return send_from_directory(TEMP_DIR, filename, as_attachment=True, download_name="enriched.csv")


app.register_blueprint(bp)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)
