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

    # CSV settings
    args.csv_delimiter = form.get("csv_delimiter", ";") or ";"
    args.csv_delimiter_output = form.get("csv_delimiter_output", ";") or ";"
    csv_ip_field = form.get("csv_ip_field", "")
    args.csv_ip_field = int(csv_ip_field) if csv_ip_field.strip() else None

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


def process_file(input_lines, args, progress_callback=None):
    """Process input lines through enabled providers, return (output_lines, error).

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

    # Detect CSV vs plain text
    is_csv = False
    csv_input_header = "IP"

    first_line = input_lines[0]
    is_csv = args.csv_delimiter in first_line

    if is_csv:
        csv_input_header = first_line
        data_lines = input_lines[1:]
        if args.csv_ip_field is None:
            args.csv_ip_field = 0  # Default to first column in web mode
    else:
        data_lines = input_lines

    # Build output header
    csv_output_header = csv_input_header.replace(args.csv_delimiter, args.csv_delimiter_output).strip()

    for provider in enabled_providers:
        provider_headers = provider.get_headers()
        if provider_headers:
            csv_output_header = csv_output_header + args.csv_delimiter_output + args.csv_delimiter_output.join(provider_headers)

    output_lines = [csv_output_header]

    # Process each line
    total = len(data_lines)
    for i, line in enumerate(data_lines):
        line = line.strip(args.csv_delimiter).strip()
        if not line:
            continue

        report("progress", {"current": i + 1, "total": total})

        if is_csv:
            try:
                ip = line.strip().split(args.csv_delimiter)[args.csv_ip_field]
            except (IndexError, TypeError):
                ip = ""
        else:
            ip = line.strip()

        context = {}

        for provider in enabled_providers:
            values = provider.enrich(ip, context)
            if values is not None:
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(values)
            else:
                empty_values = [""] * len(provider.get_headers())
                line = line + args.csv_delimiter_output + args.csv_delimiter_output.join(empty_values)

        output_lines.append(line)

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
        content = uploaded.read().decode("utf-8", errors="replace")
    except Exception as e:
        return Response(
            _ndjson_line({"event": "error", "message": f"Could not read file: {e}"}),
            content_type="application/x-ndjson",
        )

    input_lines = [l for l in content.splitlines() if l.strip()]
    if not input_lines:
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
            input_lines, args, progress_callback=on_progress
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

            delimiter = args.csv_delimiter_output
            headers = output_lines[0].split(delimiter)
            rows = [line.split(delimiter) for line in output_lines[1:]]

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
