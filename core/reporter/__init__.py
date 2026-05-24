"""Reporter package — console UI and file exports.

Public API kept flat so callers can keep using
``from core.reporter import console, print_results, export_json, export_html``.
"""

from core.reporter.console_ui import (
    console,
    print_banner,
    print_breach_notice,
    print_progress,
    print_results,
    print_scan_start,
)
from core.reporter.csv_export import (
    export_csv,
    export_xlsx,
    xlsx_available,
)
from core.reporter.html_export import export_html
from core.reporter.json_export import export_json
from core.reporter.misp_export import build_misp_event, export_misp
from core.reporter.obsidian_export import export_obsidian
from core.reporter.pdf_export import export_pdf, is_available as pdf_available
from core.reporter.stix_export import build_stix_bundle, export_stix

__all__ = [
    "build_misp_event",
    "build_stix_bundle",
    "console",
    "export_csv",
    "export_html",
    "export_json",
    "export_misp",
    "export_obsidian",
    "export_pdf",
    "export_stix",
    "export_xlsx",
    "pdf_available",
    "print_banner",
    "print_breach_notice",
    "print_progress",
    "print_results",
    "print_scan_start",
    "xlsx_available",
]
