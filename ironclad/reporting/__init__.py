"""
Multi-format report writer. Every format is generated purely from the
in-memory `ScanResult` -- no network calls, no external services.

Supported formats: json, sarif, html, markdown, junit, cyclonedx.
"""
from __future__ import annotations

import os
from typing import Dict, List

from ironclad.core.models import ScanResult
from ironclad.reporting.cyclonedx_report import render_cyclonedx
from ironclad.reporting.html_report import render_html
from ironclad.reporting.junit_report import render_junit
from ironclad.reporting.markdown_report import render_markdown
from ironclad.reporting.sarif import render_sarif

RENDERERS = {
    "json": lambda result: result.to_json(),
    "sarif": render_sarif,
    "html": render_html,
    "markdown": render_markdown,
    "junit": render_junit,
    "cyclonedx": render_cyclonedx,
}

EXTENSIONS = {
    "json": "json",
    "sarif": "sarif.json",
    "html": "html",
    "markdown": "md",
    "junit": "junit.xml",
    "cyclonedx": "cdx.json",
}


def write_reports(result: ScanResult, formats: List[str], output_dir: str) -> Dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    written = {}
    for fmt in formats:
        renderer = RENDERERS.get(fmt)
        if not renderer:
            continue
        content = renderer(result)
        ext = EXTENSIONS[fmt]
        path = os.path.join(output_dir, f"ironclad-report.{ext}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written[fmt] = path
    return written
