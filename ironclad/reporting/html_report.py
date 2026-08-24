"""HTML report renderer -- wraps the Jinja2 template with the finding data."""
from __future__ import annotations

import datetime
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ironclad.core.models import ScanResult

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def render_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    return template.render(
        result=result,
        findings=result.sorted_findings(),
        severity_counts=result.severity_counts(),
        generated_at_str=datetime.datetime.fromtimestamp(result.generated_at).strftime("%Y-%m-%d %H:%M:%S"),
    )
