"""HTML report renderer -- wraps the Jinja2 template with the finding data."""
from __future__ import annotations

import datetime
import os

from jinja2 import Environment, FileSystemLoader

from ironclad.core.models import ScanResult

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def render_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        # Unconditional, not select_autoescape(["html"]): that helper keys off
        # the template's own extension, and this file is `report.html.j2`,
        # whose extension is `j2` -- so it resolved to autoescape=False and
        # every interpolated value was emitted raw. Finding titles,
        # descriptions and code snippets all come from the scanned
        # repository, so a repo containing `<script>` in a source line or an
        # `<img onerror=...>` filename produced a report that executed
        # attacker script in the browser of whoever opened it. This renderer
        # only ever emits HTML, so escaping is always right.
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    return template.render(
        result=result,
        findings=result.sorted_findings(),
        severity_counts=result.severity_counts(),
        generated_at_str=datetime.datetime.fromtimestamp(result.generated_at).strftime("%Y-%m-%d %H:%M:%S"),
    )
