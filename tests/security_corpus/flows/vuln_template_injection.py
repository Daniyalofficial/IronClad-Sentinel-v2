"""VULNERABLE fixture: template source is built from user input."""
from flask import request
from jinja2 import Template


def render_custom():
    return Template(request.args.get("template", "")).render()
