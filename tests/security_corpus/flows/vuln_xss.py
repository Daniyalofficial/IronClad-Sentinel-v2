"""VULNERABLE fixture: untrusted data is concatenated into an HTML response."""
from flask import request
from markupsafe import Markup


def search_page():
    return Markup("<h1>Results for " + request.args.get("q") + "</h1>")
