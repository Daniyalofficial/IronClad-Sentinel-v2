"""SAFE fixture: output is escaped before it reaches the response."""
import html

from flask import request


def search_page():
    query = html.escape(request.args.get("q", ""))
    return f"<h1>Results for {query}</h1>"
