"""SAFE fixture: fixed template, user data passed as context."""
from flask import render_template, request


def render_custom():
    return render_template("page.html", greeting=request.args.get("name", "there"))
