"""VULNERABLE fixture: redirect target comes straight from the query string."""
from flask import redirect, request


def after_login():
    return redirect(request.args.get("next"))
