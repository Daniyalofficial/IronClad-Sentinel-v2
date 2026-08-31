"""SAFE fixture: only server-generated internal URLs are used."""
from flask import redirect, url_for


def after_login():
    return redirect(url_for("dashboard"))
