"""VULNERABLE fixture: untrusted filename reaches a filesystem path sink."""
import os

from flask import request


def read_uploaded():
    name = request.args.get("name")
    with open(os.path.join("/var/data", name)) as handle:
        return handle.read()


def delete_anything():
    target = request.form["path"]
    os.remove(target)
