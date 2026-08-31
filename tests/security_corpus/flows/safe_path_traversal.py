"""SAFE fixture: filename is canonicalised and the resolved path is confined."""
import os

from flask import request
from werkzeug.utils import secure_filename

DATA_ROOT = "/var/data"


def read_uploaded():
    name = secure_filename(request.args.get("name", ""))
    candidate = os.path.realpath(os.path.join(DATA_ROOT, name))
    if not candidate.startswith(DATA_ROOT + os.sep):
        raise ValueError("path escapes the data root")
    with open(candidate) as handle:
        return handle.read()


def read_static():
    with open(os.path.join(DATA_ROOT, "index.html")) as handle:
        return handle.read()
