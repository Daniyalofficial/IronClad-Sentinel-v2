"""
Generates the intentionally-vulnerable demo application used to validate
IronClad Sentinel's detection engines end-to-end.

This is a GENERATOR rather than static committed fixture files on
purpose: several planted "secrets" are constructed by string
concatenation at generation time so that no literal secret-shaped string
ever exists in git history / GitHub's secret-scanning push protection,
while the *generated* files on disk still contain a realistic-looking
token for the scanner to detect. Run this once after cloning:

    python demo/generate_vulnerable_app.py

Do not deploy the generated app anywhere real -- every pattern in it is
a deliberately planted security bug used purely for testing detection
rules.
"""
from __future__ import annotations

import os

DEMO_DIR = os.path.join(os.path.dirname(__file__), "vulnerable_app")

# Built via concatenation so this source file itself never contains a
# literal secret-shaped string (keeps it out of secret-scanning tools'
# radar for the *generator*; the *generated* app.py is meant to be
# flagged, which is the whole point of the demo).
_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
_STRIPE_KEY = "sk_" + "live_" + "51H8xYtANDsomeRandomLongerSecretKeyLooksLegit12345"
_DB_PASSWORD = "S3cur3P" + "@ssw0rd!ThisIsHardcoded"
_JS_API_KEY = "AbCdEfGh" + "IjKlMnOp" + "QrStUvWx" + "Yz123456"
_MONGO_PASSWORD = "SuperSecret" + "123"

APP_PY = f'''"""
INTENTIONALLY VULNERABLE demo Flask application, generated only to
exercise and validate IronClad Sentinel's detection engines end-to-end.
Do not deploy this file anywhere real -- every pattern in it is a
deliberately planted security bug.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
DEBUG = True

AWS_ACCESS_KEY_ID = "{_AWS_KEY}"
STRIPE_SECRET_KEY = "{_STRIPE_KEY}"
db_password = "{_DB_PASSWORD}"


def run_backup(filename):
    # Command injection: user-controlled filename flows into shell=True.
    cmd = "tar czf backup.tar.gz " + filename
    subprocess.run(cmd, shell=True)


@app.route("/search")
def search():
    query = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL injection: raw string formatting into execute().
    cursor.execute("SELECT * FROM products WHERE name = '%s'" % query)
    return str(cursor.fetchall())


@app.route("/render")
def render():
    expr = request.args.get("expr")
    # Arbitrary code execution via eval on tainted input.
    result = eval(expr)
    return str(result)


@app.route("/load-config")
def load_config():
    raw = request.args.get("data")
    # Insecure deserialization.
    obj = pickle.loads(raw.encode("latin1"))
    return str(obj)


@app.route("/load-yaml")
def load_yaml():
    raw = request.data
    # Unsafe YAML load (RCE via crafted YAML).
    config = yaml.load(raw, Loader=yaml.Loader)
    return str(config)


def weak_password_hash(password):
    return hashlib.md5(password.encode()).hexdigest()


def call_internal_api():
    # TLS verification disabled.
    return requests.get("https://internal.example.com/status", verify=False)


def is_admin_check(user):
    # Security check implemented with assert -- stripped under python -O.
    assert user.role == "admin"
    return True


def append_item(item, items=[]):
    # Mutable default argument -- shared state leak across calls.
    items.append(item)
    return items


try:
    call_internal_api()
except Exception:
    pass  # broad exception silently swallowed


if __name__ == "__main__":
    host = "0.0.0.0"
    app.run(host=host, port=5000, debug=DEBUG)
'''

REQUIREMENTS_TXT = """django==3.2.3
flask==2.3.1
pyyaml==5.3
requests==2.30.0
paramiko==3.3.0
"""

PACKAGE_JSON = """{
  "name": "vulnerable-frontend-demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.11",
    "express": "4.17.2",
    "jsonwebtoken": "8.5.1",
    "axios": "1.5.0"
  }
}
"""

DOCKERFILE = f"""FROM python:3.9
RUN curl -sSL https://get.example.com/install.sh | bash
ENV API_SECRET={_JS_API_KEY}value12345abcdef
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 22
EXPOSE 5000
CMD ["python", "app.py"]
"""

CONFIG_JS = f'''const apiKey = "{_JS_API_KEY}";
const dbUrl = "mongodb://admin:{_MONGO_PASSWORD}@prod-db.internal:27017/app";

function loadUserPrefs(id) {{
  document.getElementById("prefs").innerHTML = getPrefsHtml(id);
  eval("var x = " + id);
}}

module.exports = {{ apiKey, dbUrl }};
'''

FILES = {
    "app.py": APP_PY,
    "requirements.txt": REQUIREMENTS_TXT,
    "package.json": PACKAGE_JSON,
    "Dockerfile": DOCKERFILE,
    "config.js": CONFIG_JS,
}


def generate(target_dir: str = DEMO_DIR) -> None:
    os.makedirs(target_dir, exist_ok=True)
    for filename, content in FILES.items():
        path = os.path.join(target_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    print(f"[+] Generated {len(FILES)} intentionally-vulnerable demo files in {target_dir}")
    print("    Run: ironclad scan demo/vulnerable_app --format json,html")


if __name__ == "__main__":
    generate()
