"""
Pytest bootstrap: ensures the intentionally-vulnerable demo fixture app
exists on disk before the test suite runs. The demo app is generated at
runtime (see demo/generate_vulnerable_app.py) rather than committed as
static files, so that no secret-shaped string used to validate the
secrets-detection engine ever lives in git history.
"""
import os
import sys

_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _REPO_ROOT)

DEMO_APP_DIR = os.path.join(_REPO_ROOT, "demo", "vulnerable_app")


def pytest_configure(config):
    if not os.path.isdir(DEMO_APP_DIR) or not os.listdir(DEMO_APP_DIR):
        sys.path.insert(0, os.path.join(_REPO_ROOT, "demo"))
        from generate_vulnerable_app import generate
        generate(DEMO_APP_DIR)
