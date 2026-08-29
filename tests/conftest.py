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


# The API test suite exercises functionality, not throttling: it logs in many
# times from a single client address. Rate limits are raised here so unrelated
# tests are not affected, and tests/test_ratelimit.py sets tight limits
# explicitly to verify the limiter itself. Neither weakens any assertion --
# it separates the two concerns.
os.environ.setdefault("IRONCLAD_RATELIMIT_LOGIN", "100000:60")
os.environ.setdefault("IRONCLAD_RATELIMIT_LOGIN_ACCOUNT", "100000:300")
os.environ.setdefault("IRONCLAD_RATELIMIT_TOKEN_CREATE", "100000:300")
os.environ.setdefault("IRONCLAD_RATELIMIT_PASSWORD_CHANGE", "100000:300")


def pytest_configure(config):
    if not os.path.isdir(DEMO_APP_DIR) or not os.listdir(DEMO_APP_DIR):
        sys.path.insert(0, os.path.join(_REPO_ROOT, "demo"))
        from generate_vulnerable_app import generate
        generate(DEMO_APP_DIR)
