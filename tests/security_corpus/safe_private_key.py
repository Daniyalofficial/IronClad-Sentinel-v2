"""SAFE fixture: the key material is loaded from the environment, not committed."""

import os

SIGNING_KEY = os.environ["APP_SIGNING_KEY"]
