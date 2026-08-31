"""Stable, documented CLI exit codes.

Every IronClad command exits with one of these values and nothing else, so
CI pipelines can branch on them without parsing stdout:

    0  success / security gate passed
    1  security gate failed (policy violation, fail-on threshold, risk cap)
    2  usage error (bad flags / arguments -- emitted by click itself)
    3  configuration error (invalid policy, config, or baseline file)
    4  target error (scan path does not exist / is unreadable)
    5  internal error (unexpected exception; a bug report, not user error)
"""
from __future__ import annotations

SUCCESS = 0
GATE_FAILED = 1
USAGE_ERROR = 2
CONFIG_ERROR = 3
TARGET_ERROR = 4
INTERNAL_ERROR = 5

DESCRIPTIONS = {
    SUCCESS: "success / security gate passed",
    GATE_FAILED: "security gate failed (findings exceeded policy or --fail-on)",
    USAGE_ERROR: "usage error (unknown flag or argument)",
    CONFIG_ERROR: "configuration error (invalid policy/config/baseline)",
    TARGET_ERROR: "target error (path missing or unreadable)",
    INTERNAL_ERROR: "internal error (unexpected exception)",
}


def describe(code: int) -> str:
    return DESCRIPTIONS.get(code, f"unknown exit code {code}")
