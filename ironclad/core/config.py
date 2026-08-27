"""
Configuration loading for IronClad Sentinel.

Config precedence (highest wins):

  1. CLI flags
  2. ``IRONCLAD_*`` environment variables (e.g. ``IRONCLAD_MIN_SEVERITY``)
  3. ``.ironclad.yml`` in the scan target root (project config)
  4. ``~/.ironclad/config.yml`` (organization/machine-wide config)
  5. Built-in defaults

The config file format is intentionally small and explicit -- no plugin
downloads, no remote includes, nothing that would require network access.
Only the ``remote`` advisory source ever opens a socket, and it is opt-in.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv",
    "env", ".env", "__pycache__", ".mypy_cache", ".pytest_cache",
    "dist", "build", "target", ".tox", ".idea", ".vscode", "coverage",
    ".next", ".nuxt", ".output", ".turbo", "out",
}

DEFAULT_EXCLUDE_FILE_GLOBS = {
    "*.min.js", "*.lock", "*.map", "*.svg", "*.png", "*.jpg", "*.jpeg",
    "*.gif", "*.ico", "*.woff", "*.woff2", "*.ttf", "*.eot", "*.pdf",
    "*.zip", "*.tar", "*.gz", "*.whl", "*.pyc", "*.so", "*.dll", "*.exe",
}

CONFIG_FILENAME = ".ironclad.yml"


def _read_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return data if isinstance(data, dict) else {}


@dataclass
class IronCladConfig:
    target: str = "."
    exclude_dirs: set = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    exclude_globs: set = field(default_factory=lambda: set(DEFAULT_EXCLUDE_FILE_GLOBS))
    include_globs: List[str] = field(default_factory=list)
    enabled_engines: List[str] = field(default_factory=lambda: [
        "ast-python", "rule-engine", "secrets", "dependency", "iac", "license-compliance",
    ])
    min_severity: str = "info"
    fail_on_severity: Optional[str] = None
    max_risk_score: Optional[int] = None
    baseline_file: Optional[str] = None
    custom_rules_dirs: List[str] = field(default_factory=list)
    ignore_rule_ids: List[str] = field(default_factory=list)
    ignore_paths: List[str] = field(default_factory=list)
    max_file_size_kb: int = 2048
    entropy_threshold: float = 4.3
    report_formats: List[str] = field(default_factory=lambda: ["json"])
    output_dir: str = ".ironclad/reports"
    # Advisory feed selection. "bundled" is offline and is the default;
    # "directory" merges an organization overlay; "remote" is opt-in only.
    advisory_source: str = "bundled"
    advisory_path: Optional[str] = None
    advisory_endpoint: Optional[str] = None

    @classmethod
    def load(cls, target: str, overrides: Optional[Dict[str, Any]] = None) -> "IronCladConfig":
        """Load configuration using the documented precedence chain."""
        cfg = cls(target=target)

        org_path = os.path.join(os.path.expanduser("~"), ".ironclad", "config.yml")
        if os.path.isfile(org_path):
            cfg._apply(_read_yaml(org_path))

        project_path = os.path.join(target, CONFIG_FILENAME)
        if os.path.isfile(project_path):
            cfg._apply(_read_yaml(project_path))

        cfg._apply(cls._env_overrides())

        if overrides:
            cfg._apply(overrides)
        return cfg

    #: Environment variables mapped to configuration fields.
    ENV_MAP = {
        "IRONCLAD_MIN_SEVERITY": ("min_severity", str),
        "IRONCLAD_OUTPUT_DIR": ("output_dir", str),
        "IRONCLAD_BASELINE": ("baseline_file", str),
        "IRONCLAD_ENTROPY_THRESHOLD": ("entropy_threshold", float),
        "IRONCLAD_MAX_FILE_SIZE_KB": ("max_file_size_kb", int),
        "IRONCLAD_ADVISORY_SOURCE": ("advisory_source", str),
        "IRONCLAD_ADVISORY_PATH": ("advisory_path", str),
        "IRONCLAD_ADVISORY_ENDPOINT": ("advisory_endpoint", str),
        "IRONCLAD_IGNORE_RULES": ("ignore_rule_ids", lambda raw: [r.strip() for r in raw.split(",") if r.strip()]),
        "IRONCLAD_ENGINES": ("enabled_engines", lambda raw: [e.strip() for e in raw.split(",") if e.strip()]),
    }

    @classmethod
    def _env_overrides(cls) -> Dict[str, Any]:
        found: Dict[str, Any] = {}
        for env_name, (field_name, caster) in cls.ENV_MAP.items():
            raw = os.environ.get(env_name)
            if raw is None or raw == "":
                continue
            try:
                found[field_name] = caster(raw)
            except (TypeError, ValueError):
                # A malformed environment value must not silently widen or
                # narrow a scan; ignore it and let the file/default win.
                continue
        return found

    def _apply(self, data: Dict[str, Any]) -> None:
        for key, value in data.items():
            if value is None:
                continue
            if key in ("exclude_dirs", "exclude_globs") and isinstance(value, list):
                getattr(self, key).update(value)
            elif hasattr(self, key):
                setattr(self, key, value)

    def is_excluded_dir(self, dirname: str) -> bool:
        return dirname in self.exclude_dirs
