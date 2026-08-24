"""
Configuration loading for IronClad Sentinel.

Config precedence (highest wins):
  1. CLI flags
  2. `.ironclad.yml` in the scan target root
  3. Built-in defaults

The config file format is intentionally small and explicit -- no plugin
downloads, no remote includes, nothing that would require network access.
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

    @classmethod
    def load(cls, target: str, overrides: Optional[Dict[str, Any]] = None) -> "IronCladConfig":
        cfg = cls(target=target)
        config_path = os.path.join(target, CONFIG_FILENAME)
        if os.path.isfile(config_path):
            with open(config_path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            cfg._apply(data)
        if overrides:
            cfg._apply(overrides)
        return cfg

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
