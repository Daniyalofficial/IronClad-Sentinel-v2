"""
Filesystem discovery: walks the target directory once, classifies files
by language/type, and hands back a `FileSet` that every engine shares.
Scanning the tree exactly once (instead of once per engine) is one of the
reasons IronClad Sentinel is fast on large monorepos.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List

from ironclad.core.config import IronCladConfig

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".sql": "sql",
    ".html": "html",
    ".env": "dotenv",
}

DEPENDENCY_MANIFESTS = {
    # Python
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    # npm / JavaScript
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    # Go
    "go.mod", "go.sum",
    # Rust
    "Cargo.toml", "Cargo.lock",
    # Java / JVM
    "pom.xml", "build.gradle", "build.gradle.kts",
    # PHP
    "composer.json", "composer.lock",
    # Ruby
    "Gemfile", "Gemfile.lock",
    # .NET
    "packages.config",
}

# Manifest filenames that vary per project (requirements-dev.txt, MyApp.csproj)
_REQUIREMENTS_VARIANT = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)


def is_dependency_manifest(filename: str) -> bool:
    """True when a filename is a dependency manifest IronClad can parse."""
    if filename in DEPENDENCY_MANIFESTS:
        return True
    if _REQUIREMENTS_VARIANT.match(filename):
        return True
    return filename.lower().endswith(".csproj")

IAC_FILENAMES_HINTS = {
    "dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
}


@dataclass
class DiscoveredFile:
    path: str
    rel_path: str
    language: str
    size_bytes: int
    is_dependency_manifest: bool = False
    iac_kind: str = ""


@dataclass
class FileSet:
    root: str
    files: List[DiscoveredFile] = field(default_factory=list)
    skipped: int = 0

    def by_language(self, language: str) -> List[DiscoveredFile]:
        return [f for f in self.files if f.language == language]

    def dependency_manifests(self) -> List[DiscoveredFile]:
        return [f for f in self.files if f.is_dependency_manifest]

    def iac_files(self) -> List[DiscoveredFile]:
        return [f for f in self.files if f.iac_kind]


def _matches_any_glob(name: str, globs) -> bool:
    return any(fnmatch.fnmatch(name, g) for g in globs)


def classify(filename: str) -> str:
    lower = filename.lower()
    if lower in IAC_FILENAMES_HINTS:
        return "iac"
    _, ext = os.path.splitext(lower)
    return LANGUAGE_EXTENSIONS.get(ext, "other")


def discover(config: IronCladConfig) -> FileSet:
    root = os.path.abspath(config.target)
    fileset = FileSet(root=root)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not config.is_excluded_dir(d) and not d.startswith(".git")]

        for filename in filenames:
            if _matches_any_glob(filename, config.exclude_globs):
                fileset.skipped += 1
                continue

            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root)

            if _matches_any_glob(rel_path, config.ignore_paths):
                fileset.skipped += 1
                continue

            if config.include_globs and not _matches_any_glob(rel_path, config.include_globs):
                fileset.skipped += 1
                continue

            try:
                size_bytes = os.path.getsize(full_path)
            except OSError:
                fileset.skipped += 1
                continue

            if size_bytes > config.max_file_size_kb * 1024:
                fileset.skipped += 1
                continue

            language = classify(filename)
            lower_name = filename.lower()

            iac_kind = ""
            if lower_name == "dockerfile" or lower_name.startswith("dockerfile."):
                iac_kind = "docker"
            elif lower_name in ("docker-compose.yml", "docker-compose.yaml"):
                iac_kind = "docker-compose"
            elif language == "terraform":
                iac_kind = "terraform"
            elif language == "yaml" and ("k8s" in dirpath.lower() or "kubernetes" in dirpath.lower() or lower_name in ("deployment.yaml", "deployment.yml")):
                iac_kind = "kubernetes-maybe"

            is_manifest = is_dependency_manifest(filename)

            fileset.files.append(DiscoveredFile(
                path=full_path,
                rel_path=rel_path,
                language=language,
                size_bytes=size_bytes,
                is_dependency_manifest=is_manifest,
                iac_kind=iac_kind,
            ))

    return fileset


def read_text_safely(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return ""
