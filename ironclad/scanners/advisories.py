"""Pluggable vulnerability advisory sources.

IronClad Sentinel is offline-first, so the *default* advisory source is the
bundled JSON database that ships inside the package. Enterprises that
maintain their own advisory feed (an internal OSV mirror, a curated
internal database, a vendor feed) plug it in without touching scanner code.

Three sources ship today:

``bundled``   the JSON file in ``ironclad/data/vuln_db.json``. Always
              available, never touches the network. This is the default.
``directory`` a folder of JSON advisory files with the same schema, merged
              over the bundled data. Use this for an organization-specific
              overlay (``advisory_path: /etc/ironclad/advisories``).
``remote``    an OSV-compatible HTTPS endpoint. **Opt-in only.** It is
              never used unless explicitly configured, it has a hard
              timeout, it sends only the package name and ecosystem in a
              GET/POST body, and a network failure degrades to "no
              advisories" plus a recorded warning rather than failing the
              scan silently or hanging CI.

Every source returns the same shape::

    {
      "id": "GHSA-xxxx",
      "cve": "CVE-2024-0000",
      "affected": ">=1.0.0, <1.5.3",
      "severity": "high",
      "summary": "...",
      "fixed_in": "1.5.3"
    }
"""
from __future__ import annotations

import abc
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ironclad.scanners import osv

BUNDLED_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "vuln_db.json")

# Hard ceiling for the opt-in remote source. Scans must never hang on a
# network call in CI; if the feed is slow the scan proceeds with what it has.
REMOTE_TIMEOUT_SECONDS = 10.0
REMOTE_MAX_PACKAGES = 500


class AdvisorySourceError(RuntimeError):
    """Raised when an advisory source is misconfigured."""


@dataclass
class AdvisorySource(abc.ABC):
    """Base advisory source. Concrete subclasses implement ``lookup``."""

    name: str = "bundled"
    warnings: List[str] = field(default_factory=list)

    @abc.abstractmethod
    def lookup(self, ecosystem: str, package: str) -> List[Dict[str, object]]:
        """Return every advisory known for ``package`` in ``ecosystem``."""

    def stats(self) -> Dict[str, object]:
        return {"source": self.name, "warnings": list(self.warnings)}


@dataclass
class BundledAdvisorySource(AdvisorySource):
    """The offline database shipped inside the package."""

    path: str = BUNDLED_DB_PATH
    _data: Optional[Dict] = field(default=None, repr=False)

    def __post_init__(self):
        self.name = "bundled"

    def _load(self) -> Dict:
        if self._data is None:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                self._data = loaded if isinstance(loaded, dict) else {}
            except (OSError, json.JSONDecodeError) as exc:
                self.warnings.append(f"bundled advisory database unreadable: {exc}")
                self._data = {}
        return self._data

    def lookup(self, ecosystem: str, package: str) -> List[Dict[str, object]]:
        eco = self._load().get(ecosystem, {})
        if not isinstance(eco, dict):
            return []
        advisories = eco.get(package) or eco.get(package.lower())
        return list(advisories) if isinstance(advisories, list) else []

    def ecosystems(self) -> List[str]:
        return [k for k in self._load() if not k.startswith("_")]

    def package_count(self) -> int:
        return sum(
            len(v) for key, eco in self._load().items() if not key.startswith("_")
            and isinstance(eco, dict) for v in [eco]
        )


@dataclass
class DirectoryAdvisorySource(AdvisorySource):
    """Organization-specific overlay merged over the bundled database.

    Two file formats are accepted, detected per file:

    * IronClad's own schema -- ``{ecosystem: {package: [advisories]}}`` --
      the same shape as the bundled database. Later files (alphabetical) win
      for the same package.
    * Native OSV records, an OSV batch response (``{"vulns": [...]}``), or a
      JSON array of records. This is what ``osv.dev`` publishes and what the
      ``github/advisory-database`` repository contains, so a mirror of either
      can be dropped in directly. Ranges are converted through
      :mod:`ironclad.scanners.osv`; records for ecosystems IronClad has no
      manifest parser for are dropped with a recorded warning.
    """

    directory: str = ""
    base: AdvisorySource = field(default_factory=BundledAdvisorySource)

    def __post_init__(self):
        self.name = f"directory:{self.directory}"
        self._overlay: Optional[Dict[str, Dict[str, List[Dict]]]] = None

    def _load_overlay(self) -> Dict[str, Dict[str, List[Dict]]]:
        if self._overlay is not None:
            return self._overlay
        overlay: Dict[str, Dict[str, List[Dict]]] = {}
        if not self.directory or not os.path.isdir(self.directory):
            self.warnings.append(f"advisory directory not found: {self.directory!r}")
            self._overlay = overlay
            return overlay
        for filename in sorted(os.listdir(self.directory)):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.directory, filename)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                self.warnings.append(f"skipping unreadable advisory file {filename}: {exc}")
                continue
            if not isinstance(payload, (dict, list)):
                self.warnings.append(f"skipping {filename}: not a JSON object")
                continue
            if osv.is_osv_payload(payload):
                # A real OSV record, batch response or array of records.
                converted = 0
                for eco, packages in osv.build_database(osv.iter_records(payload)).items():
                    for package, advisories in packages.items():
                        overlay.setdefault(eco, {})[package] = advisories
                        converted += 1
                if converted == 0:
                    self.warnings.append(
                        f"{filename}: OSV records found, but none for an ecosystem "
                        f"IronClad scans -- nothing merged")
                continue
            if not isinstance(payload, dict):
                self.warnings.append(f"skipping {filename}: not a JSON object")
                continue
            for ecosystem, packages in payload.items():
                if ecosystem.startswith("_") or not isinstance(packages, dict):
                    continue
                for package, advisories in packages.items():
                    if not isinstance(advisories, list):
                        self.warnings.append(
                            f"skipping {filename}:{ecosystem}/{package}: advisories must be a list")
                        continue
                    overlay.setdefault(ecosystem, {})[package.lower()] = advisories
        self._overlay = overlay
        return overlay

    def lookup(self, ecosystem: str, package: str) -> List[Dict[str, object]]:
        merged = list(self.base.lookup(ecosystem, package))
        override = self._load_overlay().get(ecosystem, {}).get(package.lower())
        if override is not None:
            # An explicit organization entry replaces the bundled one for
            # that package: the org feed is authoritative for its own scope.
            merged = [a for a in merged if a.get("id") not in {o.get("id") for o in override}]
            merged.extend(override)
        return merged


@dataclass
class RemoteAdvisorySource(AdvisorySource):
    """Opt-in OSV-compatible remote feed.

    Disabled unless an operator explicitly configures it. Failures are
    recorded as warnings and degrade to the bundled source so a scan can
    never be blocked -- or silently "pass" -- because of the network.
    """

    endpoint: str = ""
    timeout: float = REMOTE_TIMEOUT_SECONDS
    fallback: AdvisorySource = field(default_factory=BundledAdvisorySource)
    _client: object = field(default=None, repr=False)

    def __post_init__(self):
        self.name = f"remote:{self.endpoint}"
        if self.endpoint and not self.endpoint.lower().startswith("https://"):
            raise AdvisorySourceError(
                "remote advisory endpoint must use https:// (refusing plain HTTP)")

    def lookup(self, ecosystem: str, package: str) -> List[Dict[str, object]]:
        advisories = list(self.fallback.lookup(ecosystem, package))
        if not self.endpoint:
            return advisories
        try:
            remote = self._fetch(ecosystem, package)
        except Exception as exc:  # noqa: BLE001 - network failures must not fail a scan
            self.warnings.append(f"remote advisory lookup failed for {package}: {exc}")
            return advisories
        known = {a.get("id") for a in advisories}
        advisories.extend(a for a in remote if a.get("id") not in known)
        return advisories

    def _fetch(self, ecosystem: str, package: str) -> List[Dict[str, object]]:
        import urllib.request

        payload = json.dumps({"package": {"name": package, "ecosystem": osv.osv_ecosystem(ecosystem)}}).encode()
        request = urllib.request.Request(
            self.endpoint.rstrip("/") + "/query",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "ironclad-sentinel"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - https enforced above
            body = json.loads(response.read().decode("utf-8"))
        # Converted through the same OSV code path as the directory overlay.
        # The previous hand-rolled conversion here read only the last
        # `fixed` event of the first range: it ignored `introduced` (so
        # versions *before* the vulnerable range were flagged) and emitted
        # "<0" when a record had no `fixed` event at all, which the matcher
        # treats as "matches nothing" -- silently hiding those advisories.
        out: List[Dict[str, object]] = []
        for record in osv.iter_records(body):
            for eco, name, advisory in osv.record_to_entries(record):
                if eco == ecosystem and name.lower() == package.lower():
                    out.append(advisory)
        return out


def build_source(
    kind: str = "bundled",
    path: Optional[str] = None,
    endpoint: Optional[str] = None,
    timeout: float = REMOTE_TIMEOUT_SECONDS,
) -> AdvisorySource:
    """Construct an advisory source from configuration values."""
    kind = (kind or "bundled").lower()
    if kind == "bundled":
        # `advisory_path` pointing at a *directory* is the documented overlay
        # workflow ("point advisory_path at your own maintained overlay
        # directory"). Honour it instead of handing the directory to the
        # bundled file loader, which would fail to open it, warn, and then
        # scan with an empty database -- silently disabling every dependency
        # vulnerability check while the scan still exited 0.
        if path and os.path.isdir(path):
            return DirectoryAdvisorySource(directory=path)
        return BundledAdvisorySource(path=path or BUNDLED_DB_PATH)
    if kind == "directory":
        if not path:
            raise AdvisorySourceError("advisory source 'directory' requires advisory_path")
        return DirectoryAdvisorySource(directory=path)
    if kind == "remote":
        if not endpoint:
            raise AdvisorySourceError("advisory source 'remote' requires advisory_endpoint")
        base = DirectoryAdvisorySource(directory=path) if path else BundledAdvisorySource()
        return RemoteAdvisorySource(endpoint=endpoint, timeout=timeout, fallback=base)
    raise AdvisorySourceError(f"unknown advisory source kind: {kind!r}")
