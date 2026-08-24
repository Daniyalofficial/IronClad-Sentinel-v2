"""
Infrastructure-as-Code misconfiguration scanner.

Handles structural checks that are awkward to express as single-line
regex rules (multi-line context, "absence of a required directive"
checks). The YAML-based rule pack (`multi_language_crypto.yml`,
`shell_and_config.yml`) already covers several presence-based IaC
patterns; this module focuses on Dockerfiles specifically, since
Dockerfile syntax isn't YAML/JSON and benefits from a small dedicated
line-oriented parser.
"""
from __future__ import annotations

import re
from typing import List

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile, read_text_safely


def scan_dockerfile(discovered: DiscoveredFile) -> List[Finding]:
    content = read_text_safely(discovered.path)
    if not content:
        return []

    lines = content.splitlines()
    findings: List[Finding] = []

    has_user_directive = False
    has_healthcheck = False
    last_from_line = 1

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        upper = line.upper()

        if upper.startswith("FROM"):
            last_from_line = idx
            if ":LATEST" in upper or (":" not in line.split()[1] if len(line.split()) > 1 else False):
                findings.append(_finding(
                    discovered, idx, line,
                    "DOCKER-FLOATING-TAG", "Base image uses a floating/latest tag",
                    "Using `latest` (or no tag at all, which defaults to `latest`) means the "
                    "exact base image contents can change between builds without notice, "
                    "breaking reproducibility and silently introducing new vulnerabilities.",
                    Severity.LOW, "supply-chain", cwe="CWE-1104",
                    remediation="Pin the base image to an explicit version tag, ideally with a digest (FROM image@sha256:...).",
                ))

        if upper.startswith("USER"):
            has_user_directive = True

        if upper.startswith("HEALTHCHECK"):
            has_healthcheck = True

        if upper.startswith("RUN") and re.search(r"\bcurl\b.*\|\s*(sudo\s+)?(sh|bash)", line, re.IGNORECASE):
            findings.append(_finding(
                discovered, idx, line,
                "DOCKER-CURL-PIPE-SH", "Piping a remote download into a shell during image build",
                "A RUN instruction downloads a script and pipes it directly into a shell "
                "interpreter, baking unreviewed remote code into the image with no integrity "
                "verification.",
                Severity.HIGH, "supply-chain", cwe="CWE-494",
                remediation="Download the script, verify its checksum/signature, then execute it explicitly.",
            ))

        if re.search(r"(?i)(password|secret|api_key|token)\s*=\s*[\"']?[A-Za-z0-9+/_\-]{8,}", line) and upper.startswith(("ENV", "ARG")):
            findings.append(_finding(
                discovered, idx, line,
                "DOCKER-HARDCODED-SECRET-ENV", "Secret hardcoded in Dockerfile ENV/ARG",
                "A credential-looking value is baked into the image via ENV/ARG. Anyone with "
                "access to the image (registry, `docker history`, or a shared cache layer) "
                "can extract it, and ARG values persist in the build history and layer cache.",
                Severity.HIGH, "secrets", cwe="CWE-798",
                remediation="Use Docker BuildKit secrets (--mount=type=secret) or inject secrets at runtime via an orchestrator, never bake them into image layers.",
            ))

        if upper.startswith("EXPOSE") and re.search(r"\b22\b", line):
            findings.append(_finding(
                discovered, idx, line,
                "DOCKER-EXPOSE-SSH-PORT", "Container exposes SSH port 22",
                "Running an SSH daemon inside an application container is a common "
                "anti-pattern that expands the attack surface; containers should generally "
                "be accessed via `docker exec`/orchestrator tooling, not SSH.",
                Severity.LOW, "misconfiguration", cwe="CWE-1188",
                remediation="Remove the SSH server from the container image; use `kubectl exec`/`docker exec` for interactive access.",
            ))

    if not has_user_directive:
        findings.append(_finding(
            discovered, last_from_line, "(no USER instruction found in file)",
            "DOCKER-MISSING-USER", "Container runs as root (no USER instruction)",
            "No USER instruction was found, so the container's main process runs as root "
            "by default. A container escape or arbitrary-file-write bug in the application "
            "then grants the attacker root inside (and potentially outside) the container.",
            Severity.MEDIUM, "iac-misconfiguration", cwe="CWE-250",
            remediation="Add a non-root user (e.g. `RUN useradd -m appuser` then `USER appuser`) before the final CMD/ENTRYPOINT.",
        ))

    if not has_healthcheck:
        findings.append(_finding(
            discovered, last_from_line, "(no HEALTHCHECK instruction found in file)",
            "DOCKER-MISSING-HEALTHCHECK", "No HEALTHCHECK instruction defined",
            "Without a HEALTHCHECK, orchestrators cannot automatically detect and restart an "
            "unhealthy/hung container, increasing downtime during an incident.",
            Severity.INFO, "reliability",
            remediation="Add a HEALTHCHECK instruction that verifies the application is actually serving requests.",
        ))

    return findings


def _finding(discovered: DiscoveredFile, line_no: int, snippet: str, rule_id: str, title: str,
             description: str, severity: Severity, category: str, cwe: str = None,
             remediation: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        engine=Engine.IAC,
        category=category,
        cwe=cwe,
        remediation=remediation,
        confidence="medium",
        location=CodeLocation(
            file_path=discovered.rel_path,
            start_line=line_no,
            end_line=line_no,
            snippet=snippet[:300],
        ),
    )


def scan_iac_files(iac_files: List[DiscoveredFile]) -> List[Finding]:
    findings: List[Finding] = []
    for f in iac_files:
        if f.iac_kind == "docker":
            findings.extend(scan_dockerfile(f))
    return findings
