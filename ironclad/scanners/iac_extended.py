"""High-confidence Terraform, Kubernetes and Compose IaC checks."""
from __future__ import annotations

import re
from typing import List

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile, read_text_safely


def _finding(f: DiscoveredFile, line: int, rule_id: str, title: str, description: str,
             severity: Severity, category: str, remediation: str) -> Finding:
    text = read_text_safely(f.path).splitlines()
    snippet = text[line - 1].strip() if 0 < line <= len(text) else ""
    return Finding(
        rule_id=rule_id, title=title, description=description, severity=severity,
        engine=Engine.IAC, category=category, confidence="high",
        remediation=remediation,
        location=CodeLocation(file_path=f.rel_path, start_line=line, end_line=line, snippet=snippet[:300]),
    )


def scan_extended_iac(f: DiscoveredFile) -> List[Finding]:
    content = read_text_safely(f.path)
    if not content:
        return []
    lines = content.splitlines()
    out: List[Finding] = []

    if f.iac_kind == "terraform":
        for n, line in enumerate(lines, 1):
            if re.search(r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']', line):
                out.append(_finding(f, n, "TF-WORLD-INGRESS", "Terraform security group allows world-wide ingress",
                    "A security-group rule explicitly permits traffic from every IPv4 address.", Severity.HIGH,
                    "iac-misconfiguration", "Restrict cidr_blocks to the smallest trusted network range."))
            if re.search(r'\bpublicly_accessible\s*=\s*true\b', line, re.I):
                out.append(_finding(f, n, "TF-PUBLICLY-ACCESSIBLE", "Terraform resource is publicly accessible",
                    "A resource is explicitly configured for public accessibility, increasing its exposure.", Severity.MEDIUM,
                    "iac-misconfiguration", "Disable public accessibility unless it is explicitly required and protected."))
            if re.search(r'\bencryption\s*=\s*false\b|\bencrypted\s*=\s*false\b', line, re.I):
                out.append(_finding(f, n, "TF-ENCRYPTION-DISABLED", "Terraform resource disables encryption",
                    "Encryption is explicitly disabled on an infrastructure resource.", Severity.HIGH,
                    "data-protection", "Enable encryption at rest using the provider's managed encryption feature."))

    elif f.iac_kind == "kubernetes-maybe":
        for n, line in enumerate(lines, 1):
            if re.search(r'^\s*privileged:\s*true\s*$', line, re.I):
                out.append(_finding(f, n, "K8S-PRIVILEGED", "Kubernetes container runs privileged",
                    "A privileged container receives substantially expanded host-level capabilities.", Severity.HIGH,
                    "iac-misconfiguration", "Remove privileged mode and grant only the capabilities the workload needs."))
            if re.search(r'^\s*hostNetwork:\s*true\s*$', line, re.I):
                out.append(_finding(f, n, "K8S-HOST-NETWORK", "Kubernetes workload uses the host network",
                    "hostNetwork exposes the workload directly to the node network namespace.", Severity.MEDIUM,
                    "iac-misconfiguration", "Use the pod network unless host networking is explicitly required."))
            if re.search(r'^\s*runAsUser:\s*0\s*$', line):
                out.append(_finding(f, n, "K8S-ROOT-USER", "Kubernetes workload explicitly runs as root",
                    "The pod security context requests UID 0, increasing impact if the application is compromised.", Severity.MEDIUM,
                    "iac-misconfiguration", "Run the workload as a dedicated non-root UID."))

    elif f.iac_kind == "docker-compose":
        for n, line in enumerate(lines, 1):
            if re.search(r'^\s*privileged:\s*true\s*$', line, re.I):
                out.append(_finding(f, n, "COMPOSE-PRIVILEGED", "Compose service runs privileged",
                    "Privileged mode grants the container broad host capabilities.", Severity.HIGH,
                    "iac-misconfiguration", "Remove privileged mode and use narrowly scoped capabilities."))
            if re.search(r'^\s*-?\s*["\']?0\.0\.0\.0:22:', line):
                out.append(_finding(f, n, "COMPOSE-SSH-PUBLISHED", "Compose publishes SSH to all interfaces",
                    "SSH is exposed on every host interface, increasing external attack surface.", Severity.MEDIUM,
                    "network-exposure", "Avoid SSH in application containers or bind administrative ports to a restricted interface."))
    return out
