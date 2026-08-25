from pathlib import Path

from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.iac_extended import scan_extended_iac


def _file(tmp_path: Path, name: str, content: str, kind: str) -> DiscoveredFile:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return DiscoveredFile(path=str(path), rel_path=name, language="terraform" if kind == "terraform" else "yaml", size_bytes=len(content), iac_kind=kind)


def test_terraform_high_risk_settings(tmp_path):
    f = _file(tmp_path, "main.tf", '''resource "x" "y" {\n  cidr_blocks = ["0.0.0.0/0"]\n  publicly_accessible = true\n  encrypted = false\n}\n''', "terraform")
    ids = {x.rule_id for x in scan_extended_iac(f)}
    assert {"TF-WORLD-INGRESS", "TF-PUBLICLY-ACCESSIBLE", "TF-ENCRYPTION-DISABLED"} <= ids


def test_kubernetes_privileged_and_root(tmp_path):
    f = _file(tmp_path, "deployment.yaml", '''apiVersion: apps/v1\nspec:\n  hostNetwork: true\n  securityContext:\n    runAsUser: 0\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n''', "kubernetes-maybe")
    ids = {x.rule_id for x in scan_extended_iac(f)}
    assert {"K8S-PRIVILEGED", "K8S-HOST-NETWORK", "K8S-ROOT-USER"} <= ids


def test_compose_safe_configuration_has_no_extended_findings(tmp_path):
    f = _file(tmp_path, "docker-compose.yml", '''services:\n  app:\n    image: example/app:1.2.3\n    read_only: true\n''', "docker-compose")
    assert scan_extended_iac(f) == []
