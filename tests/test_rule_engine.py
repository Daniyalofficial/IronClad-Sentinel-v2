import os
import tempfile

from ironclad.core.walker import DiscoveredFile
from ironclad.rules.schema import load_rule_packs
from ironclad.scanners.rule_engine import scan_file_with_rules

PACK_DIR = os.path.join(os.path.dirname(__file__), "..", "ironclad", "rules", "packs")


def _discovered(content: str, language: str, suffix: str):
    fh = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return DiscoveredFile(path=fh.name, rel_path=os.path.basename(fh.name), language=language, size_bytes=len(content))


def test_rule_packs_load_without_errors():
    rules = load_rule_packs([PACK_DIR])
    assert len(rules) > 10


def test_detects_aws_key_generic():
    rules = load_rule_packs([PACK_DIR])
    d = _discovered('key = "AKIAABCDEFGHIJKLMNOP"\n', "python", ".py")
    try:
        findings = scan_file_with_rules(d, rules)
        assert any(f.rule_id == "SECRET-AWS-ACCESS-KEY-ID" for f in findings)
    finally:
        os.unlink(d.path)


def test_detects_js_eval():
    rules = load_rule_packs([PACK_DIR])
    d = _discovered('eval(userInput);\n', "javascript", ".js")
    try:
        findings = scan_file_with_rules(d, rules)
        assert any(f.rule_id == "JS-EVAL-USE" for f in findings)
    finally:
        os.unlink(d.path)


def test_exclude_if_matches_suppresses_finding():
    rules = load_rule_packs([PACK_DIR])
    d = _discovered('const apiKey = process.env.API_KEY_VALUE_XXXXXXXXXXXX;\n', "javascript", ".js")
    try:
        findings = scan_file_with_rules(d, rules)
        assert not any(f.rule_id == "JS-HARDCODED-SECRET-ASSIGN" for f in findings)
    finally:
        os.unlink(d.path)


def test_k8s_privileged_container_detected():
    rules = load_rule_packs([PACK_DIR])
    d = _discovered('spec:\n  containers:\n  - securityContext:\n      privileged: true\n', "yaml", ".yaml")
    try:
        findings = scan_file_with_rules(d, rules)
        assert any(f.rule_id == "YAML-K8S-PRIVILEGED-CONTAINER" for f in findings)
    finally:
        os.unlink(d.path)
