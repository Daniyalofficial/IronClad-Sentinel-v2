"""High-confidence supplemental Python security checks.

This module deliberately stays narrow: it complements the main AST/taint
engine with path-traversal sinks that are easy to model statically without
introducing a broad, noisy heuristic engine.
"""
from __future__ import annotations

import ast
from typing import Dict, List, Optional

from ironclad.core.models import CodeLocation, Engine, Finding, Severity


TAINT_SOURCES = {
    "input",
    "request.args",
    "request.form",
    "request.values",
    "request.data",
    "request.json",
    "request.cookies",
    "request.headers",
    "os.environ",
    "os.getenv",
    "sys.argv",
}

PATH_SINKS = {"open", "builtins.open", "Path.read_text", "Path.read_bytes", "Path.open"}

SANITIZERS = {
    "secure_filename",
    "werkzeug.utils.secure_filename",
}


def _dotted_name(node: ast.AST) -> Optional[str]:
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _call_name(node: ast.Call) -> Optional[str]:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return _dotted_name(node.func)
    return None


def _snippet(lines: List[str], lineno: int, end: Optional[int] = None) -> str:
    stop = end or lineno
    return "\n".join(lines[max(0, lineno - 1):stop]).strip()[:500]


def _taint(expr: ast.AST, tainted: Dict[str, str]) -> Optional[str]:
    if isinstance(expr, ast.Name):
        return tainted.get(expr.id)
    if isinstance(expr, ast.Attribute):
        dotted = _dotted_name(expr)
        if dotted in TAINT_SOURCES:
            return f"access of `{dotted}`"
    if isinstance(expr, ast.Call):
        name = _call_name(expr)
        if name in TAINT_SOURCES:
            return f"call to `{name}`"
        if name in SANITIZERS:
            return None
        # Conservative propagation through common conversion/wrapper calls.
        for arg in expr.args:
            source = _taint(arg, tainted)
            if source:
                return source
    if isinstance(expr, ast.Subscript):
        return _taint(expr.value, tainted)
    if isinstance(expr, ast.BinOp):
        return _taint(expr.left, tainted) or _taint(expr.right, tainted)
    if isinstance(expr, ast.JoinedStr):
        for value in expr.values:
            if isinstance(value, ast.FormattedValue):
                source = _taint(value.value, tainted)
                if source:
                    return source
    return None


def _finding(filename: str, lines: List[str], node: ast.Call, source: str) -> Finding:
    end = getattr(node, "end_lineno", node.lineno)
    return Finding(
        rule_id="PY-AST-PATH-TRAVERSAL",
        title="Path traversal via untrusted file path",
        description=(
            f"Untrusted data ({source}) reaches a filesystem path sink without a recognized "
            "canonicalization/allowlist step. An attacker may use `../` or absolute paths to "
            "read or overwrite files outside the intended directory."
        ),
        severity=Severity.HIGH,
        engine=Engine.AST_PYTHON,
        category="path-traversal",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        confidence="high",
        remediation=(
            "Resolve the candidate path against a fixed trusted root, verify that the resolved "
            "path remains inside that root, and reject absolute/escaping paths. For uploaded "
            "filenames, use a trusted allowlist or secure_filename-style canonicalization."
        ),
        references=["https://cwe.mitre.org/data/definitions/22.html"],
        location=CodeLocation(
            file_path=filename,
            start_line=node.lineno,
            end_line=end,
            snippet=_snippet(lines, node.lineno, end),
        ),
    )


def scan_python_path_traversal(path: str, rel_path: str) -> List[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
    except OSError:
        return []

    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return []

    lines = source.splitlines()
    findings: List[Finding] = []

    for function in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        tainted: Dict[str, str] = {}
        for arg in function.args.args:
            if arg.arg in {"path", "file", "filename", "filepath", "user_path", "name", "request"} or "path" in arg.arg.lower():
                tainted[arg.arg] = f"function parameter `{arg.arg}`"

        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                source_name = _taint(node.value, tainted)
                if source_name:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            tainted[target.id] = source_name

            if not isinstance(node, ast.Call):
                continue

            name = _call_name(node)
            if name == "open":
                args = list(node.args)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes", "open"}:
                args = [node.func.value]
            else:
                continue

            for arg in args:
                source_name = _taint(arg, tainted)
                if source_name:
                    findings.append(_finding(rel_path, lines, node, source_name))
                    break

    return findings
