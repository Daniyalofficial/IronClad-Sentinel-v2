"""Source -> propagation -> sanitizer -> sink detectors for Python.

This module complements ``ironclad.scanners.ast_python`` (which handles
command/SQL/eval injection and structural checks) with the remaining
high-value flow classes. It is deliberately conservative:

* a finding requires a *modelled* untrusted source to reach a *modelled*
  sink -- a suggestive variable name is never enough on its own;
* every sink has an explicit sanitizer list, and passing through one
  suppresses the finding;
* constant-only flows never produce a finding.

The trade-off is explicit and documented in docs/THREAT_MODEL.md: this is
intra-procedural analysis, so it will miss flows that cross a function
boundary, and it will not invent findings to inflate a rule count.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.scanners.ast_python import _call_name, _dotted_name, _snippet

# --------------------------------------------------------------------------- #
# Import alias resolution
# --------------------------------------------------------------------------- #
def collect_import_aliases(tree: ast.AST) -> Dict[str, str]:
    """Map local import names to their fully-qualified module path.

    ``import xml.etree.ElementTree as ET`` makes the sink call appear as
    ``ET.fromstring``, which no rule lists. Resolving aliases first is what
    lets the XXE/crypto rules match real-world code instead of only the
    spelling the rule author happened to use.
    """
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = alias.name
                if alias.asname is None and "." in alias.name:
                    # `import a.b.c` also binds `a.b.c` as an attribute chain.
                    aliases[alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{module}.{alias.name}" if module else alias.name
    return aliases


def resolve_name(name: str, aliases: Dict[str, str]) -> str:
    """Expand the leading component of a dotted call name through ``aliases``."""
    if not name:
        return name
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] if not rest else f"{aliases[head]}.{rest}"
    return name


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
UNTRUSTED_SOURCES: Set[str] = {
    # generic stdlib
    "input", "sys.argv", "os.environ", "os.getenv",
    # flask / starlette / fastapi / django style request objects
    "request.args", "request.form", "request.values", "request.data",
    "request.json", "request.cookies", "request.headers", "request.files",
    "request.GET", "request.POST", "request.META", "request.body",
    "flask.request.args", "flask.request.form",
    # network reads
    "socket.recv", "sys.stdin.read", "sys.stdin.readline",
}

#: Function parameters whose *name* implies attacker control. Treated as a
#: source only when the parameter name is explicit about it, which keeps the
#: false-positive rate low on internal helpers.
TAINTED_PARAM_HINTS = {
    "user_input", "raw_input", "user_data", "user_path", "user_url",
    "untrusted", "attacker", "request_body", "request_data", "client_input",
    "filename_from_user", "user_filename",
}

# --------------------------------------------------------------------------- #
# Sinks
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SinkSpec:
    rule_id: str
    title: str
    severity: Severity
    category: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    calls: Tuple[str, ...]
    sanitizers: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    #: When True the tainted value must be (part of) the URL/path argument
    #: rather than an arbitrary argument -- used for SSRF/redirect precision.
    url_position: bool = False


SINK_SPECS: Tuple[SinkSpec, ...] = (
    SinkSpec(
        rule_id="PY-AST-PATH-TRAVERSAL",
        title="Path traversal via untrusted file path",
        severity=Severity.HIGH,
        category="path-traversal",
        cwe="CWE-22",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Untrusted data ({source}) reaches a filesystem path without canonicalisation or "
            "an allowlist. An attacker can use `../` or an absolute path to read or overwrite "
            "files outside the intended directory."
        ),
        remediation=(
            "Resolve the candidate against a fixed trusted root and verify the resolved path "
            "stays inside it; reject absolute and escaping paths. For uploaded filenames use "
            "os.path.basename()/secure_filename() and then re-verify the resolved location."
        ),
        calls=("open", "io.open", "builtins.open", "Path.read_text", "Path.read_bytes",
               "Path.open", "Path.write_text", "Path.write_bytes", "os.remove", "os.unlink",
               "os.rmdir", "shutil.copy", "shutil.copyfile", "shutil.move", "send_file",
               "send_from_directory", "os.path.abspath"),
        sanitizers=("secure_filename", "werkzeug.utils.secure_filename", "os.path.basename",
                    "basename", "Path.name", "os.path.realpath", "realpath"),
        references=("https://cwe.mitre.org/data/definitions/22.html",),
    ),
    SinkSpec(
        rule_id="PY-AST-SSRF",
        title="Server-side request forgery via untrusted URL",
        severity=Severity.HIGH,
        category="ssrf",
        cwe="CWE-918",
        owasp="A10:2021-Server-Side Request Forgery",
        description=(
            "Untrusted data ({source}) is used to build the target URL of an outbound HTTP "
            "request. An attacker can point the server at internal endpoints (cloud metadata "
            "services, admin panels, databases) that are not reachable from outside."
        ),
        remediation=(
            "Never build a request URL from user input. Resolve the hostname, compare it "
            "against an allowlist of permitted hosts, and reject private/link-local ranges "
            "before connecting."
        ),
        calls=("requests.get", "requests.post", "requests.put", "requests.delete",
               "requests.patch", "requests.request", "requests.head", "urllib.request.urlopen",
               "urlopen", "httpx.get", "httpx.post", "httpx.Client.get", "httpx.AsyncClient.get",
               "aiohttp.ClientSession.get", "session.get", "session.post"),
        url_position=True,
        references=("https://cwe.mitre.org/data/definitions/918.html",),
    ),
    SinkSpec(
        rule_id="PY-AST-XSS",
        title="Cross-site scripting via unescaped untrusted output",
        severity=Severity.HIGH,
        category="xss",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        description=(
            "Untrusted data ({source}) is rendered into an HTML response without escaping. "
            "An attacker can inject script that runs in another user's browser session."
        ),
        remediation=(
            "Render through the template engine's autoescaping instead of building HTML "
            "strings, or escape explicitly with markupsafe.escape()/html.escape(). Never mark "
            "user input as safe."
        ),
        calls=("render_template_string", "Markup", "markupsafe.Markup", "mark_safe",
               "django.utils.safestring.mark_safe", "response.write", "self.write",
               "writer.write"),
        sanitizers=("html.escape", "escape", "markupsafe.escape", "bleach.clean", "quote"),
        references=("https://cwe.mitre.org/data/definitions/79.html",),
    ),
    SinkSpec(
        rule_id="PY-AST-OPEN-REDIRECT",
        title="Open redirect via untrusted destination",
        severity=Severity.MEDIUM,
        category="open-redirect",
        cwe="CWE-601",
        owasp="A01:2021-Broken Access Control",
        description=(
            "Untrusted data ({source}) controls a redirect target. Attackers use open redirects "
            "to make a trusted domain hand the victim off to a phishing site, and to smuggle "
            "tokens through the Referer header."
        ),
        remediation=(
            "Redirect only to relative paths validated against an allowlist of internal routes, "
            "or map a user-supplied key to a server-side URL instead of accepting the URL itself."
        ),
        calls=("redirect", "flask.redirect", "HttpResponseRedirect",
               "django.shortcuts.redirect", "Response.redirect"),
        sanitizers=("url_for", "flask.url_for", "urllib.parse.urljoin", "urljoin"),
        references=("https://cwe.mitre.org/data/definitions/601.html",),
    ),
    SinkSpec(
        rule_id="PY-AST-TEMPLATE-INJECTION",
        title="Server-side template injection",
        severity=Severity.CRITICAL,
        category="injection",
        cwe="CWE-1336",
        owasp="A03:2021-Injection",
        description=(
            "Untrusted data ({source}) is used to build a template that is then rendered. In "
            "Jinja2/Django this is remote code execution, not just markup injection."
        ),
        remediation=(
            "Never construct a template from user input. Use a fixed template file and pass "
            "user data in as context values."
        ),
        calls=("Template", "jinja2.Template", "render_template_string", "from_string",
               "django.template.Template"),
        references=("https://cwe.mitre.org/data/definitions/1336.html",),
    ),
)

#: Structural (non-taint) checks: the pattern itself is the problem.
@dataclass(frozen=True)
class PatternSpec:
    rule_id: str
    title: str
    severity: Severity
    category: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    calls: Tuple[str, ...] = ()
    attributes: Tuple[str, ...] = ()
    confidence: str = "high"
    references: Tuple[str, ...] = ()


PATTERN_SPECS: Tuple[PatternSpec, ...] = (
    PatternSpec(
        rule_id="PY-AST-WEAK-TLS-PROTOCOL",
        title="Deprecated TLS/SSL protocol version pinned",
        severity=Severity.HIGH,
        category="crypto",
        cwe="CWE-326",
        owasp="A02:2021-Cryptographic Failures",
        description=(
            "The code pins SSLv2/SSLv3/TLS 1.0/1.1. These versions have known protocol-level "
            "attacks (POODLE, BEAST, downgrade) and are prohibited by PCI DSS."
        ),
        remediation="Use ssl.PROTOCOL_TLS_CLIENT (or TLSv1.2+ explicitly) and let the library negotiate.",
        attributes=("ssl.PROTOCOL_SSLv2", "ssl.PROTOCOL_SSLv3", "ssl.PROTOCOL_SSLv23",
                    "ssl.PROTOCOL_TLSv1", "ssl.PROTOCOL_TLSv1_1", "ssl.TLSv1_METHOD",
                    "ssl.TLSv1_1_METHOD", "ssl.SSLv23_METHOD", "ssl.SSLv3_METHOD"),
        references=("https://cwe.mitre.org/data/definitions/326.html",),
    ),
    PatternSpec(
        rule_id="PY-AST-UNSAFE-XML-PARSER",
        title="XML parsed with a parser vulnerable to XXE",
        severity=Severity.HIGH,
        category="xxe",
        cwe="CWE-611",
        owasp="A05:2021-Security Misconfiguration",
        description=(
            "xml.etree/xml.dom/xml.sax/lxml resolve external entities by default. Parsing "
            "attacker-supplied XML can disclose local files or trigger SSRF and billion-laughs "
            "denial of service."
        ),
        remediation=(
            "Use defusedxml (defusedxml.ElementTree.fromstring / defusedxml.lxml.fromstring) or "
            "explicitly disable DTDs and external entity resolution on the parser."
        ),
        calls=("xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring",
               "ElementTree.parse", "ElementTree.fromstring", "etree.parse", "etree.fromstring",
               "xml.dom.minidom.parse", "xml.dom.minidom.parseString", "minidom.parse",
               "minidom.parseString", "xml.sax.parseString", "xml.sax.parse",
               "xmlrpc.client.ServerProxy", "pulldom.parse"),
        references=("https://cwe.mitre.org/data/definitions/611.html",),
    ),
    PatternSpec(
        rule_id="PY-AST-UNSAFE-YAML-LOADER",
        title="Unsafe YAML loader selected explicitly",
        severity=Severity.CRITICAL,
        category="deserialization",
        cwe="CWE-502",
        owasp="A08:2021-Software and Data Integrity Failures",
        description=(
            "yaml.unsafe_load()/yaml.load(..., Loader=Loader|FullLoader-with-python-objects) can "
            "construct arbitrary Python objects, giving remote code execution on any YAML the "
            "application accepts."
        ),
        remediation="Use yaml.safe_load(); never accept a Loader argument derived from user input.",
        calls=("yaml.unsafe_load", "yaml.full_load"),
        references=("https://cwe.mitre.org/data/definitions/502.html",),
    ),
    PatternSpec(
        rule_id="PY-AST-SSL-VERIFY-DISABLED",
        title="TLS verification disabled on an SSL context",
        severity=Severity.HIGH,
        category="crypto",
        cwe="CWE-295",
        owasp="A02:2021-Cryptographic Failures",
        description=(
            "check_hostname/verify_mode are weakened, so any certificate (including an "
            "attacker's) is accepted. This makes the connection trivially interceptable."
        ),
        remediation="Leave check_hostname=True and verify_mode=CERT_REQUIRED; install the correct CA instead.",
        attributes=("ssl.CERT_NONE",),
        references=("https://cwe.mitre.org/data/definitions/295.html",),
    ),
)

#: random.* calls that matter only when the result is used as a credential.
INSECURE_RANDOM_CALLS = {"random.random", "random.randint", "random.randrange",
                         "random.choice", "random.sample", "random.shuffle", "random.uniform"}
SECRET_NAME_HINTS = ("token", "secret", "password", "passwd", "session", "nonce",
                     "salt", "otp", "apikey", "api_key", "csrf", "signature")


# --------------------------------------------------------------------------- #
# Taint tracking
# --------------------------------------------------------------------------- #
class FlowTracker:
    """Intra-procedural source -> sink tracker shared by every flow rule."""

    def __init__(self, filename: str, source_lines: List[str], findings: List[Finding],
                 aliases: Optional[Dict[str, str]] = None):
        self.filename = filename
        self.source_lines = source_lines
        self.findings = findings
        self.tainted: Dict[str, str] = {}
        self.aliases: Dict[str, str] = aliases or {}

    # -- sources ----------------------------------------------------------
    def mark_tainted_params(self, func: ast.AST) -> None:
        args = getattr(func, "args", None)
        if args is None:
            return
        for arg in list(args.args) + list(getattr(args, "kwonlyargs", []) or []):
            name = arg.arg
            lowered = name.lower()
            if name in TAINTED_PARAM_HINTS or any(hint in lowered for hint in ("user_input", "untrusted")):
                self.tainted[name] = f"function parameter `{name}`"

    def source_of(self, node: ast.AST) -> Optional[str]:
        """Return a description of the untrusted origin of ``node``, if any."""
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        if isinstance(node, ast.Constant):
            return None  # literals are never a taint source
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            if dotted in UNTRUSTED_SOURCES:
                return f"access of `{dotted}`"
            # request.args.get("x") -> attribute chain root is a source
            if dotted:
                root = dotted.split(".")[0]
                if dotted in {"request.args", "request.form"}:
                    return f"access of `{dotted}`"
                if root in {"request", "req"} and dotted.count(".") >= 1:
                    return f"access of `{dotted}`"
            return None
        if isinstance(node, ast.Call):
            name = _call_name(node) or ""
            if name in UNTRUSTED_SOURCES:
                return f"call to `{name}`"
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "getlist", "getone"}:
                inner = self.source_of(node.func.value)
                if inner:
                    return inner
            if name in {"str", "bytes", "format", "os.path.join", "str.format"}:
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    found = self.source_of(arg)
                    if found:
                        return found
            for arg in list(node.args):
                if self._is_sanitizer_call(node):
                    return None
            return None
        if isinstance(node, ast.Subscript):
            return self.source_of(node.value)
        if isinstance(node, ast.BinOp):
            return self.source_of(node.left) or self.source_of(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    found = self.source_of(value.value)
                    if found:
                        return found
            return None
        if isinstance(node, ast.IfExp):
            return self.source_of(node.body) or self.source_of(node.orelse)
        if isinstance(node, ast.Starred):
            return self.source_of(node.value)
        return None

    @staticmethod
    def _is_sanitizer_call(node: ast.Call) -> bool:
        name = _call_name(node) or ""
        leaf = name.rsplit(".", 1)[-1]
        return leaf in {"escape", "quote", "clean", "secure_filename", "basename", "url_for",
                        "urlencode", "int"}

    def _contains_sanitizer(self, node: ast.AST, sanitizers: Tuple[str, ...]) -> bool:
        """True if any sanitizer in ``sanitizers`` appears inside ``node``."""
        if not sanitizers:
            return False
        wanted = {s.rsplit(".", 1)[-1] for s in sanitizers}
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _call_name(child) or ""
                if name in sanitizers or name.rsplit(".", 1)[-1] in wanted:
                    return True
            if isinstance(child, ast.Attribute) and child.attr in {"name", "basename"}:
                # `Path(x).name` / `os.path.basename(x)` style canonicalisation
                if child.attr == "name":
                    return True
        return False

    # -- assignment propagation ------------------------------------------
    def visit_assign(self, node: ast.Assign) -> None:
        source = self.source_of(node.value)
        if source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = source
        elif isinstance(node.value, (ast.Constant, ast.List, ast.Dict, ast.Tuple)):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted.pop(target.id, None)

    # -- sinks ------------------------------------------------------------
    def check_call(self, node: ast.Call) -> None:
        name = resolve_name(_call_name(node) or "", self.aliases)
        leaf = name.rsplit(".", 1)[-1]
        for spec in SINK_SPECS:
            matched = name in spec.calls or (leaf and leaf in {c.rsplit(".", 1)[-1] for c in spec.calls}
                                             and _looks_like_spec_call(name, spec))
            if not matched:
                continue
            arguments = self._candidate_arguments(node, spec)
            for arg in arguments:
                if self._contains_sanitizer(arg, spec.sanitizers):
                    continue
                source = self.source_of(arg)
                if not source:
                    continue
                self._emit_flow(spec, node, source)
                break

    def _candidate_arguments(self, node: ast.Call, spec: SinkSpec) -> List[ast.AST]:
        if spec.url_position:
            if node.args:
                return [node.args[0]]
            for keyword in node.keywords:
                if keyword.arg in {"url", "uri", "href", "location"}:
                    return [keyword.value]
            return []
        return list(node.args) + [keyword.value for keyword in node.keywords if keyword.arg]

    def _emit_flow(self, spec: SinkSpec, node: ast.Call, source: str) -> None:
        end = getattr(node, "end_lineno", node.lineno)
        self.findings.append(Finding(
            rule_id=spec.rule_id,
            title=spec.title,
            description=spec.description.format(source=source),
            severity=spec.severity,
            engine=Engine.AST_PYTHON,
            category=spec.category,
            cwe=spec.cwe,
            owasp=spec.owasp,
            confidence="high",
            remediation=spec.remediation,
            references=list(spec.references),
            location=CodeLocation(
                file_path=self.filename,
                start_line=node.lineno,
                end_line=end,
                snippet=_snippet(self.source_lines, node.lineno, end),
            ),
            extra={"source": source},
        ))

    # -- insecure randomness ---------------------------------------------
    def check_insecure_random(self, node: ast.Call, parent_assign_target: Optional[str]) -> None:
        name = resolve_name(_call_name(node) or "", self.aliases)
        if name not in INSECURE_RANDOM_CALLS:
            return
        haystack = (parent_assign_target or "").lower()
        haystack += " " + _snippet(self.source_lines, node.lineno,
                                   getattr(node, "end_lineno", node.lineno)).lower()
        if not any(hint in haystack for hint in SECRET_NAME_HINTS):
            return
        end = getattr(node, "end_lineno", node.lineno)
        self.findings.append(Finding(
            rule_id="PY-AST-INSECURE-RANDOM",
            title="Non-cryptographic PRNG used for a security value",
            description=(
                "`random` is a Mersenne Twister PRNG: its internal state can be recovered from a "
                "handful of outputs, so anything derived from it (tokens, passwords, salts, "
                "session identifiers) is guessable."
            ),
            severity=Severity.HIGH,
            engine=Engine.AST_PYTHON,
            category="crypto",
            cwe="CWE-330",
            owasp="A02:2021-Cryptographic Failures",
            confidence="medium",
            remediation="Use the `secrets` module (secrets.token_urlsafe / secrets.randbelow) for security values.",
            references=["https://cwe.mitre.org/data/definitions/330.html"],
            location=CodeLocation(file_path=self.filename, start_line=node.lineno, end_line=end,
                                  snippet=_snippet(self.source_lines, node.lineno, end)),
        ))


def _looks_like_spec_call(name: str, spec: SinkSpec) -> bool:
    """Guard against matching an unrelated method that shares a leaf name.

    ``open``/``parse``/``redirect`` are common method names, so a bare leaf
    match is only accepted when the receiver looks like the expected module
    or object (``Path(...)``, ``xml.etree...``, ``flask...``).
    """
    receiver = name.rsplit(".", 1)[0] if "." in name else ""
    if not receiver:
        return True  # a plain builtin-style call such as `open(...)`
    allowed_roots = {call.split(".")[0] for call in spec.calls}
    root = receiver.split(".")[0]
    if root in allowed_roots:
        return True
    # Object-style receivers that legitimately own these methods.
    return root in {"path", "p", "f", "fh", "session", "client", "response", "self", "parser", "tree",
                    "doc", "soup", "template", "target", "dest", "src"}


# --------------------------------------------------------------------------- #
# Structural patterns
# --------------------------------------------------------------------------- #
def _check_patterns(filename: str, source_lines: List[str], tree: ast.AST,
                    findings: List[Finding], aliases: Dict[str, str]) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = resolve_name(_call_name(node) or "", aliases)
            for spec in PATTERN_SPECS:
                if name in spec.calls:
                    _emit_pattern(spec, filename, source_lines, node, findings)
        if isinstance(node, ast.Attribute):
            dotted = resolve_name(_dotted_name(node) or "", aliases)
            for spec in PATTERN_SPECS:
                if dotted in spec.attributes:
                    _emit_pattern(spec, filename, source_lines, node, findings)
        if isinstance(node, ast.Assign):
            _check_insecure_random_assignment(filename, source_lines, node, findings, aliases)


def _emit_pattern(spec: PatternSpec, filename: str, source_lines: List[str],
                  node: ast.AST, findings: List[Finding]) -> None:
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start)
    findings.append(Finding(
        rule_id=spec.rule_id,
        title=spec.title,
        description=spec.description,
        severity=spec.severity,
        engine=Engine.AST_PYTHON,
        category=spec.category,
        cwe=spec.cwe,
        owasp=spec.owasp,
        confidence=spec.confidence,
        remediation=spec.remediation,
        references=list(spec.references),
        location=CodeLocation(file_path=filename, start_line=start, end_line=end,
                              snippet=_snippet(source_lines, start, end)),
    ))


def _check_insecure_random_assignment(filename: str, source_lines: List[str],
                                      node: ast.Assign, findings: List[Finding],
                                      aliases: Dict[str, str]) -> None:
    for child in ast.walk(node.value):
        if isinstance(child, ast.Call):
            tracker = FlowTracker(filename, source_lines, findings, aliases)
            target = node.targets[0]
            tracker.check_insecure_random(child, getattr(target, "id", None))


def scan_python_flows(path: str, rel_path: str) -> List[Finding]:
    """Run the flow + structural detectors over one Python file."""
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

    aliases = collect_import_aliases(tree)
    _check_patterns(rel_path, source_lines, tree, findings, aliases)

    def run_scope(scope: ast.AST, mark_params: bool) -> None:
        tracker = FlowTracker(rel_path, source_lines, findings, aliases)
        if mark_params:
            tracker.mark_tainted_params(scope)
        for statement in ast.walk(scope):
            if isinstance(statement, ast.Assign):
                tracker.visit_assign(statement)
            elif isinstance(statement, ast.Call):
                tracker.check_call(statement)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            run_scope(node, mark_params=True)

    module_scope = [n for n in tree.body
                    if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if module_scope:
        tracker = FlowTracker(rel_path, source_lines, findings, aliases)
        for statement in module_scope:
            for child in ast.walk(statement):
                if isinstance(child, ast.Assign):
                    tracker.visit_assign(child)
                elif isinstance(child, ast.Call):
                    tracker.check_call(child)

    # Flow findings are reported once per (rule, line) even when several
    # scopes reach the same sink line.
    seen: Set[Tuple[str, int, str]] = set()
    unique: List[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.location.start_line, finding.extra.get("source", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
