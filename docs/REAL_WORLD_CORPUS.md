# Real-world corpus measurement

The labelled corpus in `tests/security_corpus` is 26 hand-written files.
Precision 1.00 there means the rules do not fire on their own safe
counterparts — necessary, but far weaker than "no false positives on real
code". This document closes that gap with a measurement on real projects.

## Method

Five well-maintained, widely deployed Python libraries, shallow-cloned at
their default branch:

| Project | Role |
|---|---|
| `pallets/flask` | web framework |
| `pallets/click` | CLI framework |
| `pallets/jinja` | template engine |
| `psf/requests` | HTTP client |
| `encode/httpx` | HTTP client |

**671 files scanned.** Each was scanned with every engine enabled, and every
finding was classified by hand as a true positive, a defensible finding, or
a false positive.

This is not a benchmark of the projects' security. They are mature,
actively reviewed codebases; the point is to measure how much noise
IronClad generates on code that is largely correct.

## Result

| Stage | Total findings | In production source |
|---|---:|---:|
| Before tuning | 182 | 47 |
| After test/docstring/namespace fixes | 81 | 32 |
| After `usedforsecurity`, word-boundary and docstring fixes | **73** | **25** |

**A 60% reduction in total findings and a 47% reduction in
production-source findings, with no loss of detection** — the labelled
corpus stayed at 12 true positives, 0 false negatives, precision 1.00,
recall 1.00 throughout, and `ironclad scan ironclad` stayed clean.

## What the noise actually was

Five distinct false-positive classes, each found on real code and each now
fixed with a regression test:

### 1. `assert` in test files — 86 findings

`PY-AST-ASSERT-SECURITY-CHECK` describes a real risk (the check is stripped
by `python -O`), but that risk applies to production code. In a test suite
`assert` *is* the correct idiom. 86 of 87 hits were in test files.

**Fix:** the rule is skipped for test paths. `tests/test_python_flows.py::test_assert_rule_is_skipped_entirely_in_test_files`.

### 2. Substring matching — 1 finding, but a systemic bug

`assert authority_match is not None` in `httpx/httpx/_urlparse.py:306` is a
URL-parser invariant. It matched because the rule tested `"auth" in text`,
and "auth" is a substring of "authority".

**Fix:** the keyword list is now matched with word boundaries. This class
would have silently matched `author`, `authoritative`, `authenticate_or_skip`
and so on.

### 3. Docstring examples — 4 findings

`flask/src/flask/config.py` documents `from_object` with:

```python
    """...
        DEBUG = True
        SECRET_KEY = 'development key'
    """
```

Both lines were reported as live configuration. `httpx/httpx/_urls.py` had
the same problem with a basic-auth URL inside a docstring.

**Fix:** the regex rule engine and the secrets scanner both skip lines
inside a docstring. Only lines whose triple quote *starts* the line count,
so `SIGNING_KEY = """-----BEGIN ...` — an assigned literal — is still
scanned. `tests/test_python_flows.py::test_docstring_examples_do_not_trigger_rules`.

### 4. Credential-named namespace prefixes — 12 findings

`jinja/src/jinja2/lexer.py` defines a dictionary of token-type names:

```python
TOKEN_COMMENT_BEGIN: "begin of comment",
TOKEN_VARIABLE_END: "end of print statement",
```

Twelve findings, because `TOKEN_COMMENT_BEGIN` contains "TOKEN".

**Fix:** when the sensitive word is the leading segment of a 3+-segment
name, it is a namespace prefix rather than the subject. `SECRET_KEY` and
`API_TOKEN` (2 segments) still fire. `test_credential_named_namespace_prefix_is_not_a_secret`.

### 5. `usedforsecurity=False` — 3 findings

`requests/src/requests/auth.py` calls `hashlib.md5(x, usedforsecurity=False)`
on every digest, because HTTP digest auth is not a security-sensitive use.
That keyword is CPython's documented escape hatch (it also lets FIPS builds
permit md5/sha1).

**Fix:** the flag is honoured. `test_usedforsecurity_false_is_not_a_weak_hash`.

## What remains, and why it is defensible

The 25 production-source findings that survived are not noise:

| Count | Rule | Assessment |
|---:|---|---|
| 7 | `PY-AST-SILENT-EXCEPTION-SWALLOW` | Low severity, legitimate style finding |
| 5 | `PY-AST-WEAK-HASH` | Real sha1/md5 uses without the opt-out flag |
| 4 | `PY-AST-COMPILE-USE` | `flask/cli.py` and `jinja2/environment.py` compile dynamic source |
| 3 | `PY-AST-EXEC-USE` | Same — inherent to a template engine |
| 2 | `PY-AST-INSECURE-DESERIALIZATION` | **Genuine.** `jinja2/bccache.py` does `pickle.load` / `marshal.load` on its bytecode cache; Jinja documents that the cache directory must not be attacker-writable |
| 1 | `PY-AST-PATH-TRAVERSAL` | `flask/cli.py` opens a CLI-supplied startup file |
| 1 | `PY-AST-EVAL-USE` | Same line as the compile finding |
| 1 | `PY-AST-SSL-VERIFY-DISABLED` | `httpx/_config.py` sets `CERT_NONE` — this *is* the implementation of its opt-in `verify=False` |
| 1 | `SHELL-CURL-PIPE-SH` | `.devcontainer/on-create-command.sh` pipes a remote script to a shell |

The `eval`/`exec`/`compile` cluster (8 findings) deserves a note: for a
*library whose job is to execute generated code*, these are inherent. For an
*application* repository the same findings would be real. IronClad reports
them and lets policy decide — `rules.ignore` or `severity_overrides` is the
intended control, not a scanner that guesses which project you are.

## Reproducing

```bash
for r in pallets/flask pallets/click pallets/jinja psf/requests encode/httpx; do
  git clone -q --depth 1 "https://github.com/$r.git" "/tmp/realcorpus/${r##*/}"
done
for p in flask click jinja requests httpx; do
  ironclad scan "/tmp/realcorpus/$p" --quiet --output-dir "/tmp/rc-$p" --format json
done
```

## Second measurement: other languages

The first measurement was Python-only, so it exercised the AST engine and the
Python rule pack but none of the Java/Go/Ruby/PHP packs. A second pass covers
real non-Python code:

| Project | Language | Files | Findings |
|---|---|---:|---:|
| `google/uuid` | Go | 29 | 1 |
| `gorilla/mux` | Go | 23 | 0 |
| `rubygems/rubygems` | Ruby | 1,944 | 107 → **103** |

Go was essentially clean (one `GO-UNSAFE-POINTER` in `google/uuid`, which is a
correct finding). Ruby surfaced **two more false-positive classes**, both now
fixed with regression tests:

| Class | Count | Fix |
|---|---:|---|
| Rule matched inside a whole-line comment | 1 in source, 2 in tests | `# +input+ can be anything that YAML.load() accepts` is prose. The rule engine now skips whole-line comments, with the marker chosen per language (`#` for Ruby/Python/shell/YAML/Terraform, `//` for JS/Java/Go/C-family, `--` for SQL). Trailing comments are deliberately *not* attempted — deciding whether a `#` starts a comment or sits inside a string needs a real lexer. |
| Bare URL assigned to a credential-named variable | 1 in source | `EC2_IAM_TOKEN = "http://169.254.169.254/..."` is the EC2 metadata endpoint, not a secret. Bare `http(s)://` values are excluded; URLs that embed credentials (`user:pass@host`) are still reported. |

Ruby production-source findings fell **18 → 15**. What remains is defensible:
13 of them are `RUBY-EVAL-USE` in Bundler, which `eval`s Gemfiles and
gemspecs — inherent to what Bundler does, exactly like the Jinja
`exec`/`compile` cluster above.

## Third measurement: Java and PHP

The Java and PHP packs were the last unmeasured ones. Third pass:

| Project | Language | Files | Findings | Assessment |
|---|---|---:|---:|---|
| `square/tape` | Java | 40 | 4 | 3 of 4 are in `website/prettify.js`, a **vendored** copy of Google Code Prettify. The 4th (`rm -rf $DIR` unquoted in `deploy_website.sh`) is a correct finding. |
| `PHPMailer/PHPMailer` | PHP | 182 | 9 → **5** | All in `examples/` and `test/`. Six of nine were one false-positive class, now fixed. |
| `guzzle/guzzle` | PHP | 170 | 4 | All in `tests/` — fixture URLs and a deliberately malicious payload string in a cookie-jar test. |

One more false-positive class found and fixed:

**`your<X>` fill-in placeholders (6 findings).** PHPMailer ships examples with
`$mail->Password = 'yourpassword'` and `$clientSecret = 'yourClientId'`. The
placeholder list already knew `your_key` and `your_secret` but not the general
`your<X>` convention. Extended to `your_(password|passwd|pass|pwd|token|email|
user|username|domain|host|client_id|key|secret)`.

### What was deliberately *not* suppressed

Five PHPMailer findings remain, all credential-shaped literals in example and
test files (`$clientSecret = 'RA0oTkEwOVQzfm00…'`, a DKIM test key path).
These look like real secrets and are committed to the repository. Suppressing
them because they live in `examples/` would also suppress a genuine key
committed to a test suite, which is the more costly error. They are left
reported.

The `prettify.js` case is also left as-is. It is a vendored third-party
library that is not named `*.min.js`, so the minified-file exclusion does not
catch it. The control is `paths.exclude` in `policy.yaml` — the scanner
should not guess which directories are vendored.

## Honest limitations of this measurement

1. **Eleven projects, four languages.** Python (5), Go (2), Ruby (1), Java (1)
   and PHP (2) are now measured. Coverage is still uneven — the Java pack saw
   one small project, and no Java project large enough to exercise
   `JAVA-SQL-CONCATENATION` or `JAVA-OBJECT-DESERIALIZATION` was scanned, so
   those two rules have no real-code evidence either way.
2. **Hand-classified, single reviewer.** The TP/FP calls above are one
   person's judgement, not a consensus labelling.
3. **No false-negative measurement.** Finding what the scanner *missed* in
   671 files would require knowing every real vulnerability in five mature
   libraries. This document measures noise, not coverage.
4. **A snapshot.** These are shallow clones of the default branch on the
   measurement date; results will drift as the projects change.

## Fourth measurement: dependency findings on real repositories

Everything above measured the *code* rules. This measures the dependency
engine, which is a different failure mode: its precision depends on the
advisory database and on whether a manifest declaration is evidence of an
installed version at all.

    python benchmarks/real_world_corpus.py

Six repositories, shallow clones of the default branch:

| Repository | Findings | False positives | Packages |
|---|---|---|---|
| `pallets/flask` | 12 | 0 | flask, jinja2, werkzeug |
| `pallets/click` | 0 | 0 | — |
| `pallets/jinja` | 0 | 0 | — |
| `psf/requests` | 0 | 0 | — |
| `encode/httpx` | 8 | 0 | cryptography, pytest |
| `encode/uvicorn` | 0 | 0 | — |
| **Total** | **20** | **0** | |

Every finding is on a version that is genuinely pinned in the repository
(`flask==2.3.2`, `jinja2==3.1.2` and `werkzeug==2.3.3` in flask's
`examples/celery/requirements.txt`; `cryptography==45.0.7` and
`pytest==8.4.1` in httpx's `requirements.txt`), and the script re-checks each
one independently against the advisory database rather than trusting the
scanner's own code path.

### The false-positive class this exposed

Before the pinned/range distinction existed, the same six repositories
produced **33** findings, and most were false:

```
urllib3  declared=urllib3>=1.26,<3  resolved=1.26  ->  8 advisories
idna     declared=idna>=2.5,<4      resolved=2.5   ->  2 advisories
pytest   declared=>=2.8.0,<10       resolved=2.8.0 ->  1 advisory
h11      declared=h11>=0.8          resolved=0.8   ->  1 CRITICAL
```

`urllib3>=1.26,<3` does not say urllib3 1.26 is installed; installing against
it yields the newest 2.x, which is patched. The scanner was reporting the
lowest version the range *permits* as though it were the version in use. With
the 44-package demonstration database this almost never fired, because few
range floors happened to match an advisory; a real advisory feed turns it on
immediately. Ranges are now reported only when no patched release can satisfy
them.

### What this still does not measure

**Recall.** Scoring against the same advisory database the scanner reads
would be circular — it would only prove the lookup works. A real recall
figure needs an independently labelled set of vulnerable revisions, which
this project does not have. The 0-false-positive result above is a precision
statement and nothing more.
