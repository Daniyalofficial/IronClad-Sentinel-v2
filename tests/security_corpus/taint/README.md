# Taint/SAST regression corpus

These fixtures deliberately contain vulnerable and safe variants. They are used to measure whether IronClad detects high-confidence patterns without flagging the safe counterparts.

Current cases:
- command injection
- SQL injection
- path traversal
- unsafe deserialization

The fixtures are intentionally small and deterministic so they can be reused in CI and future scanner improvements.

The path-traversal case is also covered by `test_python_security_supplement.py` to ensure the supplemental AST sink remains regression-tested.