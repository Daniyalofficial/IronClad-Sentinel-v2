# Python security analysis coverage

IronClad's Python security analysis combines the main AST/taint engine with a narrow supplemental path-traversal pass.

## Current high-confidence path checks

- Direct `open(untrusted_path)` sinks
- `Path.read_text()`, `Path.read_bytes()`, and `Path.open()` sinks
- Common request/environment/argv/input sources
- Direct assignment propagation
- String concatenation and f-string propagation
- `secure_filename()` treated as a sanitization boundary

## Design rule

The supplemental pass intentionally favors high-confidence findings over broad heuristics. It should not claim that a filesystem path is safe merely because a variable has a suggestive name; it requires a modeled untrusted source reaching a modeled sink.

## Limitations

This is still intra-procedural analysis. It does not prove arbitrary filesystem safety, perform full inter-procedural data-flow analysis, or model every framework's request object. Future improvements should be driven by benchmark fixtures and false-positive/false-negative measurements rather than rule-count targets.
