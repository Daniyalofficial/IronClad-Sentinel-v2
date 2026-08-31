"""
IronClad Sentinel
==================

A fully offline, self-hosted Application Security scanning platform.

No telemetry. No external API calls. No "phone home." Every scan, every
rule evaluation, and every report is generated entirely on the machine
running the tool. This makes IronClad Sentinel suitable for air-gapped
networks, regulated industries (finance, healthcare, defense), and any
organization whose security policy forbids sending source code to a
third-party SaaS scanner.

Engines bundled in this package:
  - Deep Python AST taint/heuristic analyzer
  - Generic multi-language rule engine (custom YAML rule DSL)
  - Secrets & credential detector (regex + Shannon entropy)
  - Offline dependency vulnerability matcher (bundled advisory DB)
  - Infrastructure-as-Code misconfiguration scanner (Docker/K8s/Terraform)
  - SBOM (Software Bill of Materials) generator
  - Open-source license compliance checker

Commercial licensing is enforced locally via signed, offline Ed25519
license tokens (see `ironclad.licensing`). No license server is contacted
at scan time -- license files are verified with a public key embedded in
the distribution.
"""

__version__ = "1.1.0"
__product__ = "IronClad Sentinel"
