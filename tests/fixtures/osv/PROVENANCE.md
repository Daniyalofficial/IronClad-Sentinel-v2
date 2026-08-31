# Provenance

These are **unmodified** OSV-schema records copied from the public
[`github/advisory-database`](https://github.com/github/advisory-database)
repository (CC-BY-4.0), which is the same data served by `osv.dev`.

They are vendored verbatim so the OSV conversion tests in
`tests/test_osv_advisories.py` exercise real advisory data rather than a
hand-written approximation of the schema.

| File | Package | CVE | Severity | Range shape exercised |
|---|---|---|---|---|
| `GHSA-x84v-xcm2-53pg.json` | requests (PyPI) | CVE-2018-18074 | HIGH | `introduced: 0` + `fixed` |
| `GHSA-rprw-h62v-c2w7.json` | PyYAML (PyPI) | CVE-2017-18342 | CRITICAL | `introduced: 0` + `fixed` |
| `GHSA-462w-v97r-4m45.json` | Jinja2 (PyPI) | CVE-2019-10906 | HIGH | `introduced: 0` + `fixed` |
| `GHSA-3cm8-v4mc-gppg.json` | binwalk (PyPI) | CVE-2022-4510 | HIGH | `introduced: 2.1.2b` + `last_affected: 2.3.3` (lower bound and `<=`) |
