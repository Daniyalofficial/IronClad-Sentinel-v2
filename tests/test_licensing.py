import os
import tempfile

import pytest

from ironclad.licensing.keygen import (
    generate_vendor_keypair,
    issue_license,
    verify_license,
)
import ironclad.licensing.keygen as keygen_module


def test_issue_and_verify_valid_license(monkeypatch):
    tmpdir = tempfile.mkdtemp()
    priv_path = os.path.join(tmpdir, "vendor_private_key.pem")
    pub_path = os.path.join(tmpdir, "vendor_public_key.pem")
    generate_vendor_keypair(priv_path, pub_path)

    # Point the module at our throwaway keypair instead of the real bundled one.
    monkeypatch.setattr(keygen_module, "PUBLIC_KEY_PATH", pub_path)

    license_path = os.path.join(tmpdir, "license.json")
    issue_license("Test Customer", "enterprise", 10, 365, priv_path, license_path)

    status = verify_license(license_path)
    assert status.valid
    assert status.terms.customer == "Test Customer"
    assert status.terms.tier == "enterprise"
    assert status.days_remaining > 300


def test_verify_rejects_tampered_license(monkeypatch):
    tmpdir = tempfile.mkdtemp()
    priv_path = os.path.join(tmpdir, "vendor_private_key.pem")
    pub_path = os.path.join(tmpdir, "vendor_public_key.pem")
    generate_vendor_keypair(priv_path, pub_path)
    monkeypatch.setattr(keygen_module, "PUBLIC_KEY_PATH", pub_path)

    license_path = os.path.join(tmpdir, "license.json")
    issue_license("Test Customer", "standard", 5, 30, priv_path, license_path)

    # Tamper: bump seats after signing.
    import json
    with open(license_path) as fh:
        doc = json.load(fh)
    doc["terms"]["seats"] = 99999
    with open(license_path, "w") as fh:
        json.dump(doc, fh)

    status = verify_license(license_path)
    assert not status.valid
    assert "invalid" in status.reason.lower()


def test_verify_rejects_expired_license(monkeypatch):
    tmpdir = tempfile.mkdtemp()
    priv_path = os.path.join(tmpdir, "vendor_private_key.pem")
    pub_path = os.path.join(tmpdir, "vendor_public_key.pem")
    generate_vendor_keypair(priv_path, pub_path)
    monkeypatch.setattr(keygen_module, "PUBLIC_KEY_PATH", pub_path)

    license_path = os.path.join(tmpdir, "license.json")
    issue_license("Test Customer", "standard", 5, -1, priv_path, license_path)  # already expired

    status = verify_license(license_path)
    assert not status.valid
    assert "expired" in status.reason.lower()


def test_verify_missing_file_returns_invalid():
    status = verify_license("/nonexistent/license.json")
    assert not status.valid
    assert "no license file" in status.reason.lower()
