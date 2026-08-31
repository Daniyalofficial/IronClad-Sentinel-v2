"""VULNERABLE fixture: a PEM private key committed to source control.

The key below is a throwaway generated for this fixture, not a real
credential -- but its shape is what the detector matches on.
"""

SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0FictionalKeyMaterialForTestingPurposesOnly0000000000
FictionalKeyMaterialForTestingPurposesOnly000000000000000000000000000000000
-----END RSA PRIVATE KEY-----"""
