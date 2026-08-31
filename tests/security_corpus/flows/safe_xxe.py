"""SAFE fixture: defusedxml refuses DTDs and external entities."""
import defusedxml.ElementTree as SafeET


def parse_payload(body):
    return SafeET.fromstring(body)
