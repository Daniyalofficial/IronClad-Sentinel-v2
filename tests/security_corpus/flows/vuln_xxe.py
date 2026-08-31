"""VULNERABLE fixture: XML parsed with an entity-resolving parser."""
import xml.etree.ElementTree as ET


def parse_payload(body):
    return ET.fromstring(body)
