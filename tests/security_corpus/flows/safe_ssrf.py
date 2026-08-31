"""SAFE fixture: the request target is a fixed constant."""
import requests

STATUS_URL = "https://api.internal.example.com/v1/status"


def fetch_status():
    return requests.get(STATUS_URL, timeout=5).json()
