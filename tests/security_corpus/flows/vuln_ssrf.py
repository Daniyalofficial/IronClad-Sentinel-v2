"""VULNERABLE fixture: request target is attacker controlled."""
import requests
from flask import request


def proxy():
    url = request.args.get("url")
    return requests.get(url).text


def fetch_avatar():
    return requests.get("https://images.example.com/" + request.args["id"]).content
