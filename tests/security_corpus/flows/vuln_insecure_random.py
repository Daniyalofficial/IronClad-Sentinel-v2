"""VULNERABLE fixture: a security token built from the non-crypto PRNG."""
import random


def make_reset_token():
    token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    return token
