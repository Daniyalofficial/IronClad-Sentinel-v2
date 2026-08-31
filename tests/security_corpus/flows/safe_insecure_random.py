"""SAFE fixture: secrets module for security values; random for shuffling test data."""
import random
import secrets


def make_reset_token():
    return secrets.token_urlsafe(32)


def shuffle_sample_rows(rows):
    random.shuffle(rows)
    return rows
