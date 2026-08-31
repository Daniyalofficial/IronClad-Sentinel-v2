"""VULNERABLE fixture: unsafe YAML loader."""
import yaml


def load_config(raw):
    return yaml.unsafe_load(raw)
