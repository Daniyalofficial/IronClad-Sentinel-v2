from pathlib import Path


def vulnerable(base, user_path):
    return Path(base, user_path).read_text()


def safe(base, user_path):
    root = Path(base).resolve()
    candidate = (root / user_path).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError("path escapes root")
    return candidate.read_text()
