"""Repository-local output paths and canonical JSON."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from src.config import ROOT


def contained(path):
    path = Path(path)
    path = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if not path.is_relative_to(ROOT.resolve()) or path == ROOT.resolve():
        raise ValueError('Output must remain inside the release directory')
    return path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def output_file(path):
    raw = Path(path)
    raw = ROOT / raw if not raw.is_absolute() else raw
    if raw.is_symlink():
        raise ValueError('Refusing symlink output file')
    return contained(raw)


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value, private=False):
    path = output_file(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if private:
        path.parent.chmod(0o700)
    temporary = path.with_name(path.name + '.tmp')
    if temporary.is_symlink():
        raise ValueError('Refusing symlink temporary output')
    with temporary.open('wb') as stream:
        temporary.chmod(0o600 if private else 0o644)
        stream.write(canonical(value) + b'\n')
    temporary.replace(path)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(8 * 1024**2), b''):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path):
    return str(Path(path).resolve().relative_to(ROOT.resolve()))


def portable(value):
    if isinstance(value, dict):
        return {k: portable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [portable(v) for v in value]
    return str(value) if type(value) is int else value
