"""Inspect the source publication set without reading ignored runtime material."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

ROOT_FILES = {
    '.gitignore', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md',
    'package.json', 'package-lock.json', 'pyproject.toml', 'requirements.txt',
    'requirements.lock', 'tsconfig.json', 'SOURCE_PROVENANCE.json',
}
DIRECTORIES = {'circuits', 'contracts', 'configs', 'src', 'data', 'scripts', 'tests'}
SUFFIXES = {'.py', '.mjs', '.js', '.ts', '.c', '.h', '.circom', '.sol', '.sh', '.json',
            '.yaml', '.yml', '.toml', '.lock', '.in', '.txt', '.md'}
IGNORED = {
    '.git', '.local', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache',
    '.ruff_cache', '.mypy_cache', '.cache', '.artifacts', '.runtime', '.validation',
    '.release-validation', '.DS_Store', '__MACOSX', 'validation', 'runs', 'outputs', 'results', 'logs',
    'private', 'artifacts', 'build', 'dist', 'coverage',
}
GENERATED_SUFFIXES = {'.wtns', '.ptau', '.zkey', '.r1cs', '.wasm', '.sym', '.pyc', '.pyo',
                      '.log', '.tmp', '.so', '.dylib', '.node', '.exe', '.zip', '.gz'}
REQUIRED = {
    'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'SOURCE_PROVENANCE.json',
    '.gitignore', 'package.json',
    'package-lock.json', 'requirements.txt', 'requirements.lock',
    'configs/s1.json', 'configs/s2.json', 'configs/s3.json',
    'circuits/s1/stage_a.circom', 'circuits/s1/stage_b.circom',
    'circuits/s2/stage_a.circom', 'circuits/s2/stage_b.circom',
    'circuits/s3/stage_a.circom', 'circuits/s3/stage_b.circom',
    'src/config.py', 'src/protocol/cli.py', 'src/protocol/engine.py',
    'src/fixtures.py', 'src/reference.py', 'src/blockchain/run.ts',
    'contracts/protocol/ExplanationCertificateRegistryV3.sol',
    'data/s1/original.json', 'data/s1/provenance.json',
    'data/s2/original.json', 'data/s2/provenance.json',
    'data/s3/original.json', 'data/s3/provenance.json',
    'scripts/setup.sh', 'scripts/run_demo.sh', 'scripts/run_benchmark.sh',
}
MAX_BYTES = 10 * 1024**2
BRANDS = ('veri' + 'concept', 'federated-zk-explanations-' + 'stress')
PUBLIC_NONCE_PREFIX = 'large-model-' + 'stress:public-chain-nonce:'
FIXTURE_PREFIX = 'stress-' + 'v1:'
NONCE_ALLOWED = {'src/blockchain/run.ts'}
FIXTURE_ALLOWED = {'src/reference.py'}
LEGACY_PREFIX = 'FL-' + 'XAI-ZKP-BC'
LEGACY_ALLOWED = {
    'contracts/protocol/InputCommitmentRegistryV3.sol',
    'contracts/protocol/StateCertificationRegistryV3.sol',
    'contracts/protocol/ExplanationCertificateRegistryV3.sol',
    'src/blockchain/run.ts',
}
SECRET_PATTERNS = (
    re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{40,}\b'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'''(?i)(?:private_?key|mnemonic|password|api_?secret)\s*[=:]\s*["'](?:0x)?[A-Za-z0-9+/=_ -]{20,}["']'''),
)
HOME_PATH = re.compile(r'/(?:Users|home)/[A-Za-z0-9_.-]+|[A-Za-z]:\\Users\\')
PRIVATE_FIELDS = {'privatekey', 'mnemonic', 'password', 'apisecret', 'modelblind',
                  'headblind', 'inputnonce', 'statenonce', 'explanationnonce',
                  'parametersq', 'xq', 'cq', 'cprimeq', 'deltawq', 'deltabq'}
PUBLIC_NUMERICAL_FILES = {
    f'data/{configuration}/{filename}.json'
    for configuration in ['s1', 's2', 's3']
    for filename in ['original', 'example', 'recovered_preparation']
}


def issue(issues, name, reason, line=None):
    item = dict(file=name, reason=reason)
    if line is not None:
        item['line'] = line
    issues.append(item)


def allowed(name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        return False
    if any(part in IGNORED for part in path.parts) or path.suffix in GENERATED_SUFFIXES:
        return False
    if len(path.parts) == 1:
        return name in ROOT_FILES
    return path.parts[0] in DIRECTORIES and (path.suffix in SUFFIXES or path.name == 'COPYING')


def collect(root, issues):
    files = {}
    excluded = 0
    for folder, dirs, names in os.walk(root, followlinks=False):
        current = Path(folder)
        kept = []
        for name in sorted(dirs):
            path = current / name
            relative = path.relative_to(root).as_posix()
            if name in IGNORED:
                excluded += 1
            elif path.is_symlink():
                issue(issues, relative, 'Source directory symlink is not portable')
            elif current == root and name not in DIRECTORIES:
                issue(issues, relative, 'Directory outside the source allowlist')
            else:
                kept.append(name)
        dirs[:] = kept
        for name in sorted(names):
            path = current / name
            relative = path.relative_to(root).as_posix()
            if name in IGNORED:
                excluded += 1
                continue
            if path.is_symlink():
                issue(issues, relative, 'Source file symlink is not portable')
                continue
            if not allowed(relative):
                issue(issues, relative, 'File outside the source allowlist')
                continue
            if path.stat().st_size > MAX_BYTES:
                issue(issues, relative, 'Oversized source file')
                continue
            files[relative] = path.read_bytes()
    return files, excluded


def target_module(path, root, files):
    path = path.resolve()
    if not path.is_relative_to(root):
        return False
    name = path.relative_to(root).as_posix()
    return name + '.py' in files or any(key.startswith(name + '/') and key.endswith('.py') for key in files)


def python_imports(root, name, text, files, issues):
    try:
        tree = ast.parse(text, filename=name)
    except SyntaxError as error:
        issue(issues, name, 'Invalid Python syntax', error.lineno)
        return
    local = {Path(key).parts[0] for key in files if key.endswith('.py') and '/' in key}
    dependencies = {'eth_hash', 'Crypto', 'pytest'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [entry.name for entry in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = (root / name).parent
                for _ in range(node.level - 1):
                    base = base.parent
                if not base.is_relative_to(root):
                    issue(issues, name, 'Relative Python import escapes the release', node.lineno)
                    continue
                target = base.joinpath(*(node.module or '').split('.'))
                if not target_module(target, root, files):
                    issue(issues, name, 'Missing relative Python module', node.lineno)
                continue
            modules = [node.module] if node.module else []
        else:
            continue
        for module in modules:
            head = module.split('.')[0]
            if head in local:
                if not target_module(root.joinpath(*module.split('.')), root, files):
                    issue(issues, name, 'Missing local Python module', node.lineno)
            elif head not in sys.stdlib_module_names and head not in dependencies:
                issue(issues, name, 'Undeclared Python import', node.lineno)


def includes(root, name, text, files, packages, issues):
    if name.endswith('.circom'):
        imports = re.findall(r'\binclude\s+"([^"]+)"', text)
    elif name.endswith(('.ts', '.js', '.mjs', '.sol')):
        imports = re.findall(r'''\b(?:from\s*|import\s*\(|require(?:\.resolve)?\s*\()\s*["']([^"']+)["']''', text)
        imports += re.findall(r'''\bimport\s*["']([^"']+)["']''', text)
    else:
        return
    for specifier in imports:
        if specifier.startswith('node:'):
            continue
        if specifier.startswith('.') or (name.endswith('.circom') and not specifier.startswith('circomlib/')):
            target = ((root / name).parent / specifier).resolve()
            if not target.is_relative_to(root):
                issue(issues, name, 'Local import/include escapes the release')
                continue
            candidates = [target]
            if target.suffix == '.js':
                candidates.append(target.with_suffix('.ts'))
            if not target.suffix:
                candidates += [target.with_suffix(ext) for ext in ('.ts', '.js', '.mjs')]
            if not any(p.relative_to(root).as_posix() in files for p in candidates):
                issue(issues, name, 'Missing local import/include')
        else:
            parts = specifier.split('/')
            package = '/'.join(parts[:2]) if specifier.startswith('@') else parts[0]
            if package not in packages:
                issue(issues, name, 'Undeclared JavaScript/Circom dependency')


def private_json(value):
    if isinstance(value, dict):
        return any(re.sub(r'[_-]', '', key.lower()) in PRIVATE_FIELDS or private_json(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(private_json(item) for item in value)
    return False


def public_synthetic_json(name, raw, files):
    if name not in PUBLIC_NUMERICAL_FILES:
        return False
    try:
        from src.workloads import validate
        configuration = Path(name).parts[1]
        cfg = json.loads(files[f'configs/{configuration}.json'])
        provenance = json.loads(files[f'data/{configuration}/provenance.json'])
        if provenance['public_data_classification'] != 'NON_CONFIDENTIAL_SYNTHETIC_TEST_DATA':
            return False
        if provenance['public_files'][Path(name).name] != hashlib.sha256(raw).hexdigest():
            return False
        validate(cfg, json.loads(raw))
        return True
    except (KeyError, TypeError, ValueError):
        return False


def audit(root=ROOT, require_complete=True):
    root = Path(root).resolve()
    issues = []
    files, excluded = collect(root, issues)
    if require_complete:
        for name in sorted(REQUIRED - files.keys()):
            issue(issues, name, 'Required publication file missing')
    packages = {}
    if 'package.json' in files:
        try:
            manifest = json.loads(files['package.json'])
            packages = dict(manifest.get('dependencies', {})) | dict(manifest.get('devDependencies', {}))
        except (ValueError, TypeError):
            issue(issues, 'package.json', 'Invalid package manifest')
    if 'package-lock.json' in files:
        try:
            locked = json.loads(files['package-lock.json'])
            for path in locked.get('packages', {}):
                if 'node_modules/' in path:
                    packages[path.rsplit('node_modules/', 1)[1]] = None
        except (ValueError, TypeError):
            issue(issues, 'package-lock.json', 'Invalid dependency lockfile')
    for name, raw in sorted(files.items()):
        try:
            text = raw.decode('utf8')
        except UnicodeDecodeError:
            issue(issues, name, 'Binary content in source publication set')
            continue
        if re.search(r'(?:^|/)(?:baseline|comparisons|historical|phase\d+)(?:[_.\-/]|$)', name, re.I):
            issue(issues, name, 'Excluded comparison or historical source path')
        for line, value in enumerate(text.splitlines(), 1):
            if any(brand in value.lower() for brand in BRANDS):
                issue(issues, name, 'Unnecessary previous repository branding', line)
            if LEGACY_PREFIX in value:
                cleaned = re.sub(re.escape(LEGACY_PREFIX) + r':(?:REQUEST|STATE|CERTIFICATE|\$\{n\}):v3', '', value)
                if name not in LEGACY_ALLOWED or LEGACY_PREFIX in cleaned:
                    issue(issues, name, 'Legacy name outside an exact functional domain', line)
            if 'large-model-' + 'stress' in value:
                remainder = value.replace(PUBLIC_NONCE_PREFIX, '') if name in NONCE_ALLOWED else value
                if 'large-model-' + 'stress' in remainder:
                    issue(issues, name, 'Nonce label outside its retained functional preimage', line)
            if FIXTURE_PREFIX in value and name not in FIXTURE_ALLOWED:
                issue(issues, name, 'Fixture label outside its retained functional preimage', line)
            if HOME_PATH.search(value):
                issue(issues, name, 'Machine-specific home path', line)
            if any(pattern.search(value) for pattern in SECRET_PATTERNS):
                issue(issues, name, 'Possible embedded credential; value withheld', line)
        if name.endswith('.json'):
            try:
                if private_json(json.loads(text)) and not public_synthetic_json(name, raw, files):
                    issue(issues, name, 'Private witness/opening fields in public JSON')
            except ValueError:
                issue(issues, name, 'Invalid JSON')
        if name.endswith('.py'):
            python_imports(root, name, text, files, issues)
        includes(root, name, text, files, packages, issues)
    return dict(status='FAIL' if issues else 'PASS', source_files_inspected=len(files),
                source_bytes=sum(map(len, files.values())), excluded_entries=excluded,
                issues=issues, source_sha256={name: hashlib.sha256(raw).hexdigest()
                                             for name, raw in sorted(files.items())},
                scope='Positive-allowlist source review; static imports/includes and targeted secret checks',
                limits='Does not prove absence of all secrets or validate dynamic import/runtime behavior',
                public_redistribution_rights_cleared=False, license_status='AUTHOR_LICENSE_PENDING',
                git_operations_performed=False, files_modified=False, network_contacted=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    result = audit()
    print(json.dumps(result, sort_keys=True, indent=2))
    raise SystemExit(0 if result['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
