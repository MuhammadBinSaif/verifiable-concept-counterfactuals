"""Source publication boundaries and static dependency closure."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_audit', ROOT / 'scripts/audit_release.py')
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_audit_cli_loads_fixed_data_without_pythonpath(tmp_path):
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/audit_release.py')],
        cwd=tmp_path, env=environment, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'PASS'


def test_runtime_material_is_excluded_without_being_read(tmp_path):
    write(tmp_path, 'src/__init__.py', '')
    write(tmp_path, 'src/example.py', 'import json\n')
    folders = ['.validation', 'validation', '__MACOSX', '.cache', '.artifacts', '.runtime',
               'runs', 'node_modules', '.venv']
    for folder in folders:
        write(tmp_path, folder + '/unpublished.txt', 'not public')
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert result['status'] == 'PASS'
    assert result['source_files_inspected'] == 2
    assert result['excluded_entries'] == len(folders)
    assert all(name.startswith('src/') for name in result['source_sha256'])


@pytest.mark.parametrize('name', ['../escape.py', '/absolute.py', 'src/private.zkey',
                                  '.env', '.artifacts/key.json', 'unapproved.txt'])
def test_allowlist_rejects_escaping_runtime_and_unapproved_paths(name):
    assert not AUDIT.allowed(name)


def test_source_symlink_is_rejected(tmp_path):
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src/escape.py').symlink_to(tmp_path.parent / 'outside.py')
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert result['status'] == 'FAIL'
    assert any('symlink' in item['reason'] for item in result['issues'])


def test_missing_and_escaping_circuit_includes_fail(tmp_path):
    write(tmp_path, 'circuits/stage_a.circom', 'include "../outside/missing.circom";\n')
    write(tmp_path, 'circuits/stage_b.circom', 'include "../../escape.circom";\n')
    result = AUDIT.audit(tmp_path, require_complete=False)
    reasons = [item['reason'] for item in result['issues']]
    assert 'Missing local import/include' in reasons
    assert 'Local import/include escapes the release' in reasons


def test_missing_local_python_module_and_undeclared_package_fail(tmp_path):
    write(tmp_path, 'src/__init__.py', '')
    write(tmp_path, 'src/example.py', 'from src.missing import value\nimport unpublished_package\n')
    reasons = [item['reason'] for item in AUDIT.audit(tmp_path, require_complete=False)['issues']]
    assert 'Missing local Python module' in reasons
    assert 'Undeclared Python import' in reasons


def test_private_json_branding_and_machine_paths_are_reported_without_values(tmp_path):
    write(tmp_path, 'configs/private.json', '{"explanation' + 'Nonce": "123456789"}')
    write(tmp_path, 'README.md', 'Veri' + 'Concept-FL\n' + '/' + 'Users/' + 'private-user/source\n')
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert result['status'] == 'FAIL'
    reasons = [item['reason'] for item in result['issues']]
    assert 'Private witness/opening fields in public JSON' in reasons
    assert 'Unnecessary previous repository branding' in reasons
    assert 'Machine-specific home path' in reasons
    assert '123456789' not in str(result)
    assert 'private-user' not in str(result)


def test_only_validated_public_synthetic_values_are_allowed(tmp_path):
    cfg = json.loads((ROOT / 'configs/s1.json').read_text())
    raw = (ROOT / 'data/s1/original.json').read_bytes()
    provenance = json.loads((ROOT / 'data/s1/provenance.json').read_text())
    write(tmp_path, 'configs/s1.json', json.dumps(cfg))
    write(tmp_path, 'data/s1/original.json', raw.decode())
    write(tmp_path, 'data/s1/provenance.json', json.dumps(provenance))
    assert AUDIT.audit(tmp_path, require_complete=False)['status'] == 'PASS'
    value = json.loads(raw)
    value['explanationNonce'] = 12345
    changed = json.dumps(value)
    provenance['public_files']['original.json'] = hashlib.sha256(changed.encode()).hexdigest()
    write(tmp_path, 'data/s1/original.json', changed)
    write(tmp_path, 'data/s1/provenance.json', json.dumps(provenance))
    issues = AUDIT.audit(tmp_path, require_complete=False)['issues']
    assert any(item['reason'] == 'Private witness/opening fields in public JSON' for item in issues)


def test_secret_format_is_reported_without_echoing_secret(tmp_path):
    secret = '-----BEGIN ' + 'PRIVATE KEY-----'
    write(tmp_path, 'README.md', secret)
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert any('credential' in item['reason'] for item in result['issues'])
    assert secret not in str(result)


def test_legacy_domain_exception_is_exact_and_file_scoped(tmp_path):
    domain = 'FL-' + 'XAI-ZKP-BC:STATE:v3'
    write(tmp_path, 'contracts/protocol/StateCertificationRegistryV3.sol', 'string constant DOMAIN = "' + domain + '";')
    assert AUDIT.audit(tmp_path, require_complete=False)['status'] == 'PASS'
    write(tmp_path, 'README.md', domain)
    assert any('Legacy name' in item['reason'] for item in AUDIT.audit(tmp_path, require_complete=False)['issues'])


def test_comparison_source_and_generated_file_are_rejected(tmp_path):
    write(tmp_path, 'src/baseline.py', 'value = 1\n')
    write(tmp_path, 'src/source.wasm', 'generated')
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert result['status'] == 'FAIL'
    reasons = [item['reason'] for item in result['issues']]
    assert 'Excluded comparison or historical source path' in reasons
    assert 'File outside the source allowlist' in reasons


def test_complete_source_audit_requires_protocol_inputs(tmp_path):
    result = AUDIT.audit(tmp_path)
    assert result['status'] == 'FAIL'
    assert result['source_files_inspected'] == 0
    assert any(item['file'] == 'configs/s3.json' for item in result['issues'])


def test_import_cannot_depend_on_excluded_runtime_module(tmp_path):
    write(tmp_path, 'src/__init__.py', '')
    write(tmp_path, 'src/example.py', 'from .private.hidden import value\n')
    write(tmp_path, 'src/private/hidden.py', 'value = 1\n')
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert result['status'] == 'FAIL'
    assert any(item['reason'] == 'Missing relative Python module' for item in result['issues'])
    assert 'src/private/hidden.py' not in result['source_sha256']


@pytest.mark.parametrize('prefix', ['large-model-' + 'stress:public-chain-nonce:', 'stress-' + 'v1:'])
def test_functional_seed_and_nonce_labels_are_not_display_branding(tmp_path, prefix):
    write(tmp_path, 'README.md', prefix)
    result = AUDIT.audit(tmp_path, require_complete=False)
    assert result['status'] == 'FAIL'
    assert any('functional preimage' in item['reason'] for item in result['issues'])
