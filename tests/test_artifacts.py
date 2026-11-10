"""Artifact mismatches must fail before verification or cache writes."""
import copy
import hashlib
import json
from pathlib import Path
import struct

import pytest

from src.config import load_config
from src.reference import A_SIGNALS
from src.protocol import artifacts


@pytest.fixture
def artifact_set(tmp_path, monkeypatch):
    root = tmp_path / 'release'
    root.mkdir()
    source = tmp_path / 'source'
    source.mkdir()
    cfg = load_config('s1')
    expected = cfg['expected']['a']
    header = struct.pack('<I', 32) + (21888242871839275222246405745257275088548364400416034343698204186575808495617).to_bytes(32, 'little')
    header += struct.pack('<IIIIQI', expected['wires'], 0, 12, expected['privateInputs'], 0, expected['constraints'])
    payload = b'r1cs' + struct.pack('<II', 1, 1) + struct.pack('<IQ', 1, len(header)) + header
    (source / 'source.r1cs').write_bytes(payload)
    cfg['expected']['a']['r1cs_sha256'] = hashlib.sha256(payload).hexdigest()
    (source / 'source.wasm').write_bytes(b'wasm-placeholder-for-header-unit-test')
    (source / 'source.sym').write_text(''.join(f'{i},{i},1,main.{name}\n' for i, name in enumerate(A_SIGNALS, 1)))
    files = {kind: dict(path=str(source / ('source.' + kind)),
             sha256=hashlib.sha256((source / ('source.' + kind)).read_bytes()).hexdigest())
             for kind in ['r1cs', 'wasm', 'sym']}
    reference = dict(status='PASS', configuration='s1', stage='A', signature='current-source',
        r1cs_sha256=cfg['expected']['a']['r1cs_sha256'], publicInputs=12)
    for kind in ['r1cs', 'wasm', 'sym']:
        copied = root / ('compiled.' + kind)
        copied.write_bytes(Path(files[kind]['path']).read_bytes())
        reference.update({kind: copied.name, kind + '_sha256': files[kind]['sha256']})
    (root / 'compile.json').write_text(json.dumps(reference))
    entry = dict(configuration='s1', stage='a', security='DEV_INSECURE',
        public_signals=list(A_SIGNALS), public_compilation='compile.json', files=files,
        source=dict(revision='test-source-revision', identity='1' * 64, tools=artifacts.TOOLS))
    recorded_source = source / 'recorded.circom'
    recorded_source.write_text('synthetic source identity test')
    digest = hashlib.sha256(recorded_source.read_bytes()).hexdigest()
    entry['source']['files'] = {'circuits/recorded.circom': dict(path=str(recorded_source), sha256=digest)}
    entry['source']['identity'] = hashlib.sha256(artifacts.canonical({'circuits/recorded.circom': digest})).hexdigest()
    monkeypatch.setattr(artifacts, 'ROOT', root)
    monkeypatch.setattr(artifacts, 'load_config', lambda identifier: copy.deepcopy(cfg))
    monkeypatch.setattr(artifacts, 'source_signature', lambda: 'current-source')
    def contained(path):
        path = Path(path)
        path = (root / path).resolve() if not path.is_absolute() else path.resolve()
        if not path.is_relative_to(root):
            raise ValueError('outside release')
        return path
    monkeypatch.setattr(artifacts, 'contained', contained)
    return root, source, entry


def test_compiled_compatibility_checks_binary_header_and_signal_order(artifact_set):
    _, _, entry = artifact_set
    cfg, stage, paths, reference, inventory = artifacts.inspect_entry(entry)
    assert cfg['id'] == 's1' and stage == 'a'
    assert set(paths) == {'r1cs', 'wasm', 'sym'}
    assert len(inventory) == 3 and reference['publicInputs'] == 12
    assert artifacts.signal_order(paths['sym'], 12) == list(A_SIGNALS)


def test_hash_change_is_rejected_before_cache_write(artifact_set):
    root, source, entry = artifact_set
    (source / 'source.r1cs').write_bytes(b'changed')
    with pytest.raises(ValueError, match='checksum mismatch'):
        artifacts.import_entry(entry)
    assert not (root / '.artifacts').exists()


def test_signal_order_substitution_is_rejected(artifact_set):
    _, _, entry = artifact_set
    entry['public_signals'][0], entry['public_signals'][1] = entry['public_signals'][1], entry['public_signals'][0]
    with pytest.raises(ValueError, match='ordering'):
        artifacts.inspect_entry(entry)


def test_missing_public_compilation_does_not_infer_s3_identity(artifact_set):
    _, _, entry = artifact_set
    entry['public_compilation'] = 'missing.json'
    with pytest.raises(ValueError, match='do not infer R1CS identity'):
        artifacts.inspect_entry(entry)


def test_public_compile_with_another_source_is_rejected(artifact_set):
    root, _, entry = artifact_set
    path = root / 'compile.json'
    record = json.loads(path.read_text())
    record['signature'] = 'different-source'
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match='current source'):
        artifacts.inspect_entry(entry)


@pytest.mark.parametrize('field,value', [('security', 'PRODUCTION'), ('stage', 'x')])
def test_invalid_classification_or_stage_rejected(artifact_set, field, value):
    _, _, entry = artifact_set
    entry[field] = value
    with pytest.raises(ValueError):
        artifacts.inspect_entry(entry)


def test_source_revision_and_tools_are_required(artifact_set):
    _, _, entry = artifact_set
    entry['source']['tools'] = dict(artifacts.TOOLS, snarkjs='0.0.0')
    with pytest.raises(ValueError, match='version mismatch'):
        artifacts.inspect_entry(entry)
    entry['source']['tools'] = artifacts.TOOLS
    entry['source']['revision'] = ''
    with pytest.raises(ValueError, match='revision'):
        artifacts.inspect_entry(entry)


def test_source_identity_cannot_be_declared_without_matching_files(artifact_set):
    _, source, entry = artifact_set
    (source / 'recorded.circom').write_text('changed source')
    with pytest.raises(ValueError, match='source inventory checksum'):
        artifacts.inspect_entry(entry)


def test_check_only_does_not_verify_keys_or_import(artifact_set, monkeypatch):
    root, _, entry = artifact_set
    monkeypatch.setattr(artifacts, 'operation', lambda *args, **kwargs: pytest.fail('verification ran'))
    result = artifacts.import_entry(entry, check_only=True)
    assert result['status'] == 'COMPATIBILITY_CHECKED'
    assert result['key_verification'] == 'NOT RUN' and not result['imported']
    assert not (root / '.artifacts').exists()


def test_existing_key_cache_rejected_before_expensive_verification(artifact_set, monkeypatch):
    root, source, entry = artifact_set
    cfg = load_config('s1')
    base = root / '.artifacts/keys/s1/a'
    base.mkdir(parents=True)
    (base / 'key.json').write_text('{}')
    paths = {kind: source / ('source.' + kind) for kind in artifacts.KINDS}
    monkeypatch.setattr(artifacts, 'inspect_entry', lambda value: (cfg, 'a', paths, {}, []))
    monkeypatch.setattr(artifacts, 'operation', lambda *args, **kwargs: pytest.fail('Verification ran'))
    with pytest.raises(ValueError, match='already exists'):
        artifacts.import_entry(entry)


def test_export_symlink_rejected_before_expensive_verification(artifact_set, monkeypatch):
    root, source, entry = artifact_set
    cfg = load_config('s1')
    base = root / '.artifacts/imports/s1/a'
    base.mkdir(parents=True)
    outside = source / 'unchanged.json'
    outside.write_text('preserved')
    (base / 'exported_vk.json').symlink_to(outside)
    paths = {kind: source / ('source.' + kind) for kind in artifacts.KINDS}
    monkeypatch.setattr(artifacts, 'inspect_entry', lambda value: (cfg, 'a', paths, {}, []))
    monkeypatch.setattr(artifacts, 'require_capacity', lambda *args: None)
    monkeypatch.setattr(artifacts, 'operation', lambda *args, **kwargs: pytest.fail('Verification ran'))
    with pytest.raises(ValueError, match='symlink'):
        artifacts.import_entry(entry)
    assert outside.read_text() == 'preserved'


def test_invalid_r1cs_field_rejected(tmp_path):
    path = tmp_path / 'wrong.r1cs'
    header = struct.pack('<I', 32) + (17).to_bytes(32, 'little')
    header += struct.pack('<IIIIQI', 12, 0, 12, 2, 0, 1)
    path.write_bytes(b'r1cs' + struct.pack('<II', 1, 1) + struct.pack('<IQ', 1, len(header)) + header)
    with pytest.raises(ValueError, match='scalar field'):
        artifacts.r1cs_header(path)
