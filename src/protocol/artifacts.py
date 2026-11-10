"""Check local development artifacts before installing compatible runtime caches."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil
import struct

from src.config import ROOT, load_config
from src.reference import A_SIGNALS, b_signals
from src.protocol.engine import ptau_power
from src.protocol.io import canonical, contained, load, output_file, rel, save, sha
from src.protocol.measure import operation, require
from src.protocol.resources import require_capacity

KINDS = {'r1cs', 'wasm', 'sym', 'zkey', 'ptau', 'vk', 'sol'}
COMPILED_KINDS = {'r1cs', 'wasm', 'sym'}
TOOLS = {'circom': '2.2.3', 'snarkjs': '0.7.6', 'circomlib': '2.0.5'}


def source_signature():
    return hashlib.sha256(canonical({rel(path): sha(path) for path in
        sorted((ROOT / 'circuits').rglob('*.circom'))})).hexdigest()


def verify_source_identity(source):
    records = source.get('files')
    if type(records) is not dict or not records or len(records) > 2000:
        raise ValueError('Research source file inventory required')
    hashes = {}
    for name, record in records.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or not relative.parts:
            raise ValueError('Source identity requires normalized relative file names')
        if relative.as_posix() != name or type(record) is not dict:
            raise ValueError('Invalid source identity inventory')
        path = Path(record.get('path', ''))
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise ValueError('Research source inventory path is not a regular file')
        digest = sha(path)
        if digest != record.get('sha256'):
            raise ValueError('Research source inventory checksum mismatch')
        hashes[name] = digest
    if hashlib.sha256(canonical(hashes)).hexdigest() != source.get('identity'):
        raise ValueError('Research source identity does not match its file inventory')


def r1cs_header(path):
    with Path(path).open('rb') as stream:
        if stream.read(4) != b'r1cs':
            raise ValueError('Invalid R1CS file')
        version, count = struct.unpack('<II', stream.read(8))
        if version != 1 or count > 100:
            raise ValueError('Unsupported R1CS format')
        for _ in range(count):
            section, size = struct.unpack('<IQ', stream.read(12))
            position = stream.tell()
            if section == 1:
                field_size = struct.unpack('<I', stream.read(4))[0]
                if field_size != 32:
                    raise ValueError('Expected BN254 scalar-field R1CS')
                field = int.from_bytes(stream.read(field_size), 'little')
                wires, outputs, public, private = struct.unpack('<IIII', stream.read(16))
                stream.read(8)
                constraints = struct.unpack('<I', stream.read(4))[0]
                if field != 21888242871839275222246405745257275088548364400416034343698204186575808495617:
                    raise ValueError('Unexpected R1CS scalar field')
                return dict(wires=wires, publicOutputs=outputs, publicInputs=public,
                            privateInputs=private, constraints=constraints)
            stream.seek(position + size)
    raise ValueError('R1CS header section missing')


def signal_order(path, count):
    public = {}
    with Path(path).open() as stream:
        for line in stream:
            fields = line.rstrip('\n').split(',', 3)
            if len(fields) != 4:
                raise ValueError('Invalid symbol record')
            wire = int(fields[1])
            if 1 <= wire <= count and fields[3].startswith('main.'):
                name = fields[3][5:]
                # Aliased inner signals do not determine the public entrypoint ABI.
                if '.' not in name:
                    if wire in public and public[wire] != name:
                        raise ValueError('Conflicting public wire names')
                    public[wire] = name
    if set(public) != set(range(1, count + 1)):
        raise ValueError('Missing public entrypoint symbols')
    return [public[index] for index in range(1, count + 1)]


def inspect_entry(entry):
    if type(entry) is not dict or entry.get('stage') not in {'a', 'b'}:
        raise ValueError('Artifact entry requires configuration and stage a or b')
    cfg, stage = load_config(entry.get('configuration')), entry['stage']
    expected = cfg['expected'][stage]
    if entry.get('security') != 'DEV_INSECURE':
        raise ValueError('Only explicitly classified development keys are supported')
    source = entry.get('source', {})
    if not isinstance(source.get('revision'), str) or not source['revision']:
        raise ValueError('Research source revision is required')
    if not re.fullmatch(r'[0-9a-f]{64}', str(source.get('identity', ''))):
        raise ValueError('Research source identity must be a SHA-256 digest')
    verify_source_identity(source)
    if any(source.get('tools', {}).get(key) != value for key, value in TOOLS.items()):
        raise ValueError('Artifact compiler or cryptographic dependency version mismatch')
    records = entry.get('files')
    if type(records) is not dict or set(records) not in [KINDS, COMPILED_KINDS]:
        raise ValueError('Supply compiled artifacts alone or the complete key/setup/verifier set')
    paths, inventory = {}, []
    for kind, record in sorted(records.items()):
        if type(record) is not dict or not isinstance(record.get('path'), str):
            raise ValueError('Artifact source path required')
        raw = Path(record['path']).expanduser()
        if not raw.is_absolute() or raw.is_symlink() or not raw.is_file():
            raise ValueError('Artifact source must be an absolute regular-file path')
        path = raw.resolve()
        if not re.fullmatch(r'[0-9a-f]{64}', str(record.get('sha256', ''))):
            raise ValueError('Artifact checksum required')
        digest = sha(path)
        if digest != record['sha256']:
            raise ValueError('Artifact checksum mismatch: ' + kind)
        paths[kind] = path
        inventory.append(dict(type=kind, source_path=str(path), sha256=digest,
                              bytes=path.stat().st_size))
    if sha(paths['r1cs']) != expected['r1cs_sha256']:
        raise ValueError('R1CS differs from the configuration-specific relation')
    info = r1cs_header(paths['r1cs'])
    if any(info[key] != expected[key] for key in info if key in expected):
        raise ValueError('R1CS dimensions differ from the configured relation')
    names = list(A_SIGNALS if stage == 'a' else b_signals(cfg))
    if entry.get('public_signals') != names or signal_order(paths['sym'], len(names)) != names:
        raise ValueError('Public signal count or ordering mismatch')
    reference_path = entry.get('public_compilation')
    if not isinstance(reference_path, str):
        raise ValueError('A compatible compilation of the public source is required')
    reference_path = contained(reference_path)
    if not reference_path.is_file():
        raise ValueError('Public compilation record not available; do not infer R1CS identity')
    reference = load(reference_path)
    if (reference.get('status') != 'PASS' or reference.get('configuration') != cfg['id']
        or reference.get('stage') != stage.upper() or reference.get('signature') != source_signature()
        or reference.get('r1cs_sha256') != expected['r1cs_sha256']):
        raise ValueError('Public compilation record is incompatible with the current source')
    for kind in ['r1cs', 'wasm', 'sym']:
        reference_file = contained(reference[kind])
        if sha(reference_file) != reference[kind + '_sha256']:
            raise ValueError('Public compilation artifact changed')
    if sha(paths['r1cs']) != sha(contained(reference['r1cs'])):
        raise ValueError('Public and imported R1CS are not byte-identical')
    if 'ptau' in paths and ptau_power(paths['ptau']) < expected['required_power']:
        raise ValueError('Setup transcript capacity is insufficient')
    return cfg, stage, paths, reference, inventory


def import_entry(entry, check_only=False):
    cfg, stage, paths, reference, inventory = inspect_entry(entry)
    result = dict(configuration=cfg['id'], stage=stage.upper(), status='COMPATIBILITY_CHECKED',
        security='DEV_INSECURE', source=entry['source'], circuit_hash=cfg['expected'][stage]['r1cs_sha256'],
        artifacts=inventory, public_signal_order_verified=True,
        current_public_compilation_verified=True, key_verification='NOT RUN', imported=False)
    if check_only:
        return result
    if set(paths) == COMPILED_KINDS:
        result.update(status='PASS', imported=False,
                      compiled_artifacts='PASS: matching public compilation already available')
        base = contained(ROOT / '.artifacts/imports' / cfg['id'] / stage)
        save(base / 'compiled_check.json', result)
        return result
    key_base = contained(ROOT / '.artifacts/keys' / cfg['id'] / stage)
    if (key_base / 'key.json').exists():
        raise ValueError('Key cache already exists; retain it before importing another key')
    require_capacity(cfg, 'artifact_verify', stage)
    base = contained(ROOT / '.artifacts/imports' / cfg['id'] / stage)
    base.mkdir(parents=True, exist_ok=True)
    exported_vk = output_file(base / 'exported_vk.json')
    exported_sol = output_file(base / 'exported_verifier.sol')
    reserve = sum(path.stat().st_size for path in paths.values()) + 4 * 1024**3
    if shutil.disk_usage(ROOT).free < reserve:
        raise RuntimeError('Insufficient free disk for checked artifact import')
    costs = []
    phase1 = entry.get('phase1_verification')
    phase1_reused = False
    if phase1 is not None:
        if (type(phase1) is not dict or not isinstance(phase1.get('path'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', str(phase1.get('sha256', '')))):
            raise ValueError('Exact phase-1 verification record path and checksum required')
        marker = Path(phase1['path'])
        if not marker.is_absolute() or marker.is_symlink() or sha(marker) != phase1['sha256']:
            raise ValueError('Phase-1 verification record checksum mismatch')
        record = load(marker)
        observation = record.get('verification', {})
        if (record.get('valid') is not True or record.get('sha256') != sha(paths['ptau'])
            or observation.get('exit_code') != 0 or observation.get('measurement_type') != 'ACTUAL'):
            raise ValueError('Phase-1 record does not attest full verification of this exact transcript')
        phase1_reused = True
    requests = [] if phase1_reused else [('phase1', dict(op='ptau-verify', input=str(paths['ptau'])))]
    requests.append(('key', dict(op='key-verify', r1cs=str(paths['r1cs']),
                    ptau=str(paths['ptau']), zkey=str(paths['zkey']))))
    for label, request in requests:
        response, cost = operation('artifact_' + label, request, timeout=86400)
        require(response, 'valid', True)
        costs.append(dict(operation=label, **cost))
    response, cost = operation('artifact_export', dict(op='export', zkey=str(paths['zkey']),
        vk=str(exported_vk), solidity=str(exported_sol),
        contract='StateGroth16VerifierV3' if stage == 'a' else 'ExplanationGroth16VerifierV3'))
    require(response)
    costs.append(dict(operation='export', **cost))
    if load(exported_vk) != load(paths['vk']):
        raise ValueError('Verification key does not match the imported proving key')
    if exported_sol.read_text().strip() != paths['sol'].read_text().strip():
        raise ValueError('Solidity verifier differs from the proving-key export')
    vk = load(exported_vk)
    if vk.get('protocol') != 'groth16' or vk.get('curve') not in {'bn128', 'bn254'} or vk.get('nPublic') != reference['publicInputs']:
        raise ValueError('Verification key protocol, curve or public layout mismatch')
    if len(vk.get('IC', [])) != reference['publicInputs'] + 1:
        raise ValueError('Verification key public-input basis mismatch')
    key_base = contained(ROOT / '.artifacts/keys' / cfg['id'] / stage)
    marker = key_base / 'key.json'
    if marker.exists():
        raise ValueError('Key cache already exists; retain it and choose another cache location')
    key_base.mkdir(parents=True, exist_ok=True)
    key_record = dict(status='PASS', security='DEV_INSECURE',
        r1cs_sha256=cfg['expected'][stage]['r1cs_sha256'], ptau_sha256=sha(paths['ptau']),
        operations=costs, preparation_origin='Verified local artifact import',
        key_verification='PASS', source_revision=entry['source']['revision'],
        source_identity=entry['source']['identity'], tool_versions=entry['source']['tools'])
    key_record['verification'] = dict(status='PASS', r1cs_sha256=cfg['expected'][stage]['r1cs_sha256'],
        ptau_sha256=sha(paths['ptau']), zkey_sha256=sha(paths['zkey']),
        verification_key_export='PASS', solidity_verifier_export='PASS',
        phase1_verification_reused=phase1_reused, phase1_verification_record=phase1,
        operations=costs)
    for kind, filename in [('zkey', 'DEV_INSECURE.zkey'), ('vk', 'verification_key.json'), ('sol', 'verifier.sol')]:
        target = contained(key_base / filename)
        if target.exists():
            raise ValueError('Refusing to overwrite a retained artifact')
        shutil.copyfile(paths[kind], target)
        target.chmod(0o600 if kind == 'zkey' else 0o644)
        digest = sha(target)
        if digest != sha(paths[kind]):
            raise RuntimeError('Imported artifact checksum changed during copy')
        key_record.update({kind: rel(target), kind + '_sha256': digest,
                           kind + '_bytes': target.stat().st_size})
    save(marker, key_record)
    result.update(status='PASS', key_verification='PASS', verification_key_export='PASS',
                  solidity_verifier_export='PASS', phase1_verification_reused=phase1_reused,
                  imported=True, measurements=costs)
    save(base / 'import.json', result)
    return result


def run_manifest(path, check_only=False):
    manifest = load(path)
    if manifest.get('schema') != 1 or type(manifest.get('entries')) is not list or not manifest['entries']:
        raise ValueError('Artifact manifest schema 1 requires nonempty entries')
    seen = set()
    results = []
    for entry in manifest['entries']:
        identity = entry.get('configuration'), entry.get('stage')
        if identity in seen:
            raise ValueError('Duplicate configuration/stage artifact entry')
        seen.add(identity)
        results.append(import_entry(entry, check_only))
    return dict(status='PASS', check_only=check_only, entries=results,
                security='DEV_INSECURE', network_contacted=False)
