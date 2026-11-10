"""Compile the configured relation and execute individual Groth16 proofs."""
from __future__ import annotations

import copy
import hashlib
import secrets
import struct
from pathlib import Path
from src.config import ROOT
from src.reference import FIELD, public_signals
from src.protocol.io import canonical, contained, load, output_file, portable, rel, save, sha
from src.protocol.measure import measure, operation, require
from src.protocol.resources import require_capacity


def compile_stage(cfg, stage):
    source = ROOT / cfg['circuits'][stage]
    base = output_file(ROOT / '.artifacts/build' / cfg['id'] / stage)
    base.mkdir(parents=True, exist_ok=True)
    signature = hashlib.sha256(canonical({rel(p): sha(p) for p in
        sorted((ROOT / 'circuits').rglob('*.circom'))})).hexdigest()
    marker = base / 'compile.json'
    if marker.exists():
        record = load(marker)
        if record['signature'] != signature:
            raise RuntimeError('Circuit source changed; retain and relocate the previous build')
        if record['r1cs_sha256'] != cfg['expected'][stage]['r1cs_sha256']:
            raise RuntimeError('Cached R1CS differs from the configured relation')
        if any(sha(ROOT / record[k]) != record[k + '_sha256'] for k in ['r1cs', 'wasm', 'sym']):
            raise RuntimeError('Compiled artifact checksum changed')
        return dict(record, reused=True)
    stem = source.stem
    generated = output_file(base / (stem + '_js'))
    paths = dict(r1cs=output_file(base / (stem + '.r1cs')),
        wasm=output_file(generated / (stem + '.wasm')),
        sym=output_file(base / (stem + '.sym')))
    # Circom writes these fixed leaves directly.
    for name in ['witness_calculator.js', 'generate_witness.js', 'package.json']:
        output_file(generated / name)
    require_capacity(cfg, 'compile', stage)
    _, cost = measure('compile_' + cfg['id'] + '_' + stage,
        ['circom', str(source), '--O1', '--r1cs', '--wasm', '--sym', '--inspect',
         '-l', str(ROOT / 'node_modules'), '-o', str(base)], timeout=14400)
    output_file(generated / 'package.json').write_text('{"type":"commonjs"}')
    info, _ = operation('info', dict(op='info', r1cs=str(paths['r1cs'])))
    expected = cfg['expected'][stage]
    if any(info[k] != expected[k] for k in
           ['constraints', 'wires', 'publicInputs', 'privateInputs', 'publicOutputs'] if k in expected):
        raise RuntimeError('Compiled dimensions differ from the source relation')
    record = dict(status='PASS', configuration=cfg['id'], stage=stage.upper(),
        signature=signature, compilation=cost, required_power=expected['required_power'], **info)
    for key, path in paths.items():
        record.update({key: rel(path), key + '_sha256': sha(path), key + '_bytes': path.stat().st_size})
    if record['r1cs_sha256'] != expected['r1cs_sha256']:
        raise RuntimeError('R1CS is not byte-identical to the tested source relation')
    save(marker, record)
    return dict(record, reused=False)


def ptau_power(path):
    with Path(path).open('rb') as stream:
        if stream.read(4) != b'ptau':
            raise ValueError('Invalid Powers of Tau file')
        version, sections = struct.unpack('<II', stream.read(8))
        power = None
        kinds = set()
        for _ in range(sections):
            kind, length = struct.unpack('<IQ', stream.read(12))
            start = stream.tell()
            kinds.add(kind)
            if kind == 1:
                size = struct.unpack('<I', stream.read(4))[0]
                stream.seek(size, 1)
                power = struct.unpack('<I', stream.read(4))[0]
            stream.seek(start + length)
    if version != 1 or power is None or not {12, 13, 14, 15}.issubset(kinds):
        raise ValueError('Prepared phase-2 sections required')
    return power


def phase_one(cfg, stage, compiled, provided=None):
    require_capacity(cfg, 'setup', stage)
    power = compiled['required_power']
    base = contained(ROOT / '.artifacts/setup')
    base.mkdir(parents=True, exist_ok=True)
    path = contained(provided) if provided else output_file(base / f'DEV_INSECURE_power{power}.ptau')
    if not path.exists():
        if provided:
            raise FileNotFoundError('Copy the supplied prepared setup into the release directory')
        initial, contributed = [output_file(base / name) for name in
            [f'power{power}_initial.ptau', f'power{power}_contributed.ptau']]
        requests = [dict(op='ptau-new', power=power, output=str(initial)),
            dict(op='ptau-contribute', input=str(initial), output=str(contributed), entropy=secrets.token_hex(64)),
            dict(op='ptau-prepare', input=str(contributed), output=str(path))]
        for request in requests:
            result, _ = operation(request['op'], request, timeout=86400)
            require(result)
        initial.unlink()
        contributed.unlink()
    if ptau_power(path) < power:
        raise ValueError('Powers of Tau capacity is too small for this circuit')
    digest = sha(path)
    marker = base / (digest + '.verified.json')
    if not marker.exists() or load(marker).get('sha256') != digest or not load(marker).get('valid'):
        result, cost = operation('verify_phase1', dict(op='ptau-verify', input=str(path)), timeout=86400)
        require(result, 'valid', True)
        save(marker, dict(valid=True, sha256=digest, power=ptau_power(path), verification=cost,
                          security='DEV_INSECURE'))
    return path


def setup_stage(cfg, stage, compiled, provided=None):
    base = contained(ROOT / '.artifacts/keys' / cfg['id'] / stage)
    base.mkdir(parents=True, exist_ok=True)
    marker = base / 'key.json'
    if marker.exists():
        record = load(marker)
        if record['r1cs_sha256'] != compiled['r1cs_sha256']:
            raise RuntimeError('Key belongs to another R1CS')
        verification = record.get('verification', {})
        if (verification.get('status') != 'PASS'
            or verification.get('r1cs_sha256') != compiled['r1cs_sha256']
            or verification.get('zkey_sha256') != record['zkey_sha256']
            or verification.get('ptau_sha256') != record.get('ptau_sha256')):
            raise RuntimeError('Key cache lacks matching setup/key verification; use the artifact importer')
        if any(sha(ROOT / record[k]) != record[k + '_sha256'] for k in ['zkey', 'vk', 'sol']):
            raise RuntimeError('Key or verifier checksum changed')
        return dict(record, reused=True)
    initial, key, vk, sol = [output_file(base / name) for name in
        ['initial.zkey', 'DEV_INSECURE.zkey', 'verification_key.json', 'verifier.sol']]
    ptau = phase_one(cfg, stage, compiled, provided)
    requests = [dict(op='setup', r1cs=str(ROOT / compiled['r1cs']), ptau=str(ptau), output=str(initial)),
        dict(op='contribute', input=str(initial), output=str(key), entropy=secrets.token_hex(64)),
        dict(op='key-verify', r1cs=str(ROOT / compiled['r1cs']), ptau=str(ptau), zkey=str(key)),
        dict(op='export', zkey=str(key), vk=str(vk), solidity=str(sol),
             contract='StateGroth16VerifierV3' if stage == 'a' else 'ExplanationGroth16VerifierV3')]
    costs = []
    for request in requests:
        result, cost = operation('setup_' + stage + '_' + request['op'], request, timeout=86400)
        require(result, 'valid', True) if request['op'] == 'key-verify' else require(result)
        costs.append(dict(operation=request['op'], **cost))
    record = dict(status='PASS', security='DEV_INSECURE', r1cs_sha256=compiled['r1cs_sha256'],
                  ptau_sha256=sha(ptau), operations=costs)
    for name, path in [('zkey', key), ('vk', vk), ('sol', sol)]:
        record.update({name: rel(path), name + '_sha256': sha(path), name + '_bytes': path.stat().st_size})
    record['verification'] = dict(status='PASS', r1cs_sha256=record['r1cs_sha256'],
        zkey_sha256=record['zkey_sha256'], ptau_sha256=record['ptau_sha256'],
        verification_key_export='PASS', solidity_verifier_export='PASS')
    save(marker, record)
    initial.unlink()
    return dict(record, reused=False)


def witness(cfg, stage, fixture, compiled, run_root, label):
    private = contained(run_root / 'private' / label)
    private.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    inp, wit = output_file(private / 'input.json'), output_file(private / 'witness.wtns')
    save(inp, portable(fixture[stage]), private=True)
    if wit.exists():
        wit.unlink()
    result, cost = operation(label + '_witness', dict(op='witness', input=str(inp),
        wasm=str(ROOT / compiled['wasm']), output=str(wit)), logdir=run_root / 'logs')
    require(result)
    result, check = operation(label + '_r1cs', dict(op='witness-check',
        r1cs=str(ROOT / compiled['r1cs']), witness=str(wit)), logdir=run_root / 'logs')
    require(result, 'valid', True)
    names = [f'main.core.conceptsQ[{i}]' for i in range(cfg['C'])] if stage == 'a' else [
        'main.core.marginQ', 'main.core.L0', 'main.core.L1Q', 'main.counterfactualPrediction']
    values = fixture['trace']['conceptsQ'] if stage == 'a' else [
        fixture['counterfactual']['marginQ'] % FIELD, fixture['counterfactual']['L0'],
        fixture['counterfactual']['L1Q'], 0]
    labels = {}
    with (ROOT / compiled['sym']).open() as stream:
        for line in stream:
            fields = line.rstrip('\n').split(',', 3)
            if len(fields) == 4 and fields[3] in names:
                labels[fields[3]] = int(fields[1])
    if any(labels.get(name, -1) < 0 for name in names):
        raise RuntimeError('Required retained reference output missing')
    result, _ = operation('reference', dict(op='inspect', witness=str(wit),
        indices=[labels[name] for name in names], expected=[str(v) for v in values]), logdir=run_root / 'logs')
    require(result, 'matched', True)
    return wit, cost, check


def prove(cfg, stage, fixture, compiled, key, run_root, trial):
    require_capacity(cfg, 'prove', stage)
    target = contained(run_root / 'proofs' / stage / str(trial))
    target.mkdir(parents=True, exist_ok=True)
    proof_output = output_file(target / 'proof.json')
    public_output = output_file(target / 'public.json')
    if (target / 'measurement.json').exists():
        raise RuntimeError('Measured trials cannot be overwritten')
    wit = None
    try:
        wit, wcost, rcost = witness(cfg, stage, fixture, compiled, run_root, stage + '_' + str(trial))
        _, cost = operation('prove_' + stage, dict(op='prove', zkey=str(ROOT / key['zkey']),
            witness=str(wit), proof=str(proof_output), public=str(public_output)),
            timeout=86400, logdir=run_root / 'logs')
        if load(target / 'public.json') != public_signals(cfg, stage, fixture['public_context']):
            raise RuntimeError('Public signals differ from the independent reference')
        result, verification = operation('verify_' + stage, dict(op='verify', vk=str(ROOT / key['vk']),
            proof=str(target / 'proof.json'), public=str(target / 'public.json')), logdir=run_root / 'logs')
        require(result, 'valid', True)
        record = dict(status='PASS', measurement_type='ACTUAL', stage=stage.upper(), trial=str(trial),
            prove=cost, witness=wcost, r1cs_check=rcost, verify=verification,
            key_bytes=key['zkey_bytes'], verification_key_bytes=key['vk_bytes'])
        for name in ['proof', 'public']:
            path = target / (name + '.json')
            record.update({name + '_path': rel(path), name + '_sha256': sha(path), name + '_bytes': path.stat().st_size})
        save(target / 'measurement.json', record)
        return record
    finally:
        if wit and wit.exists():
            wit.unlink()


def negatives(cfg, stage, fixture, compiled, run_root, proof=None, key=None):
    private = contained(run_root / 'private/negative')
    private.mkdir(parents=True, exist_ok=True)
    private.chmod(0o700)
    inp, wit = output_file(private / 'input.json'), output_file(private / 'witness.wtns')
    cases = []
    fields = ['C_model_v2', 'C_input', 'C_state_v3', 'architectureVersion', 'stateCircuitVersion'] if stage == 'a' else [
        'C_explanation', 'explanationNonce', 'stateNonce', 'C_state_v3', 'sparsityBound', 'l1Bound']
    for field in fields:
        bad = copy.deepcopy(fixture[stage])
        bad[field] = int(bad[field]) + 1
        cases.append((field, bad))
    vectors = ['parametersQ', 'xQ', 'deltaWQ'] if stage == 'a' else ['cQ', 'deltaWQ', 'cPrimeQ', 'allowedMask']
    for field in vectors:
        bad = copy.deepcopy(fixture[stage])
        bad[field][0] = int(bad[field][0]) + 1 if field != 'allowedMask' else 0
        cases.append((field, bad))
    if stage == 'b':
        for name, field, value in [('zero_explanation_nonce', 'explanationNonce', 0),
                ('concept_above_max', 'cPrimeQ', 10001),
                ('concept_decrease', 'cPrimeQ', fixture['b']['cQ'][0] - 1)]:
            bad = copy.deepcopy(fixture[stage])
            if isinstance(bad[field], list):
                bad[field][0] = value
            else:
                bad[field] = value
            cases.append((name, bad))
    rows = []
    try:
        for name, payload in cases:
            if wit.exists():
                wit.unlink()
            save(inp, portable(payload), private=True)
            result, _ = operation('reject_' + stage, dict(op='expect-reject', input=str(inp),
                wasm=str(ROOT / compiled['wasm']), output=str(wit)), logdir=run_root / 'logs')
            require(result, 'rejected', True)
            rows.append(dict(stage=stage.upper(), name=name, layer='CIRCUIT_ASSERTION', status='PASS'))
        if proof and key:
            signals = load(ROOT / proof['public_path'])
            for index in range(len(signals) + 1):
                if index < len(signals):
                    changed = list(signals)
                    changed[index] = str((int(changed[index]) + 1) % FIELD)
                    save(inp, changed, private=True)
                    request = dict(op='verify', vk=str(ROOT / key['vk']), proof=str(ROOT / proof['proof_path']), public=str(inp))
                else:
                    changed = load(ROOT / proof['proof_path'])
                    changed['pi_a'][0] = str((int(changed['pi_a'][0]) + 1) % FIELD)
                    save(inp, changed, private=True)
                    request = dict(op='verify', vk=str(ROOT / key['vk']), proof=str(inp), public=str(ROOT / proof['public_path']))
                result, _ = operation('reject_proof', request, logdir=run_root / 'logs')
                require(result, 'valid', False)
                rows.append(dict(stage=stage.upper(), name='public_' + str(index) if index < len(signals) else 'proof_point',
                                 layer='GROTH16_VERIFY', status='PASS'))
    finally:
        for path in [inp, wit]:
            if path.exists():
                path.unlink()
    return rows
