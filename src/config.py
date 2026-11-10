"""Fixed circuit configurations and repository-local paths."""
from __future__ import annotations
import copy
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODE = 'synthetic_stress'
MATRIX = {'s1': ([19, 16, 4, 2], 398, 201, 202),
          's2': ([64, 32, 16, 8, 2], 2762, 301, 302),
          's3': ([200, 64, 32, 16, 2], 15506, 101, 102)}


def load_config(identifier):
    if isinstance(identifier, dict):
        return copy.deepcopy(validate_config(identifier))
    if identifier not in MATRIX:
        raise ValueError('Supported configurations are s1, s2 and s3')
    value = json.loads((ROOT / 'configs' / (identifier + '.json')).read_text())
    return validate_config(value)


def validate_config(value):
    if type(value) is not dict or value.get('id') not in MATRIX:
        raise ValueError('Unsupported circuit configuration')
    shape, parameters, architecture, relation = MATRIX[value['id']]
    expected_versions = dict(modelVersion=1, architectureVersion=architecture,
        schemaVersion=architecture, quantizationVersion=1, preprocessingVersion=1,
        stateCircuitVersion=relation, explanationCircuitVersion=relation, modelCommitmentVersion=2)
    expected_policy = dict(allowed_mask=[1] * shape[-2], sparsity_bound=1, l1_bound=4000,
        concept_minimum=0, concept_maximum=10000, direction='nonnegative')
    if (value.get('architecture') != shape or value.get('parameters') != parameters
        or value.get('D') != shape[0] or value.get('H1') != shape[1]
        or value.get('H2') != (shape[2] if len(shape) == 5 else 0)
        or value.get('C') != shape[-2] or value.get('versions') != expected_versions
        or value.get('policy') != expected_policy or value.get('mode') != MODE
        or value.get('seed') != 2026102701):
        raise ValueError('Configuration changes the supported circuit relation')
    expected = dict(domain=1007, nonceNonzero=True, noncePrivate=True,
        payloadLength=6 + shape[-2], publicSignalIndex=16 + shape[-2], schemeVersion=1)
    if value.get('explanationCommitment') != expected:
        raise ValueError('Explanation commitment configuration mismatch')
    protected = dict(architecture=shape, parameters=parameters, D=shape[0], H1=shape[1],
        H2=shape[2] if len(shape) == 5 else 0, C=shape[-2], versions=expected_versions,
        policy=expected_policy, explanationCommitment=expected, seed=2026102701,
        quantization=dict(scale=10000, rounding='nearest_ties_away_from_zero',
            class_zero_on_margin_tie=True),
        proving=dict(curve='bn254', model_commitment='width8', sequential=True,
            setup_security='DEV_INSECURE', system='groth16'))
    selected = {key: value.get(key) for key in protected}
    if json.dumps(selected, sort_keys=True, allow_nan=False) != json.dumps(protected, sort_keys=True, allow_nan=False):
        raise ValueError('Configuration changes the supported arithmetic or commitment format')
    circuit_prefix = 'circuits/' + value['id'] + '/'
    if value.get('circuits') != {stage: circuit_prefix + 'stage_' + stage + '.circom'
                                  for stage in ['a', 'b']}:
        raise ValueError('Circuit entrypoint does not match the configuration')
    records = value.get('expected')
    if type(records) is not dict or set(records) != {'a', 'b'}:
        raise ValueError('Both compiled circuit expectations are required')
    for stage, record in records.items():
        fields = ['constraints', 'privateInputs', 'publicInputs', 'publicOutputs', 'required_power']
        if type(record) is not dict or any(type(record.get(key)) is not int for key in fields):
            raise ValueError('Compiled circuit dimensions must be exact integers')
        if 'wires' in record and type(record['wires']) is not int:
            raise ValueError('Compiled circuit wire count must be an exact integer')
        public_count = 12 if stage == 'a' else 17 + value['C']
        private_count = value['D'] + parameters + value['C'] + 5 if stage == 'a' else 3 * value['C'] + 3
        if (record['constraints'] <= 0 or record['publicInputs'] != public_count
            or record['privateInputs'] != private_count or record['publicOutputs'] != 0
            or not 1 <= record['required_power'] <= 28
            or not re.fullmatch(r'[0-9a-f]{64}', str(record.get('r1cs_sha256', '')))):
            raise ValueError('Compiled circuit expectations do not match the public layout')
    return value
