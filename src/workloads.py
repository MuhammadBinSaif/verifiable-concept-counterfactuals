"""Load provided datasets without replacing missing data."""
from __future__ import annotations

import copy
import hashlib
import json
from src.config import ROOT, validate_config
from src.reference import infer, prepare, validate_candidate, validate_parameters, vector


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate(cfg, value):
    validate_config(cfg)
    fields = {'schema', 'configuration', 'synthetic', 'public_test_data', 'architecture',
        'versions', 'policy', 'seed', 'parametersQ', 'xQ', 'trace', 'numerical_origin',
        'historical_experiment_fixture_status', 'candidates'}
    if type(value) is not dict or set(value) not in [fields, fields | {'candidate_origin'}]:
        raise ValueError('Provided dataset contains unsupported fields')
    if (type(value.get('schema')) is not int or value['schema'] != 1
        or value.get('configuration') != cfg['id'] or value.get('synthetic') is not True
        or value.get('public_test_data') is not True
        or canonical(value.get('architecture')) != canonical(cfg['architecture'])
        or canonical(value.get('versions')) != canonical(cfg['versions'])
        or canonical(value.get('policy')) != canonical(cfg['policy'])
        or type(value.get('seed')) is not int or value.get('seed') != cfg['seed']):
        raise ValueError('Provided dataset identity differs from the selected circuit')
    recovered = value.get('numerical_origin') == 'RECOVERED_LOCAL_PREPARATION_FIXTURE'
    historical = value.get('numerical_origin') == 'RECOVERED_OPTIMIZED_EXPERIMENT_INPUTS'
    example = value.get('numerical_origin') == 'COPIED_FROM_RECOVERED_LOCAL_PREPARATION_FIXTURE'
    if (not (recovered or historical or example)
        or value.get('historical_experiment_fixture_status') != ('RECOVERED' if historical else 'NOT RECOVERED')
        or (recovered and 'candidate_origin' in value)
        or (example and value.get('candidate_origin') != 'NEW_EXAMPLES_FROM_RETAINED_INTEGER_REFERENCE')
        or (historical and value.get('candidate_origin') != 'RECOVERED_OPTIMIZED_EXPERIMENT_INPUTS')):
        raise ValueError('Unsupported dataset provenance classification')
    parameters = validate_parameters(cfg, value['parametersQ'])
    inputs = vector(value['xQ'], cfg['D'])
    trace = infer(cfg, parameters, inputs)
    if canonical(value.get('trace')) != canonical(trace):
        raise ValueError('Published original inference differs from the integer reference')
    candidates = value.get('candidates')
    if type(candidates) is not list or len(candidates) != (1 if recovered else 20):
        raise ValueError('Dataset candidate count differs from its provenance classification')
    seen = set()
    for index, item in enumerate(candidates):
        if type(item) is not dict or set(item) != {'index', 'cPrimeQ', 'interventionQ', 'expected', 'origin'}:
            raise ValueError('Public candidate contains unsupported fields')
        origin = ('RECOVERED_LOCAL_PREPARATION_FIXTURE' if recovered else
            'RECOVERED_OPTIMIZED_EXPERIMENT_INPUTS' if historical else
            'NEW_EXAMPLE_FROM_RETAINED_INTEGER_REFERENCE')
        if item.get('origin') != origin:
            raise ValueError('Public candidate origin differs from its provenance classification')
        if type(item.get('index')) is not int or item['index'] != index:
            raise ValueError('Published candidates must have consecutive integer indices')
        changed = vector(item['cPrimeQ'], cfg['C'])
        result = validate_candidate(cfg, trace, changed)
        delta = [b - a for a, b in zip(trace['conceptsQ'], changed, strict=True)]
        if canonical(item.get('interventionQ')) != canonical(delta) or canonical(item.get('expected')) != canonical(result):
            raise ValueError('Published intervention differs from the integer reference')
        encoded = tuple(changed)
        if encoded in seen:
            raise ValueError('Published explanation candidates must be distinct')
        seen.add(encoded)
    return value


def load(cfg):
    directory = ROOT / 'data' / cfg['id']
    provenance_path = directory / 'provenance.json'
    if not provenance_path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('Dataset path escapes the release directory')
    if not provenance_path.is_file():
        raise FileNotFoundError('Provided dataset is missing; restore the data files before execution')
    provenance = json.loads(provenance_path.read_text())
    name = provenance.get('default_file')
    if name not in {'original.json', 'example.json'}:
        raise ValueError('Unsupported dataset file in provenance')
    path = directory / name
    if not path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('Dataset path escapes the release directory')
    if not path.is_file():
        raise FileNotFoundError('Provided dataset is missing; restore the data files before execution')
    raw = path.read_bytes()
    expected = provenance.get('public_files', {}).get(path.name)
    if not expected or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Dataset checksum does not match its provenance record')
    result = validate(cfg, json.loads(raw))
    return copy.deepcopy(result)


def numerical(cfg, selection='fixed'):
    if selection == 'generated':
        return prepare(cfg)
    if selection != 'fixed':
        raise ValueError('Data selection must be fixed or generated')
    value = load(cfg)
    return value['parametersQ'], value['xQ'], value['trace']


def candidate(cfg, trace, index, selection='fixed'):
    if selection == 'generated':
        from src.reference import candidate as generate_candidate
        return generate_candidate(cfg, trace, index)
    if selection != 'fixed':
        raise ValueError('Data selection must be fixed or generated')
    value = load(cfg)
    if canonical(trace) != canonical(value['trace']):
        raise ValueError('Candidate does not belong to the loaded dataset')
    if type(index) is not int or not 0 <= index < len(value['candidates']):
        raise ValueError('Candidate index is absent from the dataset')
    item = value['candidates'][index]
    return item['cPrimeQ'], item['expected']
