"""Fixed workload loading, provenance checks and explicit generation."""
import copy
import hashlib
import json
import shutil

import pytest
from src.config import ROOT, load_config
from src import workloads
from src.reference import prepare, validate_candidate


@pytest.mark.parametrize('identifier', ['s1', 's2', 's3'])
def test_fixed_original_workloads_match_integer_reference(identifier):
    cfg = load_config(identifier)
    fixed = workloads.load(cfg)
    parameters, inputs, trace = prepare(cfg)
    assert fixed['parametersQ'] == parameters
    assert fixed['xQ'] == inputs
    assert fixed['trace'] == trace
    assert fixed['historical_experiment_fixture_status'] == 'RECOVERED'
    assert fixed['numerical_origin'] == 'RECOVERED_OPTIMIZED_EXPERIMENT_INPUTS'
    assert len(fixed['candidates']) == 20
    for index, item in enumerate(fixed['candidates']):
        assert item['origin'] == 'RECOVERED_OPTIMIZED_EXPERIMENT_INPUTS'
        changed, result = workloads.candidate(cfg, fixed['trace'], index)
        assert result == validate_candidate(cfg, fixed['trace'], changed)
    encoded = json.dumps(fixed).lower()
    for name in ['modelblind', 'headblind', 'inputnonce', 'statenonce', 'explanationnonce']:
        assert name not in encoded


@pytest.fixture
def copied_workload(tmp_path, monkeypatch):
    target = tmp_path / 'data/s1'
    target.mkdir(parents=True)
    for name in ['original.json', 'provenance.json']:
        shutil.copyfile(ROOT / 'data/s1' / name, target / name)
    monkeypatch.setattr(workloads, 'ROOT', tmp_path)
    return target


def test_missing_fixed_workload_never_generates_replacement(tmp_path, monkeypatch):
    monkeypatch.setattr(workloads, 'ROOT', tmp_path)
    monkeypatch.setattr(workloads, 'prepare', lambda cfg: pytest.fail('Implicit generation'))
    with pytest.raises(FileNotFoundError, match='Provided dataset is missing'):
        workloads.numerical(load_config('s1'))


def test_changed_fixed_file_fails_checksum(copied_workload):
    provenance = json.loads((copied_workload / 'provenance.json').read_text())
    path = copied_workload / provenance['default_file']
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError, match='checksum'):
        workloads.load(load_config('s1'))


def test_rehashed_invalid_candidate_still_fails_reference(copied_workload):
    provenance = json.loads((copied_workload / 'provenance.json').read_text())
    path = copied_workload / provenance['default_file']
    value = json.loads(path.read_text())
    value['candidates'][0]['cPrimeQ'][0] = 10001
    path.write_bytes(workloads.canonical(value))
    provenance['public_files'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (copied_workload / 'provenance.json').write_text(json.dumps(provenance))
    with pytest.raises(ValueError, match='dimensions and range'):
        workloads.load(load_config('s1'))


def test_missing_original_does_not_fall_back_to_generated_example(copied_workload):
    shutil.copyfile(copied_workload / 'original.json', copied_workload / 'example.json')
    (copied_workload / 'original.json').unlink()
    assert (copied_workload / 'example.json').is_file()
    with pytest.raises(FileNotFoundError, match='Provided dataset is missing'):
        workloads.load(load_config('s1'))


def test_generated_selection_is_explicit_and_independent_of_fixed_files(tmp_path, monkeypatch):
    monkeypatch.setattr(workloads, 'ROOT', tmp_path)
    cfg = load_config('s2')
    assert workloads.numerical(cfg, 'generated') == prepare(cfg)
    with pytest.raises(ValueError, match='fixed or generated'):
        workloads.numerical(cfg, 'missing')


def test_fixed_candidate_requires_same_original_state():
    cfg = load_config('s1')
    fixed = workloads.load(cfg)
    changed = copy.deepcopy(fixed['trace'])
    changed['conceptsQ'][0] += 1
    with pytest.raises(ValueError, match='does not belong'):
        workloads.candidate(cfg, changed, 0)
    with pytest.raises(ValueError, match='absent'):
        workloads.candidate(cfg, fixed['trace'], 20)


@pytest.mark.parametrize('field,value', [('versions', {}), ('synthetic', False), ('seed', 1), ('architecture', [1])])
def test_fixed_workload_rejects_incompatible_identity(field, value):
    cfg = load_config('s1')
    fixed = workloads.load(cfg)
    fixed[field] = value
    with pytest.raises(ValueError, match='identity'):
        workloads.validate(cfg, fixed)


@pytest.mark.parametrize('field', ['explanationNonce', 'modelBlind', 'password', 'arbitrary'])
def test_public_workload_rejects_unknown_or_private_top_level_fields(field):
    cfg = load_config('s1')
    fixed = workloads.load(cfg)
    fixed[field] = 'DO_NOT_PUBLISH'
    with pytest.raises(ValueError, match='unsupported fields'):
        workloads.validate(cfg, fixed)


@pytest.mark.parametrize('field', ['explanationNonce', 'modelBlind', 'private_key'])
def test_public_candidate_rejects_unknown_or_private_fields(field):
    cfg = load_config('s1')
    fixed = workloads.load(cfg)
    fixed['candidates'][0][field] = 'DO_NOT_PUBLISH'
    with pytest.raises(ValueError, match='unsupported fields'):
        workloads.validate(cfg, fixed)


def test_public_trace_rejects_private_fields():
    cfg = load_config('s1')
    fixed = workloads.load(cfg)
    fixed['trace']['stateNonce'] = 1
    with pytest.raises(ValueError, match='original inference'):
        workloads.validate(cfg, fixed)
