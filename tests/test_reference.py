"""Integer semantics, policy limits and private commitment openings."""
import copy
import pytest

from src.config import ROOT, load_config, validate_config
from src import fixtures
from src.reference import (FIELD, A_SIGNALS, b_signals, candidate, infer, prepare,
    public_signals, round_ratio, tensors, validate_candidate)


@pytest.mark.parametrize('identifier,count,shape', [
    ('s1', 398, [19, 16, 4, 2]),
    ('s2', 2762, [64, 32, 16, 8, 2]),
    ('s3', 15506, [200, 64, 32, 16, 2])])
def test_exact_architecture_and_twenty_distinct_interventions(identifier, count, shape):
    cfg = load_config(identifier)
    parameters, inputs, trace = prepare(cfg)
    assert cfg['architecture'] == shape
    assert len(parameters) == count == sum(item[2] for item in tensors(cfg))
    assert len(inputs) == cfg['D'] and trace['prediction'] == 1
    assert prepare(cfg) == (parameters, inputs, trace)
    changed = []
    for index in range(20):
        values, result = candidate(cfg, trace, index)
        assert result['prediction'] == 0 and result['marginQ'] >= 0
        assert result['L0'] == 1 and result['L1Q'] == 2000 + index
        assert values[1:] == trace['conceptsQ'][1:]
        changed.append(tuple(values))
    assert len(set(changed)) == 20


@pytest.mark.parametrize('identifier', ['s1', 's2', 's3'])
def test_fixed_policy_and_class_zero_on_tie(identifier):
    cfg = load_config(identifier)
    trace = infer(cfg, [0] * cfg['parameters'], [0] * cfg['D'])
    assert trace['marginQ'] == 0 and trace['prediction'] == 0
    _, _, trace = prepare(cfg)
    values, _ = candidate(cfg, trace, 0)
    for kwargs in [dict(sparsity=2), dict(l1=4001), dict(allowed=[0] * cfg['C'])]:
        with pytest.raises(ValueError):
            validate_candidate(cfg, trace, values, **kwargs)
    values[1] = trace['conceptsQ'][1] - 1
    with pytest.raises(ValueError):
        validate_candidate(cfg, trace, values)


@pytest.mark.parametrize('numerator,expected', [
    (-15000, -2), (-5000, -1), (-4999, 0), (0, 0), (4999, 0), (5000, 1), (15000, 2)])
def test_exact_rounding(numerator, expected):
    assert round_ratio(numerator) == expected


def test_modified_configuration_fails_closed():
    for key, replacement in [('parameters', 399), ('seed', 1), ('D', True)]:
        cfg = load_config('s1')
        cfg[key] = replacement
        with pytest.raises(ValueError):
            validate_config(cfg)
    for value in [True, 1.0]:
        cfg = load_config('s1')
        cfg['versions']['modelVersion'] = value
        with pytest.raises(ValueError):
            validate_config(cfg)
    for value in [True, 147607.0]:
        cfg = load_config('s1')
        cfg['expected']['a']['constraints'] = value
        with pytest.raises(ValueError):
            validate_config(cfg)


@pytest.fixture
def private_workspace(tmp_path, monkeypatch):
    actual_commit = fixtures.commit
    actual_root = fixtures.ROOT
    def source_commit(vectors):
        with monkeypatch.context() as bridge:
            bridge.setattr(fixtures, 'ROOT', actual_root)
            return actual_commit(vectors)
    monkeypatch.setattr(fixtures, 'ROOT', tmp_path.resolve())
    monkeypatch.setattr(fixtures, 'commit', source_commit)
    return tmp_path


@pytest.mark.parametrize('identifier,index', [('s1', 20), ('s2', 24), ('s3', 32)])
def test_actual_commitment_opening_and_state_reuse(identifier, index, private_workspace):
    cfg = load_config(identifier)
    first = fixtures.prepare(cfg, private_workspace, 'state')
    second = fixtures.explanation(cfg, first, 1, private_workspace, explanation_id='second')
    assert first['a'] == second['a']
    assert first['b']['C_state_v3'] == second['b']['C_state_v3']
    assert first['b']['C_explanation'] != second['b']['C_explanation']
    assert first['b']['explanationNonce'] != second['b']['explanationNonce']
    assert first['b']['cPrimeQ'] != second['b']['cPrimeQ']
    opening = fixtures.load_private(private_workspace / second['opening_path'])
    assert fixtures.verify_explanation_opening(cfg, opening,
        second['b']['C_explanation'], second['b']['C_state_v3'])
    for field, value in [('explanationNonce', 0), ('C_state_v3', '1'), ('modelVersion', 2)]:
        changed = copy.deepcopy(opening)
        changed[field] = value
        assert not fixtures.verify_explanation_opening(cfg, changed,
            second['b']['C_explanation'], second['b']['C_state_v3'])
    public = public_signals(cfg, 'b', second['public_context'])
    assert len(public) == index + 1 and public[index] == second['b']['C_explanation']
    assert len(A_SIGNALS) == 12 and len(b_signals(cfg)) == index + 1
    assert str(first['b']['explanationNonce']) not in public
    for path in private_workspace.rglob('*.json'):
        assert path.stat().st_mode & 0o077 == 0


def test_public_signal_encoding_is_exact():
    cfg = load_config('s1')
    context = {name: 1 for name in A_SIGNALS}
    for value in [FIELD, True, 1.0, '01']:
        context['modelVersion'] = value
        with pytest.raises(ValueError):
            public_signals(cfg, 'a', context)


def test_private_writes_remain_inside_release():
    with pytest.raises(ValueError):
        fixtures.contained(ROOT.parent / 'outside.json')
