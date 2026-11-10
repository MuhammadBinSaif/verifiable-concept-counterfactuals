"""Path, capacity and measurement guards without expensive proof execution."""
import copy
import hashlib
import json
import pytest
from src.config import load_config
from src import workloads
from src.protocol import cli, engine, io, resources


@pytest.mark.parametrize('action', ['demo', 'benchmark'])
@pytest.mark.parametrize('identifier', ['s1', 's2', 's3'])
def test_commands_default_to_provided_data(action, identifier, monkeypatch):
    def check_data(args):
        assert args.workload == 'fixed'
        cfg = load_config(args.config)
        parameters, inputs, trace = workloads.numerical(cfg, args.workload)
        data = json.loads((workloads.ROOT / 'data' / identifier / 'original.json').read_text())
        assert (parameters, inputs, trace) == (data['parametersQ'], data['xQ'], data['trace'])
        return 0

    monkeypatch.setattr(workloads, 'prepare', lambda cfg: pytest.fail('Unexpected data generation'))
    monkeypatch.setattr(cli, 'run', check_data)
    monkeypatch.setattr('sys.argv', ['cli', action, '--config', identifier])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 0


def test_output_containment_rejects_parent_and_symlink(tmp_path, monkeypatch):
    root = tmp_path / 'release'
    root.mkdir()
    monkeypatch.setattr(io, 'ROOT', root)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (root / 'link').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        io.save(root / '../outside/result.json', {})
    with pytest.raises(ValueError):
        io.save(root / 'link/result.json', {})
    assert not (outside / 'result.json').exists()


def test_private_output_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(io, 'ROOT', tmp_path)
    path = tmp_path / 'private/value.json'
    io.save(path, {'synthetic': 1}, private=True)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize('writer', ['json', 'csv'])
@pytest.mark.parametrize('destination', ['internal', 'external', 'dangling'])
def test_result_writers_reject_symlink_leaves(tmp_path, monkeypatch, writer, destination):
    root = tmp_path / 'release'
    root.mkdir()
    monkeypatch.setattr(io, 'ROOT', root)
    target = (root if destination == 'internal' else tmp_path) / 'preserved.txt'
    if destination != 'dangling':
        target.write_text('preserved')
    path = root / 'result.json'
    path.symlink_to(target)
    with pytest.raises(ValueError, match='symlink'):
        io.save(path, {}) if writer == 'json' else cli.rows_csv(path, [])
    if destination == 'dangling':
        assert not target.exists()
    else:
        assert target.read_text() == 'preserved'


def test_cached_build_must_match_configured_relation(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, 'ROOT', tmp_path)
    monkeypatch.setattr(io, 'ROOT', tmp_path)
    base = tmp_path / '.artifacts/build/s1/a'
    io.save(base / 'compile.json', dict(signature=hashlib.sha256(io.canonical({})).hexdigest(),
                                      r1cs_sha256='0' * 64))
    with pytest.raises(RuntimeError, match='configured relation'):
        engine.compile_stage(load_config('s1'), 'a')


def test_build_rejects_symlinked_runtime_before_writing(tmp_path, monkeypatch):
    root = tmp_path / 'release'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (root / '.artifacts').symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(engine, 'ROOT', root)
    monkeypatch.setattr(io, 'ROOT', root)
    with pytest.raises(ValueError):
        engine.compile_stage(load_config('s1'), 'a')
    assert not list(outside.iterdir())


@pytest.mark.parametrize('leaf', ['stage_a.r1cs', 'stage_a.sym', 'stage_a_js',
    'stage_a_js/stage_a.wasm', 'stage_a_js/witness_calculator.js',
    'stage_a_js/generate_witness.js', 'stage_a_js/package.json'])
def test_build_rejects_symlinked_generated_leaves(tmp_path, monkeypatch, leaf):
    root = tmp_path / 'release'
    base = root / '.artifacts/build/s1/a'
    path = base / leaf
    path.parent.mkdir(parents=True)
    outside = tmp_path / 'preserved'
    outside.write_text('preserved')
    path.symlink_to(outside)
    monkeypatch.setattr(engine, 'ROOT', root)
    monkeypatch.setattr(io, 'ROOT', root)
    monkeypatch.setattr(engine, 'measure', lambda *args, **kwargs: pytest.fail('Compiler should not run'))
    with pytest.raises(ValueError, match='symlink'):
        engine.compile_stage(load_config('s1'), 'a')
    assert outside.read_text() == 'preserved'


@pytest.mark.parametrize('leaf', ['DEV_INSECURE_power18.ptau', 'power18_initial.ptau',
    'power18_contributed.ptau'])
def test_phase_one_rejects_symlinked_generated_leaves(tmp_path, monkeypatch, leaf):
    root = tmp_path / 'release'
    base = root / '.artifacts/setup'
    base.mkdir(parents=True)
    outside = tmp_path / 'preserved.ptau'
    outside.write_text('preserved')
    (base / leaf).symlink_to(outside)
    monkeypatch.setattr(engine, 'ROOT', root)
    monkeypatch.setattr(io, 'ROOT', root)
    monkeypatch.setattr(engine, 'require_capacity', lambda *args: None)
    monkeypatch.setattr(engine, 'operation', lambda *args, **kwargs: pytest.fail('Setup should not run'))
    with pytest.raises(ValueError, match='symlink'):
        engine.phase_one(load_config('s1'), 'a', {'required_power': 18})
    assert outside.read_text() == 'preserved'


@pytest.mark.parametrize('operation', ['witness', 'negative'])
@pytest.mark.parametrize('dangling', [False, True])
def test_witness_outputs_reject_symlink_leaves(tmp_path, monkeypatch, operation, dangling):
    root = tmp_path / 'release'
    run = root / 'runs/test'
    private = run / 'private' / ('a_validation' if operation == 'witness' else 'negative')
    private.mkdir(parents=True)
    outside = tmp_path / 'preserved.wtns'
    if not dangling:
        outside.write_text('preserved')
    (private / 'witness.wtns').symlink_to(outside)
    monkeypatch.setattr(engine, 'ROOT', root)
    monkeypatch.setattr(io, 'ROOT', root)
    monkeypatch.setattr(engine, 'operation', lambda *args, **kwargs: pytest.fail('Witness should not run'))
    with pytest.raises(ValueError, match='symlink'):
        if operation == 'witness':
            engine.witness(load_config('s1'), 'a', {}, {}, run, 'a_validation')
        else:
            engine.negatives(load_config('s1'), 'a', {}, {}, run)
    if dangling:
        assert not outside.exists()
    else:
        assert outside.read_text() == 'preserved'


def test_proof_rejects_symlinked_output_before_witness(tmp_path, monkeypatch):
    root = tmp_path / 'release'
    target = root / 'runs/test/proofs/a/0'
    target.mkdir(parents=True)
    outside = tmp_path / 'outside.json'
    outside.write_text('preserved')
    (target / 'proof.json').symlink_to(outside)
    monkeypatch.setattr(engine, 'ROOT', root)
    monkeypatch.setattr(io, 'ROOT', root)
    monkeypatch.setattr(engine, 'require_capacity', lambda *args: None)
    monkeypatch.setattr(engine, 'witness', lambda *args: pytest.fail('Witness should not run'))
    with pytest.raises(ValueError):
        engine.prove(load_config('s1'), 'a', {}, {}, {}, root / 'runs/test', 0)
    assert outside.read_text() == 'preserved'


def test_setup_rejects_symlinked_export_before_key_generation(tmp_path, monkeypatch):
    root = tmp_path / 'release'
    target = root / '.artifacts/keys/s1/a'
    target.mkdir(parents=True)
    outside = tmp_path / 'outside.sol'
    outside.write_text('preserved')
    (target / 'verifier.sol').symlink_to(outside)
    monkeypatch.setattr(engine, 'ROOT', root)
    monkeypatch.setattr(io, 'ROOT', root)
    monkeypatch.setattr(engine, 'phase_one', lambda *args: pytest.fail('Phase one should not run'))
    monkeypatch.setattr(engine, 'operation', lambda *args, **kwargs: pytest.fail('Setup should not run'))
    with pytest.raises(ValueError):
        engine.setup_stage(load_config('s1'), 'a', {})
    assert outside.read_text() == 'preserved'


def test_capacity_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(resources, 'available_memory', lambda: 512 * 1024**2)
    with pytest.raises(resources.ResourceBlocked):
        resources.require_capacity(load_config('s3'), 'compile')


def test_negative_case_names_do_not_include_private_concepts(tmp_path, monkeypatch):
    from src.reference import prepare
    cfg = load_config('s1')
    _, _, trace = prepare(cfg)
    fixture = {'b': dict(C_explanation=1, explanationNonce=1, stateNonce=1, C_state_v3=1,
        sparsityBound=1, l1Bound=4000, cQ=trace['conceptsQ'], deltaWQ=trace['deltaWQ'],
        cPrimeQ=list(trace['conceptsQ']), allowedMask=[1] * cfg['C'])}
    monkeypatch.setattr(engine, 'ROOT', tmp_path)
    monkeypatch.setattr(io, 'ROOT', tmp_path)
    monkeypatch.setattr(engine, 'save', lambda *args, **kwargs: None)
    monkeypatch.setattr(engine, 'operation', lambda *args, **kwargs: ({'rejected': True}, {}))
    rows = engine.negatives(cfg, 'b', copy.deepcopy(fixture), {'wasm': 'unused'}, tmp_path)
    assert 'concept_decrease' in {r['name'] for r in rows}
    assert all(str(trace['conceptsQ'][0] - 1) not in r['name'] for r in rows)


@pytest.mark.parametrize('arguments', [
    ['demo', '--config', 's1', '--explanations', '1'],
    ['benchmark', '--config', 's2', '--b-trials', '21'],
    ['benchmark', '--config', 's1', '--a-trials', '0'],
    ['demo', '--config', 's1', '--stage', 'b'],
])
def test_cli_rejects_unsupported_trial_counts(arguments, monkeypatch):
    monkeypatch.setattr('sys.argv', ['cli'] + arguments)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
