"""Source guards supplement compiled witness and proof validation."""
import re
from src.config import ROOT, load_config


def block(text, name):
    return text.split('template ' + name + '(', 1)[1].split('\ntemplate ', 1)[0]


def test_optimized_stage_b_uses_only_the_certified_head():
    source = (ROOT / 'circuits/shared/configured_protocol.circom').read_text()
    body = block(source, 'ExplanationCoreOptimizedComparison')
    for token in ['AuthenticatedStateStress(C)', 'ExplanationPolicyComparison(C)',
                  'ExplanationCommitmentComparison(C)', 'MarginHeadStress(C)']:
        assert token in body
    for token in ['IntegerEncoderComparison', 'ModelFoldStress', 'headParametersQ', 'headBlind']:
        assert token not in body
    large = (ROOT / 'circuits/shared/explanation_verification.circom').read_text()
    assert 'component counterfactual = MarginHeadStress(C)' in large
    assert 'explanation.commitment === C_explanation' in large


def test_model_fold_and_explanation_preimage_are_explicit():
    text = (ROOT / 'circuits/shared/commitments.circom').read_text()
    for statement in ['assert(k == 8)', 'Poseidon(4)', 'initial.inputs[0] <== 1006',
                      'initial.inputs[1] <== 2', 'Poseidon(k+1)',
                      'else links[i].inputs[j+1] <== 0']:
        assert statement in text
    generic = (ROOT / 'circuits/shared/configured_protocol.circom').read_text()
    body = block(generic, 'ExplanationCommitmentComparison')
    assert 'nonzero.out === 0' in body and 'StateSequenceV1(6+C,1007)' in body
    for index, field in enumerate(['1', 'explanationCircuitVersion', 'stateCircuitVersion',
                                  'modelVersion', 'C_state_v3', 'explanationNonce']):
        assert f'sequence.payload[{index}] <== {field}' in body
    assert 'sequence.payload[6+i] <== cPrimeQ[i]' in body


def test_entrypoints_preserve_public_signal_order():
    for identifier in ['s1', 's2', 's3']:
        cfg = load_config(identifier)
        for stage in ['a', 'b']:
            source = (ROOT / cfg['circuits'][stage]).read_text()
            public = re.search(r'public \[(.*?)\]', source).group(1).split(',')
            assert public[:5] == ['modelVersion', 'architectureVersion', 'schemaVersion',
                                  'quantizationVersion', 'preprocessingVersion']
            assert public[5:9] == ['C_model_v2', 'C_head', 'C_input', 'C_state_v3']
            assert public[-1] == ('modelCommitmentVersion' if stage == 'a' else 'C_explanation')
            assert str(cfg['versions']['stateCircuitVersion']) in source


def test_every_local_circuit_include_resolves():
    for source in (ROOT / 'circuits').rglob('*.circom'):
        for include in re.findall(r'include\s+"([^"]+)"', source.read_text()):
            if include.startswith('circomlib/'):
                continue
            target = (source.parent / include).resolve()
            assert target.is_relative_to(ROOT) and target.is_file()


def test_each_configuration_has_dedicated_entrypoints():
    for identifier in ['s1', 's2', 's3']:
        cfg = load_config(identifier)
        assert cfg['circuits'] == {stage: f'circuits/{identifier}/stage_{stage}.circom'
                                   for stage in ['a', 'b']}
    assert not (ROOT / 'circuits/stage_a.circom').exists()
    assert not (ROOT / 'circuits/stage_b.circom').exists()


def test_model_version_binding_remains_relation_specific():
    configured = (ROOT / 'circuits/shared/configured_protocol.circom').read_text()
    for name in ['StateCertificationCoreComparison', 'ExplanationCoreOptimizedComparison']:
        assert 'modelVersion === 1;' in block(configured, name)
    for filename, name in [('state_certification.circom', 'StateCertificationCoreLarge'),
                           ('explanation_verification.circom', 'ExplanationProofCoreStress')]:
        source = (ROOT / 'circuits/shared' / filename).read_text()
        body = block(source, name)
        assert 'modelVersion === 1;' not in body
        assert 'state.modelVersion <== modelVersion;' in body
    large = (ROOT / 'circuits/shared/state_certification.circom').read_text()
    for statement in ['model.payload[0] <== modelVersion;',
                      'headCommitment.payload[0] <== modelVersion;',
                      'inputCommitment.payload[0] <== modelVersion;']:
        assert statement in large


def test_registries_bind_the_proof_model_version_to_registered_state():
    model = (ROOT / 'contracts/protocol/ModelRegistryV3.sol').read_text()
    state = (ROOT / 'contracts/protocol/StateCertificationRegistryV3.sol').read_text()
    explanation = (ROOT / 'contracts/protocol/ExplanationCertificateRegistryV3.sol').read_text()
    assert 'if (modelVersion == 0 || registration.modelArtifactKeccak == bytes32(0))' in model
    assert 'modelRegistry.getModel(uint64(modelVersion))' in state
    assert 'publicSignals[MODEL_COMMITMENT_INDEX], model.fullModelCommitment' in state
    assert 'publicSignals[HEAD_COMMITMENT_INDEX], model.headCommitment' in state
    assert 'publicSignals[MODEL_VERSION_INDEX], state.modelVersion' in explanation
