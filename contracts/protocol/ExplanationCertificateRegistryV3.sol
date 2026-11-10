// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

// Adapted from the approved V3 research source; see THIRD_PARTY_NOTICES.md.
// Cryptographic domain identifiers intentionally retain their original bytes.

import {ModelRegistryV3} from "./ModelRegistryV3.sol";
import {StateCertificationRegistryV3} from "./StateCertificationRegistryV3.sol";
import {IExplanationGroth16VerifierV3 as ExplanationGroth16VerifierV3} from "../interfaces/IVerifiers.sol";

/// @notice Stage B requires an existing verified Stage A certificate, closing the standalone-proof trust gap.
/// @dev The fixed verifier uses the approved DEV_INSECURE / DEVELOPMENT ONLY Groth16 setup.
contract ExplanationCertificateRegistryV3 {
    uint256 public constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    bytes32 public constant DOMAIN_CERT = keccak256("FL-XAI-ZKP-BC:CERTIFICATE:v3");
    uint256 public constant EXPLANATION_CIRCUIT_VERSION = 102;
    uint64 public constant EXPLANATION_POLICY_VERSION = 2;
    bytes32 public constant APPROVED_POLICY_MANIFEST_KECCAK =
        0x8af45e12dcf7ee3f1fac51a16c08223cc83e4f776b21ae5f769973357fe724c5;
    uint256 public constant MODEL_VERSION_INDEX = 0;
    uint256 public constant ARCHITECTURE_VERSION_INDEX = 1;
    uint256 public constant SCHEMA_VERSION_INDEX = 2;
    uint256 public constant QUANTIZATION_VERSION_INDEX = 3;
    uint256 public constant PREPROCESSING_VERSION_INDEX = 4;
    uint256 public constant MODEL_COMMITMENT_INDEX = 5;
    uint256 public constant HEAD_COMMITMENT_INDEX = 6;
    uint256 public constant INPUT_COMMITMENT_INDEX = 7;
    uint256 public constant STATE_COMMITMENT_INDEX = 8;
    uint256 public constant ORIGINAL_PREDICTION_INDEX = 9;
    uint256 public constant STATE_CIRCUIT_VERSION_INDEX = 10;
    uint256 public constant MODEL_COMMITMENT_VERSION_INDEX = 11;
    uint256 public constant EXPLANATION_CIRCUIT_VERSION_INDEX = 12;
    uint256 public constant COUNTERFACTUAL_PREDICTION_INDEX = 13;
    uint256 public constant ALLOWED_MASK_0_INDEX = 14;
    uint256 public constant ALLOWED_MASK_1_INDEX = 15;
    uint256 public constant ALLOWED_MASK_2_INDEX = 16;
    uint256 public constant ALLOWED_MASK_3_INDEX = 17;
    uint256 public constant ALLOWED_MASK_4_INDEX = 18;
    uint256 public constant ALLOWED_MASK_5_INDEX = 19;
    uint256 public constant ALLOWED_MASK_6_INDEX = 20;
    uint256 public constant ALLOWED_MASK_7_INDEX = 21;
    uint256 public constant ALLOWED_MASK_8_INDEX = 22;
    uint256 public constant ALLOWED_MASK_9_INDEX = 23;
    uint256 public constant ALLOWED_MASK_10_INDEX = 24;
    uint256 public constant ALLOWED_MASK_11_INDEX = 25;
    uint256 public constant ALLOWED_MASK_12_INDEX = 26;
    uint256 public constant ALLOWED_MASK_13_INDEX = 27;
    uint256 public constant ALLOWED_MASK_14_INDEX = 28;
    uint256 public constant ALLOWED_MASK_15_INDEX = 29;
    uint256 public constant SPARSITY_BOUND_INDEX = 30;
    uint256 public constant L1_BOUND_INDEX = 31;
    uint256 public constant EXPLANATION_COMMITMENT_INDEX = 32;
    uint64 public constant EXPLANATION_COMMITMENT_VERSION = 1;

    ModelRegistryV3 public immutable modelRegistry;
    StateCertificationRegistryV3 public immutable stateRegistry;
    ExplanationGroth16VerifierV3 public immutable verifier;
    bytes32 public immutable policyManifestKeccak;

    struct CertificateRecord {
        bytes32 certificateId;
        bytes32 stateId;
        uint64 modelVersion;
        uint64 schemaVersion;
        uint8 counterfactualPrediction;
        uint256 explanationCommitment;
        bytes32 proofHash;
        bytes32 certificateNonce;
        uint64 explanationCircuitVersion;
        uint64 modelCommitmentVersion;
        uint64 explanationPolicyVersion;
        uint64 createdAt;
    }

    mapping(bytes32 => CertificateRecord) private certificates;
    mapping(bytes32 => bool) public usedProofHashes;
    mapping(bytes32 => bool) public usedCertificateNonces;

    error DuplicateReject(bytes32 kind, bytes32 id);
    error ReplayReject(bytes32 kind, bytes32 id);
    error RegistryBindingReject(uint256 signalIndex);
    error StaleModelReject(uint256 modelVersion);
    error Groth16VerificationFalse();
    error FieldElementReject(uint256 index, uint256 value);
    error ProofCoordinateReject(uint256 index, uint256 value);
    error InvalidConfiguration();

    event ExplanationCertified(
        bytes32 indexed certificateId,
        bytes32 indexed stateId,
        uint64 indexed modelVersion,
        bytes32 proofHash,
        uint256 explanationCommitment
    );

    constructor(
        ModelRegistryV3 models,
        StateCertificationRegistryV3 states,
        ExplanationGroth16VerifierV3 explanationVerifier,
        bytes32 approvedPolicyManifestKeccak
    ) {
        if (
            address(models).code.length == 0 || address(states).code.length == 0
                || address(explanationVerifier).code.length == 0
                || address(states.modelRegistry()) != address(models)
                || approvedPolicyManifestKeccak != APPROVED_POLICY_MANIFEST_KECCAK
        ) revert InvalidConfiguration();
        modelRegistry = models;
        stateRegistry = states;
        verifier = explanationVerifier;
        policyManifestKeccak = approvedPolicyManifestKeccak;
    }

    function calculateCertificateId(
        bytes32 stateId,
        uint256 modelVersion,
        bytes32 proofHash,
        bytes32 certificateNonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_CERT, stateId, modelVersion, proofHash, certificateNonce));
    }

    /// @dev ABI types: (uint256[2],uint256[2][2],uint256[2]), uint256[33].
    function calculateProofHash(
        StateCertificationRegistryV3.Groth16Proof calldata proof,
        uint256[33] calldata publicSignals
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(proof, publicSignals));
    }

    function certifyExplanation(
        bytes32 stateId,
        StateCertificationRegistryV3.Groth16Proof calldata proof,
        uint256[33] calldata publicSignals,
        bytes32 certificateNonce
    ) external returns (bytes32 certificateId) {
        _checkFields(publicSignals);
        _checkProofCoordinates(proof);
        StateCertificationRegistryV3.StateRecord memory state = stateRegistry.getState(stateId);
        ModelRegistryV3.ModelRecord memory model = modelRegistry.getModel(state.modelVersion);
        if (!model.active) revert StaleModelReject(state.modelVersion);
        _match(MODEL_VERSION_INDEX, publicSignals[MODEL_VERSION_INDEX], state.modelVersion);
        _match(ARCHITECTURE_VERSION_INDEX, publicSignals[ARCHITECTURE_VERSION_INDEX], model.architectureVersion);
        _match(SCHEMA_VERSION_INDEX, publicSignals[SCHEMA_VERSION_INDEX], state.schemaVersion);
        _match(PREPROCESSING_VERSION_INDEX, publicSignals[PREPROCESSING_VERSION_INDEX], model.preprocessingVersion);
        _match(MODEL_COMMITMENT_INDEX, publicSignals[MODEL_COMMITMENT_INDEX], model.fullModelCommitment);
        _match(STATE_CIRCUIT_VERSION_INDEX, publicSignals[STATE_CIRCUIT_VERSION_INDEX], 102);
        _match(MODEL_COMMITMENT_VERSION_INDEX, publicSignals[MODEL_COMMITMENT_VERSION_INDEX], 2);
        _match(EXPLANATION_CIRCUIT_VERSION_INDEX, publicSignals[EXPLANATION_CIRCUIT_VERSION_INDEX], 102);
        _match(QUANTIZATION_VERSION_INDEX, publicSignals[QUANTIZATION_VERSION_INDEX], model.quantizationVersion);
        _match(HEAD_COMMITMENT_INDEX, publicSignals[HEAD_COMMITMENT_INDEX], model.headCommitment);
        _match(INPUT_COMMITMENT_INDEX, publicSignals[INPUT_COMMITMENT_INDEX], state.inputCommitment);
        _match(STATE_COMMITMENT_INDEX, publicSignals[STATE_COMMITMENT_INDEX], state.stateCommitment);
        _match(ORIGINAL_PREDICTION_INDEX, publicSignals[ORIGINAL_PREDICTION_INDEX], state.originalPrediction);
        _match(ORIGINAL_PREDICTION_INDEX, publicSignals[ORIGINAL_PREDICTION_INDEX], 1);
        _match(COUNTERFACTUAL_PREDICTION_INDEX, publicSignals[COUNTERFACTUAL_PREDICTION_INDEX], 0);
        _match(ALLOWED_MASK_0_INDEX, publicSignals[ALLOWED_MASK_0_INDEX], 1);
        _match(ALLOWED_MASK_1_INDEX, publicSignals[ALLOWED_MASK_1_INDEX], 1);
        _match(ALLOWED_MASK_2_INDEX, publicSignals[ALLOWED_MASK_2_INDEX], 1);
        _match(ALLOWED_MASK_3_INDEX, publicSignals[ALLOWED_MASK_3_INDEX], 1);
        _match(ALLOWED_MASK_4_INDEX, publicSignals[ALLOWED_MASK_4_INDEX], 1);
        _match(ALLOWED_MASK_5_INDEX, publicSignals[ALLOWED_MASK_5_INDEX], 1);
        _match(ALLOWED_MASK_6_INDEX, publicSignals[ALLOWED_MASK_6_INDEX], 1);
        _match(ALLOWED_MASK_7_INDEX, publicSignals[ALLOWED_MASK_7_INDEX], 1);
        _match(ALLOWED_MASK_8_INDEX, publicSignals[ALLOWED_MASK_8_INDEX], 1);
        _match(ALLOWED_MASK_9_INDEX, publicSignals[ALLOWED_MASK_9_INDEX], 1);
        _match(ALLOWED_MASK_10_INDEX, publicSignals[ALLOWED_MASK_10_INDEX], 1);
        _match(ALLOWED_MASK_11_INDEX, publicSignals[ALLOWED_MASK_11_INDEX], 1);
        _match(ALLOWED_MASK_12_INDEX, publicSignals[ALLOWED_MASK_12_INDEX], 1);
        _match(ALLOWED_MASK_13_INDEX, publicSignals[ALLOWED_MASK_13_INDEX], 1);
        _match(ALLOWED_MASK_14_INDEX, publicSignals[ALLOWED_MASK_14_INDEX], 1);
        _match(ALLOWED_MASK_15_INDEX, publicSignals[ALLOWED_MASK_15_INDEX], 1);
        // These public inputs identify the exact fixed experiment policy.
        _match(SPARSITY_BOUND_INDEX, publicSignals[SPARSITY_BOUND_INDEX], 1);
        _match(L1_BOUND_INDEX, publicSignals[L1_BOUND_INDEX], 4000);
        if (
            model.schemaVersion != state.schemaVersion
                || model.explanationCircuitVersion != EXPLANATION_CIRCUIT_VERSION
                || state.stateCircuitVersion != 102 || state.modelCommitmentVersion != 2
                || model.modelCommitmentVersion != 2
        ) revert RegistryBindingReject(103);
        bytes32 proofHash = calculateProofHash(proof, publicSignals);
        certificateId = calculateCertificateId(stateId, state.modelVersion, proofHash, certificateNonce);
        if (certificates[certificateId].certificateId != bytes32(0)) {
            revert DuplicateReject("CERTIFICATE", certificateId);
        }
        if (usedProofHashes[proofHash]) revert ReplayReject("EXPLANATION_PROOF", proofHash);
        if (usedCertificateNonces[certificateNonce]) revert ReplayReject("CERTIFICATE_NONCE", certificateNonce);
        if (!verifier.verifyProof(proof.a, proof.b, proof.c, publicSignals)) {
            revert Groth16VerificationFalse();
        }
        if (certificateId == bytes32(0) || block.timestamp > type(uint64).max) revert InvalidConfiguration();
        certificates[certificateId] = CertificateRecord({
            certificateId: certificateId,
            stateId: stateId,
            modelVersion: state.modelVersion,
            schemaVersion: state.schemaVersion,
            counterfactualPrediction: uint8(publicSignals[COUNTERFACTUAL_PREDICTION_INDEX]),
            explanationCommitment: publicSignals[EXPLANATION_COMMITMENT_INDEX],
            proofHash: proofHash,
            certificateNonce: certificateNonce,
            explanationCircuitVersion: model.explanationCircuitVersion,
            modelCommitmentVersion: model.modelCommitmentVersion,
            explanationPolicyVersion: EXPLANATION_POLICY_VERSION,
            createdAt: uint64(block.timestamp)
        });
        usedProofHashes[proofHash] = true;
        usedCertificateNonces[certificateNonce] = true;
        emit ExplanationCertified(certificateId, stateId, state.modelVersion, proofHash, publicSignals[EXPLANATION_COMMITMENT_INDEX]);
    }

    function getCertificate(bytes32 certificateId) external view returns (CertificateRecord memory record) {
        record = certificates[certificateId];
        if (record.certificateId == bytes32(0)) revert RegistryBindingReject(104);
    }

    function _match(uint256 index, uint256 actual, uint256 expected) private pure {
        if (actual != expected) revert RegistryBindingReject(index);
    }

    function _checkFields(uint256[33] calldata signals) private pure {
        for (uint256 i = 0; i < 33; ++i) {
            if (signals[i] >= SCALAR_FIELD) revert FieldElementReject(i, signals[i]);
        }
    }

    function _checkProofCoordinates(StateCertificationRegistryV3.Groth16Proof calldata proof) private pure {
        for (uint256 i = 0; i < 2; ++i) {
            if (proof.a[i] >= BASE_FIELD) revert ProofCoordinateReject(i, proof.a[i]);
            if (proof.c[i] >= BASE_FIELD) revert ProofCoordinateReject(6 + i, proof.c[i]);
            for (uint256 j = 0; j < 2; ++j) {
                if (proof.b[i][j] >= BASE_FIELD) {
                    revert ProofCoordinateReject(2 + 2 * i + j, proof.b[i][j]);
                }
            }
        }
    }
}
