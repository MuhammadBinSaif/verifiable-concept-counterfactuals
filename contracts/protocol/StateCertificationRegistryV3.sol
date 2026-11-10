// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

// Adapted from the approved V3 research source; see THIRD_PARTY_NOTICES.md.
// Cryptographic domain identifiers intentionally retain their original bytes.

import {ModelRegistryV3} from "./ModelRegistryV3.sol";
import {InputCommitmentRegistryV3} from "./InputCommitmentRegistryV3.sol";
import {IStateGroth16VerifierV3 as StateGroth16VerifierV3} from "../interfaces/IVerifiers.sol";

/// @notice Stage A certification under the unchanged DEV_INSECURE research verifier.
contract StateCertificationRegistryV3 {
    uint256 public constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    bytes32 public constant DOMAIN_STATE = keccak256("FL-XAI-ZKP-BC:STATE:v3");
    uint256 public constant STATE_CIRCUIT_VERSION = 102;
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

    ModelRegistryV3 public immutable modelRegistry;
    InputCommitmentRegistryV3 public immutable inputRegistry;
    StateGroth16VerifierV3 public immutable verifier;

    // This static tuple is supplied as calldata and hashed. It is never a storage variable.
    struct Groth16Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }

    struct StateRecord {
        bytes32 stateId;
        bytes32 requestId;
        uint256 stateCommitment;
        uint256 inputCommitment;
        uint64 modelVersion;
        uint64 schemaVersion;
        uint8 originalPrediction;
        bytes32 proofHash;
        uint64 stateCircuitVersion;
        uint64 modelCommitmentVersion;
        uint64 createdAt;
    }

    mapping(bytes32 => StateRecord) private states;
    mapping(bytes32 => bool) public usedProofHashes;

    error DuplicateReject(bytes32 kind, bytes32 id);
    error ReplayReject(bytes32 kind, bytes32 id);
    error RegistryBindingReject(uint256 signalIndex);
    error StaleModelReject(uint256 modelVersion);
    error Groth16VerificationFalse();
    error FieldElementReject(uint256 index, uint256 value);
    error ProofCoordinateReject(uint256 index, uint256 value);
    error InvalidConfiguration();

    event StateCertified(
        bytes32 indexed stateId,
        bytes32 indexed requestId,
        uint64 indexed modelVersion,
        uint256 stateCommitment,
        bytes32 proofHash
    );

    constructor(ModelRegistryV3 models, InputCommitmentRegistryV3 inputs, StateGroth16VerifierV3 stateVerifier) {
        if (
            address(models).code.length == 0 || address(inputs).code.length == 0
                || address(stateVerifier).code.length == 0
                || models.coordinator() != inputs.coordinator()
        ) revert InvalidConfiguration();
        modelRegistry = models;
        inputRegistry = inputs;
        verifier = stateVerifier;
    }

    function calculateStateId(bytes32 requestId, uint256 modelVersion, uint256 stateCommitment)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN_STATE, requestId, modelVersion, stateCommitment));
    }

    /// @dev ABI types: (uint256[2],uint256[2][2],uint256[2]), uint256[12].
    function calculateProofHash(Groth16Proof calldata proof, uint256[12] calldata publicSignals)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(proof, publicSignals));
    }

    function certifyState(
        bytes32 requestId,
        Groth16Proof calldata proof,
        uint256[12] calldata publicSignals
    ) external returns (bytes32 stateId) {
        _checkFields(publicSignals);
        _checkProofCoordinates(proof);
        InputCommitmentRegistryV3.RequestRecord memory request = inputRegistry.getRequest(requestId);
        if (request.consumed) revert ReplayReject("REQUEST", requestId);
        uint256 modelVersion = publicSignals[MODEL_VERSION_INDEX];
        if (modelVersion == 0 || modelVersion > type(uint64).max) {
            revert RegistryBindingReject(MODEL_VERSION_INDEX);
        }
        ModelRegistryV3.ModelRecord memory model = modelRegistry.getModel(uint64(modelVersion));
        if (!model.active) revert StaleModelReject(modelVersion);
        if (modelRegistry.schemaManifestKeccak(model.schemaVersion) == bytes32(0)) {
            revert RegistryBindingReject(SCHEMA_VERSION_INDEX);
        }
        _match(ARCHITECTURE_VERSION_INDEX, publicSignals[ARCHITECTURE_VERSION_INDEX], model.architectureVersion);
        _match(SCHEMA_VERSION_INDEX, publicSignals[SCHEMA_VERSION_INDEX], model.schemaVersion);
        _match(QUANTIZATION_VERSION_INDEX, publicSignals[QUANTIZATION_VERSION_INDEX], model.quantizationVersion);
        _match(PREPROCESSING_VERSION_INDEX, publicSignals[PREPROCESSING_VERSION_INDEX], model.preprocessingVersion);
        _match(MODEL_COMMITMENT_INDEX, publicSignals[MODEL_COMMITMENT_INDEX], model.fullModelCommitment);
        _match(HEAD_COMMITMENT_INDEX, publicSignals[HEAD_COMMITMENT_INDEX], model.headCommitment);
        _match(INPUT_COMMITMENT_INDEX, publicSignals[INPUT_COMMITMENT_INDEX], request.inputCommitment);
        if (publicSignals[ORIGINAL_PREDICTION_INDEX] > 1) {
            revert RegistryBindingReject(ORIGINAL_PREDICTION_INDEX);
        }
        _match(STATE_CIRCUIT_VERSION_INDEX, publicSignals[STATE_CIRCUIT_VERSION_INDEX], STATE_CIRCUIT_VERSION);
        _match(MODEL_COMMITMENT_VERSION_INDEX, publicSignals[MODEL_COMMITMENT_VERSION_INDEX], 2);
        _match(MODEL_COMMITMENT_VERSION_INDEX, publicSignals[MODEL_COMMITMENT_VERSION_INDEX], model.modelCommitmentVersion);
        if (model.stateCircuitVersion != STATE_CIRCUIT_VERSION) revert RegistryBindingReject(101);
        // C_state and prediction are derived from proof-bound signals. No competing caller metadata exists.
        stateId = calculateStateId(requestId, modelVersion, publicSignals[STATE_COMMITMENT_INDEX]);
        if (states[stateId].stateId != bytes32(0)) revert DuplicateReject("STATE", stateId);
        bytes32 proofHash = calculateProofHash(proof, publicSignals);
        if (usedProofHashes[proofHash]) revert ReplayReject("STATE_PROOF", proofHash);
        if (!verifier.verifyProof(proof.a, proof.b, proof.c, publicSignals)) {
            revert Groth16VerificationFalse();
        }
        if (stateId == bytes32(0) || block.timestamp > type(uint64).max) revert InvalidConfiguration();
        // All effects, including consumption, occur only after the verifier returns true.
        states[stateId] = StateRecord({
            stateId: stateId,
            requestId: requestId,
            stateCommitment: publicSignals[STATE_COMMITMENT_INDEX],
            inputCommitment: request.inputCommitment,
            modelVersion: uint64(modelVersion),
            schemaVersion: model.schemaVersion,
            originalPrediction: uint8(publicSignals[ORIGINAL_PREDICTION_INDEX]),
            proofHash: proofHash,
            stateCircuitVersion: model.stateCircuitVersion,
            modelCommitmentVersion: model.modelCommitmentVersion,
            createdAt: uint64(block.timestamp)
        });
        usedProofHashes[proofHash] = true;
        inputRegistry.consumeRequest(requestId, stateId);
        emit StateCertified(stateId, requestId, uint64(modelVersion), publicSignals[STATE_COMMITMENT_INDEX], proofHash);
    }

    function getState(bytes32 stateId) external view returns (StateRecord memory record) {
        record = states[stateId];
        if (record.stateId == bytes32(0)) revert RegistryBindingReject(102);
    }

    function _match(uint256 index, uint256 actual, uint256 expected) private pure {
        if (actual != expected) revert RegistryBindingReject(index);
    }

    function _checkFields(uint256[12] calldata signals) private pure {
        for (uint256 i = 0; i < 12; ++i) {
            if (signals[i] >= SCALAR_FIELD) revert FieldElementReject(i, signals[i]);
        }
    }

    function _checkProofCoordinates(Groth16Proof calldata proof) private pure {
        // Coordinates are base-field elements, not scalar-field public inputs.
        // Reject alternate uint256 encodings instead of hashing one value and verifying another.
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
