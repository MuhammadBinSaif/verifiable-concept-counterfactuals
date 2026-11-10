// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

// Adapted from the approved V3 research source; see THIRD_PARTY_NOTICES.md.
// Cryptographic domain identifiers intentionally retain their original bytes.

/// @notice Local research registry. Registration authority is the deploying coordinator.
contract ModelRegistryV3 {
    uint256 public constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant LEGACY_MODEL_COMMITMENT = 1893305690795230111917111913131144787999123470732445036495147438964333217795;
    address public immutable coordinator;

    struct ModelRegistration {
        bytes32 modelArtifactKeccak;
        uint256 fullModelCommitment;
        uint256 headCommitment;
        uint64 schemaVersion;
        uint64 architectureVersion;
        uint64 quantizationVersion;
        uint64 preprocessingVersion;
        uint64 stateCircuitVersion;
        uint64 explanationCircuitVersion;
        uint64 modelCommitmentVersion;
    }

    struct ModelRecord {
        bytes32 modelArtifactKeccak;
        uint256 fullModelCommitment;
        uint256 headCommitment;
        uint64 schemaVersion;
        uint64 architectureVersion;
        uint64 quantizationVersion;
        uint64 preprocessingVersion;
        uint64 stateCircuitVersion;
        uint64 explanationCircuitVersion;
        uint64 modelCommitmentVersion;
        uint64 registeredAt;
        bool active;
    }

    mapping(uint64 => bytes32) public schemaManifestKeccak;
    mapping(uint64 => ModelRecord) private models;

    error AuthorizationReject();
    error DuplicateReject(bytes32 kind, bytes32 id);
    error RegistryBindingReject(uint256 signalIndex);
    error FieldElementReject(uint256 index, uint256 value);
    error UnsupportedVersion();
    error InvalidConfiguration();
    error StaleModelReject(uint256 modelVersion);

    event SchemaRegistered(uint64 indexed schemaVersion, bytes32 schemaManifestKeccak);
    event ModelRegistered(
        uint64 indexed modelVersion,
        bytes32 modelArtifactKeccak,
        uint256 fullModelCommitment,
        uint256 headCommitment
    );
    event ModelDeactivated(uint64 indexed modelVersion);

    constructor() {
        coordinator = msg.sender;
    }

    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert AuthorizationReject();
        _;
    }

    function registerSchema(uint64 schemaVersion, bytes32 manifestKeccak) external onlyCoordinator {
        if (schemaVersion == 0 || manifestKeccak == bytes32(0)) revert InvalidConfiguration();
        if (schemaManifestKeccak[schemaVersion] != bytes32(0)) {
            revert DuplicateReject("SCHEMA", bytes32(uint256(schemaVersion)));
        }
        schemaManifestKeccak[schemaVersion] = manifestKeccak;
        emit SchemaRegistered(schemaVersion, manifestKeccak);
    }

    function registerModel(uint64 modelVersion, ModelRegistration calldata registration)
        external onlyCoordinator
    {
        if (modelVersion == 0 || registration.modelArtifactKeccak == bytes32(0)) {
            revert InvalidConfiguration();
        }
        if (models[modelVersion].modelArtifactKeccak != bytes32(0)) {
            revert DuplicateReject("MODEL", bytes32(uint256(modelVersion)));
        }
        if (schemaManifestKeccak[registration.schemaVersion] == bytes32(0)) {
            revert RegistryBindingReject(2);
        }
        // Frozen V3 relations preserve the original structural versions and bind commitment v2.
        // Registering a new weight instance remains possible without changing the relation.
        if (
            registration.architectureVersion != 101 || registration.schemaVersion != 101
                || registration.quantizationVersion != 1 || registration.preprocessingVersion != 1
                || registration.stateCircuitVersion != 102 || registration.explanationCircuitVersion != 102
                || registration.modelCommitmentVersion != 2
        ) revert UnsupportedVersion();
        if (registration.fullModelCommitment == LEGACY_MODEL_COMMITMENT) revert RegistryBindingReject(5);
        _checkCommitment(5, registration.fullModelCommitment);
        _checkCommitment(6, registration.headCommitment);
        if (block.timestamp > type(uint64).max) revert InvalidConfiguration();
        models[modelVersion] = ModelRecord({
            modelArtifactKeccak: registration.modelArtifactKeccak,
            fullModelCommitment: registration.fullModelCommitment,
            headCommitment: registration.headCommitment,
            schemaVersion: registration.schemaVersion,
            architectureVersion: registration.architectureVersion,
            quantizationVersion: registration.quantizationVersion,
            preprocessingVersion: registration.preprocessingVersion,
            stateCircuitVersion: registration.stateCircuitVersion,
            explanationCircuitVersion: registration.explanationCircuitVersion,
            modelCommitmentVersion: registration.modelCommitmentVersion,
            registeredAt: uint64(block.timestamp),
            active: true
        });
        emit ModelRegistered(
            modelVersion,
            registration.modelArtifactKeccak,
            registration.fullModelCommitment,
            registration.headCommitment
        );
    }

    function getModel(uint64 modelVersion) external view returns (ModelRecord memory record) {
        record = models[modelVersion];
        if (record.modelArtifactKeccak == bytes32(0)) revert RegistryBindingReject(0);
    }

    function deactivateModel(uint64 modelVersion) external onlyCoordinator {
        ModelRecord storage record = models[modelVersion];
        if (record.modelArtifactKeccak == bytes32(0)) revert RegistryBindingReject(0);
        if (!record.active) revert StaleModelReject(modelVersion);
        record.active = false;
        emit ModelDeactivated(modelVersion);
    }

    function _checkCommitment(uint256 index, uint256 value) private pure {
        if (value >= SCALAR_FIELD) revert FieldElementReject(index, value);
    }
}
