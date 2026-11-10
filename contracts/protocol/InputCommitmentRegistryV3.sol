// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

// Adapted from the approved V3 research source; see THIRD_PARTY_NOTICES.md.
// Cryptographic domain identifiers intentionally retain their original bytes.

// Interface only; this introduces no additional deployable contract.
interface IStateRegistryInputBinding {
    function inputRegistry() external view returns (address);
}

/// @notice Immutable public C_input anchoring with a distinct public blockchain request nonce.
contract InputCommitmentRegistryV3 {
    uint256 public constant SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    bytes32 public constant DOMAIN_REQUEST = keccak256("FL-XAI-ZKP-BC:REQUEST:v3");
    address public immutable coordinator;
    address public stateRegistry;

    struct RequestRecord {
        bytes32 requestId;
        uint256 inputCommitment;
        uint64 createdAt;
        bool consumed;
        bytes32 stateId;
    }

    mapping(bytes32 => RequestRecord) private requests;

    error AuthorizationReject();
    error DuplicateReject(bytes32 kind, bytes32 id);
    error ReplayReject(bytes32 kind, bytes32 id);
    error RegistryBindingReject(uint256 signalIndex);
    error FieldElementReject(uint256 index, uint256 value);
    error InvalidConfiguration();

    event InputRequestRegistered(bytes32 indexed requestId, uint256 inputCommitment);
    event StateRegistryBound(address indexed stateRegistry);

    constructor() {
        coordinator = msg.sender;
    }

    /// @dev Resolves the deployment dependency once, under the same trusted coordinator.
    function bindStateRegistry(address registry) external {
        if (msg.sender != coordinator) revert AuthorizationReject();
        if (stateRegistry != address(0)) revert DuplicateReject("REGISTRY_BIND", bytes32(0));
        if (
            registry.code.length == 0
                || IStateRegistryInputBinding(registry).inputRegistry() != address(this)
        ) revert InvalidConfiguration();
        stateRegistry = registry;
        emit StateRegistryBound(registry);
    }

    function calculateRequestId(uint256 inputCommitment, bytes32 requestNonce)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN_REQUEST, inputCommitment, requestNonce));
    }

    function registerInputRequest(uint256 inputCommitment, bytes32 requestNonce)
        external returns (bytes32 requestId)
    {
        if (inputCommitment >= SCALAR_FIELD) revert FieldElementReject(7, inputCommitment);
        requestId = calculateRequestId(inputCommitment, requestNonce);
        if (requests[requestId].requestId != bytes32(0)) {
            revert DuplicateReject("REQUEST", requestId);
        }
        if (requestId == bytes32(0) || block.timestamp > type(uint64).max) {
            revert InvalidConfiguration();
        }
        requests[requestId] = RequestRecord({
            requestId: requestId,
            inputCommitment: inputCommitment,
            createdAt: uint64(block.timestamp),
            consumed: false,
            stateId: bytes32(0)
        });
        emit InputRequestRegistered(requestId, inputCommitment);
    }

    function getRequest(bytes32 requestId) external view returns (RequestRecord memory record) {
        record = requests[requestId];
        if (record.requestId == bytes32(0)) revert RegistryBindingReject(100);
    }

    /// @dev Only the one bound Stage A registry may consume a request, after verification.
    function consumeRequest(bytes32 requestId, bytes32 stateId) external {
        if (msg.sender != stateRegistry || stateRegistry == address(0)) revert AuthorizationReject();
        RequestRecord storage record = requests[requestId];
        if (record.requestId == bytes32(0)) revert RegistryBindingReject(100);
        if (record.consumed) revert ReplayReject("REQUEST", requestId);
        if (stateId == bytes32(0)) revert InvalidConfiguration();
        record.consumed = true;
        record.stateId = stateId;
    }
}
