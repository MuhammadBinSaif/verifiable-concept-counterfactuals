// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.37;

// ABI declarations only: no acceptance logic, placeholder proof, or verifier bytecode.
// The pipeline deploys the real freshly exported Groth16 verifier implementations.
interface IStateGroth16VerifierV3 {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[12] calldata publicSignals) external view returns (bool);
}
interface IExplanationGroth16VerifierV3 {
    function verifyProof(uint256[2] calldata a, uint256[2][2] calldata b,
        uint256[2] calldata c, uint256[33] calldata publicSignals) external view returns (bool);
}
