pragma circom 2.2.3;
include "../shared/explanation_verification.circom";
component main {public [modelVersion,architectureVersion,schemaVersion,quantizationVersion,preprocessingVersion,C_model_v2,C_head,C_input,C_state_v3,originalPrediction,stateCircuitVersion,modelCommitmentVersion,explanationCircuitVersion,counterfactualPrediction,allowedMask,sparsityBound,l1Bound,C_explanation]} = ExplanationProofStress(16,101,101,102,102);
