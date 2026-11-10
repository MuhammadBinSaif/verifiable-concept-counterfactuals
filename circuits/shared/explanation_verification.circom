pragma circom 2.2.3;
include "decision_head.circom";
include "commitments.circom";
include "intervention_policy.circom";

template ExplanationProofCoreStress(C,ARCH,SCHEMA,STATE,EXPLANATION) {
    signal input modelVersion;
    signal input architectureVersion;
    signal input schemaVersion;
    signal input quantizationVersion;
    signal input preprocessingVersion;
    signal input C_model_v2;
    signal input C_head;
    signal input C_input;
    signal input C_state_v3;
    signal input originalPrediction;
    signal input stateCircuitVersion;
    signal input modelCommitmentVersion;
    signal input explanationCircuitVersion;
    signal input counterfactualPrediction;
    signal input allowedMask[C];
    signal input sparsityBound;
    signal input l1Bound;
    signal input C_explanation;
    signal input cQ[C];
    signal input stateNonce;
    signal input explanationNonce;
    signal input cPrimeQ[C];
    signal input deltaWQ[C];
    signal input deltaBQ;
    signal output openedState;
    signal output changedMask[C];
    signal output deltaQ[C];
    signal output L0;
    signal output L1Q;
    signal output marginQ;
    signal output prediction;
    architectureVersion === ARCH;
    schemaVersion === SCHEMA;
    quantizationVersion === 1;
    preprocessingVersion === 1;
    stateCircuitVersion === STATE;
    modelCommitmentVersion === 2;
    explanationCircuitVersion === EXPLANATION;
    originalPrediction === 1;
    counterfactualPrediction === 0;

    component policy = ExplanationPolicyStress(C);
    for (var j=0; j<C; j++) {
        policy.cQ[j] <== cQ[j];
        policy.cPrimeQ[j] <== cPrimeQ[j];
        policy.allowedMask[j] <== allowedMask[j];
    }
    policy.sparsityBound <== sparsityBound;
    policy.l1Bound <== l1Bound;
    for (var j=0; j<C; j++) {
        deltaQ[j] <== policy.deltaQ[j];
        changedMask[j] <== policy.changedMask[j];
    }
    L0 <== policy.L0;
    L1Q <== policy.L1Q;

    component state = AuthenticatedStateStress(C);
    state.stateCircuitVersion <== stateCircuitVersion;
    state.explanationCircuitVersion <== explanationCircuitVersion;
    state.modelCommitmentVersion <== modelCommitmentVersion;
    state.modelVersion <== modelVersion;
    state.architectureVersion <== architectureVersion;
    state.schemaVersion <== schemaVersion;
    state.quantizationVersion <== quantizationVersion;
    state.preprocessingVersion <== preprocessingVersion;
    state.C_model_v2 <== C_model_v2;
    state.C_head <== C_head;
    state.C_input <== C_input;
    state.originalPrediction <== originalPrediction;
    state.stateNonce <== stateNonce;
    for (var j=0; j<C; j++) {
        state.cQ[j] <== cQ[j];
        state.deltaWQ[j] <== deltaWQ[j];
    }
    state.deltaBQ <== deltaBQ;
    openedState <== state.commitment;
    openedState === C_state_v3;

    component explanation = ExplanationCommitmentStress(C);
    explanation.explanationCircuitVersion <== explanationCircuitVersion;
    explanation.stateCircuitVersion <== stateCircuitVersion;
    explanation.modelVersion <== modelVersion;
    explanation.C_state_v3 <== C_state_v3;
    explanation.explanationNonce <== explanationNonce;
    for (var j=0; j<C; j++) explanation.cPrimeQ[j] <== cPrimeQ[j];
    explanation.commitment === C_explanation;

    component counterfactual = MarginHeadStress(C);
    for (var j=0; j<C; j++) {
        counterfactual.cQ[j] <== cPrimeQ[j];
        counterfactual.deltaWQ[j] <== deltaWQ[j];
    }
    counterfactual.deltaBQ <== deltaBQ;
    marginQ <== counterfactual.marginQ;
    prediction <== counterfactual.prediction;
    prediction === counterfactualPrediction;
}

template ExplanationProofStress(C,ARCH,SCHEMA,STATE,EXPLANATION) {
    signal input modelVersion;
    signal input architectureVersion;
    signal input schemaVersion;
    signal input quantizationVersion;
    signal input preprocessingVersion;
    signal input C_model_v2;
    signal input C_head;
    signal input C_input;
    signal input C_state_v3;
    signal input originalPrediction;
    signal input stateCircuitVersion;
    signal input modelCommitmentVersion;
    signal input explanationCircuitVersion;
    signal input counterfactualPrediction;
    signal input allowedMask[C];
    signal input sparsityBound;
    signal input l1Bound;
    signal input C_explanation;
    signal input cQ[C];
    signal input stateNonce;
    signal input explanationNonce;
    signal input cPrimeQ[C];
    signal input deltaWQ[C];
    signal input deltaBQ;
    component core = ExplanationProofCoreStress(C,ARCH,SCHEMA,STATE,EXPLANATION);
    core.modelVersion <== modelVersion;
    core.architectureVersion <== architectureVersion;
    core.schemaVersion <== schemaVersion;
    core.quantizationVersion <== quantizationVersion;
    core.preprocessingVersion <== preprocessingVersion;
    core.C_model_v2 <== C_model_v2;
    core.C_head <== C_head;
    core.C_input <== C_input;
    core.C_state_v3 <== C_state_v3;
    core.originalPrediction <== originalPrediction;
    core.stateCircuitVersion <== stateCircuitVersion;
    core.modelCommitmentVersion <== modelCommitmentVersion;
    core.explanationCircuitVersion <== explanationCircuitVersion;
    core.counterfactualPrediction <== counterfactualPrediction;
    for (var i=0; i<C; i++) core.allowedMask[i] <== allowedMask[i];
    core.sparsityBound <== sparsityBound;
    core.l1Bound <== l1Bound;
    core.C_explanation <== C_explanation;
    for (var i=0; i<C; i++) core.cQ[i] <== cQ[i];
    core.stateNonce <== stateNonce;
    core.explanationNonce <== explanationNonce;
    for (var i=0; i<C; i++) core.cPrimeQ[i] <== cPrimeQ[i];
    for (var i=0; i<C; i++) core.deltaWQ[i] <== deltaWQ[i];
    core.deltaBQ <== deltaBQ;
    _ <== core.openedState;
    for (var i=0; i<C; i++) _ <== core.changedMask[i];
    for (var i=0; i<C; i++) _ <== core.deltaQ[i];
    _ <== core.L0;
    _ <== core.L1Q;
    _ <== core.marginQ;
    _ <== core.prediction;
}
