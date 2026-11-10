pragma circom 2.2.3;
include "poseidon_sequence.circom";
include "quantized_activations.circom";

template ModelFoldStress(n,k) {
    assert(k == 8);
    signal input payload[n];
    signal output commitment;
    var chunks = (n+k-1)\k;
    signal accumulator[chunks+1];
    component initial = Poseidon(4);
    initial.inputs[0] <== 1006;
    initial.inputs[1] <== 2;
    initial.inputs[2] <== n;
    initial.inputs[3] <== k;
    accumulator[0] <== initial.out;
    component links[chunks];
    for (var i=0; i<chunks; i++) {
        links[i] = Poseidon(k+1);
        links[i].inputs[0] <== accumulator[i];
        for (var j=0; j<k; j++) {
            if (i*k+j < n) links[i].inputs[j+1] <== payload[i*k+j];
            else links[i].inputs[j+1] <== 0;
        }
        accumulator[i+1] <== links[i].out;
    }
    commitment <== accumulator[chunks];
}

template AuthenticatedStateStress(C) {
    signal input stateCircuitVersion;
    signal input explanationCircuitVersion;
    signal input modelCommitmentVersion;
    signal input modelVersion;
    signal input architectureVersion;
    signal input schemaVersion;
    signal input quantizationVersion;
    signal input preprocessingVersion;
    signal input C_model_v2;
    signal input C_head;
    signal input C_input;
    signal input originalPrediction;
    signal input stateNonce;
    signal input cQ[C];
    signal input deltaWQ[C];
    signal input deltaBQ;
    signal output commitment;
    component state = StateSequenceV1(14+2*C,1004);
    state.payload[0] <== stateCircuitVersion;
    state.payload[1] <== explanationCircuitVersion;
    state.payload[2] <== modelCommitmentVersion;
    state.payload[3] <== modelVersion;
    state.payload[4] <== architectureVersion;
    state.payload[5] <== schemaVersion;
    state.payload[6] <== quantizationVersion;
    state.payload[7] <== preprocessingVersion;
    state.payload[8] <== C_model_v2;
    state.payload[9] <== C_head;
    state.payload[10] <== C_input;
    state.payload[11] <== originalPrediction;
    state.payload[12] <== stateNonce;
    for (var j=0; j<C; j++) state.payload[13+j] <== cQ[j];
    for (var j=0; j<C; j++) state.payload[13+C+j] <== deltaWQ[j];
    state.payload[13+2*C] <== deltaBQ;
    commitment <== state.commitment;
}


// Bind the actual modified concepts and a private nonce.
// Ordered payload: scheme, explanation version, state version, model version,
// certified state, private opening nonce, then all actual modified concepts.
template ExplanationCommitmentStress(C) {
    assert(C == 16);
    signal input explanationCircuitVersion;
    signal input stateCircuitVersion;
    signal input modelVersion;
    signal input C_state_v3;
    signal input explanationNonce;
    signal input cPrimeQ[C];
    signal output commitment;
    // Entropy and freshness come from the off-circuit CSPRNG.
    component nonceIsZero = IsZero();
    nonceIsZero.in <== explanationNonce;
    nonceIsZero.out === 0;
    component explanation = StateSequenceV1(6+C,1007);
    explanation.payload[0] <== 1;
    explanation.payload[1] <== explanationCircuitVersion;
    explanation.payload[2] <== stateCircuitVersion;
    explanation.payload[3] <== modelVersion;
    explanation.payload[4] <== C_state_v3;
    explanation.payload[5] <== explanationNonce;
    for (var j=0; j<C; j++) explanation.payload[6+j] <== cPrimeQ[j];
    commitment <== explanation.commitment;
}
