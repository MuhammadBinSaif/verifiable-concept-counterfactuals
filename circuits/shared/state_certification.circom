pragma circom 2.2.3;
include "encoder.circom";
include "decision_head.circom";
include "commitments.circom";

template StateCertificationCoreLarge(D,H1,H2,C,ARCH,SCHEMA,STATE,EXPLANATION) {
    var E = D*H1+H1+H1*H2+H2+H2*C+C;
    var P = E+2*C+2;
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
    signal input xQ[D];
    signal input inputNonce;
    signal input parametersQ[P];
    signal input modelBlind;
    signal input headBlind;
    signal input stateNonce;
    signal input deltaWQ[C];
    signal input deltaBQ;
    signal output firstPreactivationQ[H1];
    signal output hidden1Q[H1];
    signal output secondPreactivationQ[H2];
    signal output hidden2Q[H2];
    signal output encoderPreactivationQ[C];
    signal output conceptsQ[C];
    signal output marginQ;
    signal output prediction;
    architectureVersion === ARCH;
    schemaVersion === SCHEMA;
    quantizationVersion === 1;
    preprocessingVersion === 1;
    stateCircuitVersion === STATE;
    modelCommitmentVersion === 2;
    component claimedPrediction = BooleanV1();
    claimedPrediction.in <== originalPrediction;

    component encoder = IntegerEncoderDeepStress(D,H1,H2,C);
    for (var i=0; i<D; i++) encoder.xQ[i] <== xQ[i];
    for (var i=0; i<E; i++) encoder.parametersQ[i] <== parametersQ[i];
    for (var i=0; i<H1; i++) {
        firstPreactivationQ[i] <== encoder.firstPreactivationQ[i];
        hidden1Q[i] <== encoder.hidden1Q[i];
    }
    for (var i=0; i<H2; i++) {
        secondPreactivationQ[i] <== encoder.secondPreactivationQ[i];
        hidden2Q[i] <== encoder.hidden2Q[i];
    }
    for (var j=0; j<C; j++) {
        encoderPreactivationQ[j] <== encoder.encoderPreactivationQ[j];
        conceptsQ[j] <== encoder.conceptsQ[j];
    }
    component derive = AuthenticatedDeltaHeadStress(C);
    for (var i=0; i<2*C+2; i++) derive.headParametersQ[i] <== parametersQ[E+i];
    for (var j=0; j<C; j++) derive.deltaWQ[j] <== deltaWQ[j];
    derive.deltaBQ <== deltaBQ;
    component head = MarginHeadStress(C);
    for (var j=0; j<C; j++) {
        head.cQ[j] <== encoder.conceptsQ[j];
        head.deltaWQ[j] <== deltaWQ[j];
    }
    head.deltaBQ <== deltaBQ;
    marginQ <== head.marginQ;
    prediction <== head.prediction;
    originalPrediction === prediction;

    component model = ModelFoldStress(P+5,8);
    model.payload[0] <== modelVersion;
    model.payload[1] <== architectureVersion;
    model.payload[2] <== schemaVersion;
    model.payload[3] <== quantizationVersion;
    model.payload[4] <== modelBlind;
    for (var i=0; i<P; i++) model.payload[5+i] <== parametersQ[i];
    model.commitment === C_model_v2;
    component headCommitment = StateSequenceV1(7+2*C,1002);
    headCommitment.payload[0] <== modelVersion;
    headCommitment.payload[1] <== architectureVersion;
    headCommitment.payload[2] <== schemaVersion;
    headCommitment.payload[3] <== quantizationVersion;
    headCommitment.payload[4] <== headBlind;
    for (var i=0; i<2*C+2; i++) headCommitment.payload[5+i] <== parametersQ[E+i];
    headCommitment.commitment === C_head;
    component inputCommitment = StateSequenceV1(D+3,1003);
    inputCommitment.payload[0] <== modelVersion;
    inputCommitment.payload[1] <== preprocessingVersion;
    inputCommitment.payload[2] <== inputNonce;
    for (var i=0; i<D; i++) inputCommitment.payload[3+i] <== xQ[i];
    inputCommitment.commitment === C_input;
    component state = AuthenticatedStateStress(C);
    state.stateCircuitVersion <== stateCircuitVersion;
    state.explanationCircuitVersion <== EXPLANATION;
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
        state.cQ[j] <== encoder.conceptsQ[j];
        state.deltaWQ[j] <== deltaWQ[j];
    }
    state.deltaBQ <== deltaBQ;
    state.commitment === C_state_v3;
}

template StateCertificationLarge(D,H1,H2,C,ARCH,SCHEMA,STATE,EXPLANATION) {
    assert(D == 200 && H1 == 64 && H2 == 32 && C == 16);
    var P = D*H1+H1+H1*H2+H2+H2*C+C+2*C+2;
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
    signal input xQ[D];
    signal input inputNonce;
    signal input parametersQ[P];
    signal input modelBlind;
    signal input headBlind;
    signal input stateNonce;
    signal input deltaWQ[C];
    signal input deltaBQ;
    component core = StateCertificationCoreLarge(D,H1,H2,C,ARCH,SCHEMA,STATE,EXPLANATION);
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
    for (var i=0; i<D; i++) core.xQ[i] <== xQ[i];
    core.inputNonce <== inputNonce;
    for (var i=0; i<P; i++) core.parametersQ[i] <== parametersQ[i];
    core.modelBlind <== modelBlind;
    core.headBlind <== headBlind;
    core.stateNonce <== stateNonce;
    for (var i=0; i<C; i++) core.deltaWQ[i] <== deltaWQ[i];
    core.deltaBQ <== deltaBQ;
    for (var i=0; i<H1; i++) _ <== core.firstPreactivationQ[i];
    for (var i=0; i<H1; i++) _ <== core.hidden1Q[i];
    for (var i=0; i<H2; i++) _ <== core.secondPreactivationQ[i];
    for (var i=0; i<H2; i++) _ <== core.hidden2Q[i];
    for (var i=0; i<C; i++) _ <== core.encoderPreactivationQ[i];
    for (var i=0; i<C; i++) _ <== core.conceptsQ[i];
    _ <== core.marginQ;
    _ <== core.prediction;
}
