pragma circom 2.2.3;
include "encoder.circom";
include "decision_head.circom";
include "commitments.circom";

template IntegerEncoderSingleComparison(D,H1,C) {
    var L1 = D*H1+H1;
    var L2 = H1*C+C;
    var A1 = D*334210000+70340000;
    var R1 = (A1+9999)\10000;
    var A2 = H1*R1*20465+100660000;
    var R2 = (A2+9999)\10000;
    signal input xQ[D];
    signal input parametersQ[L1+L2];
    signal output firstPreactivationQ[H1];
    signal output hidden1Q[H1];
    signal output encoderPreactivationQ[C];
    signal output conceptsQ[C];
    component first = QuantizedAffineStress(D,H1,10000,33421,7034);
    component relu[H1];
    for (var i=0;i<D;i++) first.xQ[i] <== xQ[i];
    for (var i=0;i<L1;i++) first.parametersQ[i] <== parametersQ[i];
    for (var i=0;i<H1;i++) {
        firstPreactivationQ[i] <== first.preactivationQ[i];
        relu[i] = ReLUV1(R1,StressBits(R1));
        relu[i].in <== firstPreactivationQ[i];
        hidden1Q[i] <== relu[i].out;
    }
    component last = QuantizedAffineStress(H1,C,R1,20465,10066);
    component sigmoid[C];
    for (var i=0;i<H1;i++) last.xQ[i] <== hidden1Q[i];
    for (var i=0;i<L2;i++) last.parametersQ[i] <== parametersQ[L1+i];
    for (var i=0;i<C;i++) {
        encoderPreactivationQ[i] <== last.preactivationQ[i];
        sigmoid[i] = StressHardSigmoid(R2);
        sigmoid[i].in <== encoderPreactivationQ[i];
        conceptsQ[i] <== sigmoid[i].out;
    }
}

template IntegerEncoderComparison(D,H1,H2,C) {
    var E = D*H1+H1 + (H2==0 ? H1*C+C : H1*H2+H2+H2*C+C);
    signal input xQ[D];
    signal input parametersQ[E];
    signal output firstPreactivationQ[H1];
    signal output hidden1Q[H1];
    signal output secondPreactivationQ[H2];
    signal output hidden2Q[H2];
    signal output encoderPreactivationQ[C];
    signal output conceptsQ[C];
    if (H2==0) {
        component single = IntegerEncoderSingleComparison(D,H1,C);
        for (var i=0;i<D;i++) single.xQ[i] <== xQ[i];
        for (var i=0;i<E;i++) single.parametersQ[i] <== parametersQ[i];
        for (var i=0;i<H1;i++) {
            firstPreactivationQ[i] <== single.firstPreactivationQ[i];
            hidden1Q[i] <== single.hidden1Q[i];
        }
        for (var i=0;i<C;i++) {
            encoderPreactivationQ[i] <== single.encoderPreactivationQ[i];
            conceptsQ[i] <== single.conceptsQ[i];
        }
    } else {
        component deep = IntegerEncoderDeepStress(D,H1,H2,C);
        for (var i=0;i<D;i++) deep.xQ[i] <== xQ[i];
        for (var i=0;i<E;i++) deep.parametersQ[i] <== parametersQ[i];
        for (var i=0;i<H1;i++) {
            firstPreactivationQ[i] <== deep.firstPreactivationQ[i];
            hidden1Q[i] <== deep.hidden1Q[i];
        }
        for (var i=0;i<H2;i++) {
            secondPreactivationQ[i] <== deep.secondPreactivationQ[i];
            hidden2Q[i] <== deep.hidden2Q[i];
        }
        for (var i=0;i<C;i++) {
            encoderPreactivationQ[i] <== deep.encoderPreactivationQ[i];
            conceptsQ[i] <== deep.conceptsQ[i];
        }
    }
}


template ExplanationCommitmentComparison(C) {
    assert(C==4 || C==8 || C==16);
    signal input explanationCircuitVersion;
    signal input stateCircuitVersion;
    signal input modelVersion;
    signal input C_state_v3;
    signal input explanationNonce;
    signal input cPrimeQ[C];
    signal output commitment;
    component nonzero=IsZero();
    nonzero.in <== explanationNonce;
    nonzero.out === 0;
    component sequence=StateSequenceV1(6+C,1007);
    sequence.payload[0] <== 1;
    sequence.payload[1] <== explanationCircuitVersion;
    sequence.payload[2] <== stateCircuitVersion;
    sequence.payload[3] <== modelVersion;
    sequence.payload[4] <== C_state_v3;
    sequence.payload[5] <== explanationNonce;
    for (var i=0;i<C;i++) sequence.payload[6+i] <== cPrimeQ[i];
    commitment <== sequence.commitment;
}

template ExplanationPolicyComparison(C) {
    assert(C==4 || C==8 || C==16);
    signal input cQ[C];
    signal input cPrimeQ[C];
    signal input allowedMask[C];
    signal input sparsityBound;
    signal input l1Bound;
    signal output changedMask[C];
    signal output deltaQ[C];
    signal output L0;
    signal output L1Q;
    // Public policy bounds must match the evaluated relation.
    sparsityBound === 1;
    l1Bound === 4000;
    component originalBounds[C];
    component counterfactualBounds[C];
    component deltaBounds[C];
    component unchanged[C];
    component maskBooleans[C];
    var l0 = 0;
    var l1 = 0;
    for (var j=0; j<C; j++) {
        originalBounds[j] = UnsignedBoundV1(10000,14);
        counterfactualBounds[j] = UnsignedBoundV1(10000,14);
        originalBounds[j].in <== cQ[j];
        counterfactualBounds[j].in <== cPrimeQ[j];
        deltaQ[j] <== cPrimeQ[j]-cQ[j];
        deltaBounds[j] = UnsignedBoundV1(10000,14);
        deltaBounds[j].in <== deltaQ[j];
        unchanged[j] = IsZero();
        unchanged[j].in <== deltaQ[j];
        changedMask[j] <== 1-unchanged[j].out;
        allowedMask[j] === 1;
        maskBooleans[j] = BooleanV1();
        maskBooleans[j].in <== allowedMask[j];
        changedMask[j]*(1-allowedMask[j]) === 0;
        l0 += changedMask[j];
        l1 += deltaQ[j];
    }
    L0 <== l0;
    L1Q <== l1;
    component sparsityPublicBound = UnsignedBoundV1(C,StressBits(C));
    component sparsityActualBound = UnsignedBoundV1(C,StressBits(C));
    component sparsitySlack = UnsignedBoundV1(C,StressBits(C));
    sparsityPublicBound.in <== sparsityBound;
    sparsityActualBound.in <== L0;
    sparsitySlack.in <== sparsityBound-L0;
    component distancePublicBound = UnsignedBoundV1(10000*C,StressBits(10000*C));
    component distanceActualBound = UnsignedBoundV1(10000*C,StressBits(10000*C));
    component distanceSlack = UnsignedBoundV1(10000*C,StressBits(10000*C));
    distancePublicBound.in <== l1Bound;
    distanceActualBound.in <== L1Q;
    distanceSlack.in <== l1Bound-L1Q;
}

template ModelCommitmentComparison(N) {
    signal input payload[N];
    signal output commitment;
    component folded=ModelFoldStress(N,8);
    for(var i=0;i<N;i++) folded.payload[i] <== payload[i];
    commitment <== folded.commitment;
}

template StateCertificationCoreComparison(D,H1,H2,C,ARCH,SCHEMA,STATE,EXPLANATION,COMMITMENT) {
    var E=D*H1+H1 + (H2==0 ? H1*C+C : H1*H2+H2+H2*C+C);
    var P=E+2*C+2;
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
    modelVersion === 1;
    architectureVersion === ARCH;
    schemaVersion === SCHEMA;
    quantizationVersion === 1;
    preprocessingVersion === 1;
    stateCircuitVersion === STATE;
    modelCommitmentVersion === COMMITMENT;
    component claimedPrediction=BooleanV1();
    claimedPrediction.in <== originalPrediction;
    component encoder=IntegerEncoderComparison(D,H1,H2,C);
    for(var i=0;i<D;i++) encoder.xQ[i] <== xQ[i];
    for(var i=0;i<E;i++) encoder.parametersQ[i] <== parametersQ[i];
    for(var i=0;i<H1;i++) firstPreactivationQ[i] <== encoder.firstPreactivationQ[i];
    for(var i=0;i<H1;i++) hidden1Q[i] <== encoder.hidden1Q[i];
    for(var i=0;i<H2;i++) secondPreactivationQ[i] <== encoder.secondPreactivationQ[i];
    for(var i=0;i<H2;i++) hidden2Q[i] <== encoder.hidden2Q[i];
    for(var i=0;i<C;i++) encoderPreactivationQ[i] <== encoder.encoderPreactivationQ[i];
    for(var i=0;i<C;i++) conceptsQ[i] <== encoder.conceptsQ[i];
    component derive=AuthenticatedDeltaHeadStress(C);
    for(var i=0;i<2*C+2;i++) derive.headParametersQ[i] <== parametersQ[E+i];
    for(var i=0;i<C;i++) derive.deltaWQ[i] <== deltaWQ[i];
    derive.deltaBQ <== deltaBQ;
    component margin=MarginHeadStress(C);
    for(var i=0;i<C;i++) {
        margin.cQ[i] <== conceptsQ[i];
        margin.deltaWQ[i] <== deltaWQ[i];
    }
    margin.deltaBQ <== deltaBQ;
    marginQ <== margin.marginQ;
    prediction <== margin.prediction;
    originalPrediction === prediction;
    component model=ModelCommitmentComparison(P+5);
    model.payload[0] <== modelVersion;
    model.payload[1] <== architectureVersion;
    model.payload[2] <== schemaVersion;
    model.payload[3] <== quantizationVersion;
    model.payload[4] <== modelBlind;
    for(var i=0;i<P;i++) model.payload[5+i] <== parametersQ[i];
    model.commitment === C_model_v2;
    component head=StateSequenceV1(7+2*C,1002);
    head.payload[0] <== modelVersion;
    head.payload[1] <== architectureVersion;
    head.payload[2] <== schemaVersion;
    head.payload[3] <== quantizationVersion;
    head.payload[4] <== headBlind;
    for(var i=0;i<2*C+2;i++) head.payload[5+i] <== parametersQ[E+i];
    head.commitment === C_head;
    component inp=StateSequenceV1(D+3,1003);
    inp.payload[0] <== modelVersion;
    inp.payload[1] <== preprocessingVersion;
    inp.payload[2] <== inputNonce;
    for(var i=0;i<D;i++) inp.payload[3+i] <== xQ[i];
    inp.commitment === C_input;
    component state=AuthenticatedStateStress(C);
    state.stateCircuitVersion <== stateCircuitVersion;
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
    state.explanationCircuitVersion <== EXPLANATION;
    for(var i=0;i<C;i++) {
        state.cQ[i] <== conceptsQ[i];
        state.deltaWQ[i] <== deltaWQ[i];
    }
    state.deltaBQ <== deltaBQ;
    state.commitment === C_state_v3;
}

template StateCertificationComparison(D,H1,H2,C,ARCH,SCHEMA,STATE,EXPLANATION,COMMITMENT) {
    var E=D*H1+H1 + (H2==0 ? H1*C+C : H1*H2+H2+H2*C+C);
    var P=E+2*C+2;
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
    component core=StateCertificationCoreComparison(D,H1,H2,C,ARCH,SCHEMA,STATE,EXPLANATION,COMMITMENT);
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
    for (var i=0;i<D;i++) core.xQ[i] <== xQ[i];
    core.inputNonce <== inputNonce;
    for (var i=0;i<P;i++) core.parametersQ[i] <== parametersQ[i];
    core.modelBlind <== modelBlind;
    core.headBlind <== headBlind;
    core.stateNonce <== stateNonce;
    for (var i=0;i<C;i++) core.deltaWQ[i] <== deltaWQ[i];
    core.deltaBQ <== deltaBQ;
    for (var i=0;i<H1;i++) _ <== core.firstPreactivationQ[i];
    for (var i=0;i<H1;i++) _ <== core.hidden1Q[i];
    for (var i=0;i<H2;i++) _ <== core.secondPreactivationQ[i];
    for (var i=0;i<H2;i++) _ <== core.hidden2Q[i];
    for (var i=0;i<C;i++) _ <== core.encoderPreactivationQ[i];
    for (var i=0;i<C;i++) _ <== core.conceptsQ[i];
    _ <== core.marginQ;
    _ <== core.prediction;
}

template ExplanationCoreOptimizedComparison(C,ARCH,SCHEMA,STATE,EXPLANATION,COMMITMENT) {
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
    modelVersion === 1;
    architectureVersion === ARCH;
    schemaVersion === SCHEMA;
    quantizationVersion === 1;
    preprocessingVersion === 1;
    stateCircuitVersion === STATE;
    modelCommitmentVersion === COMMITMENT;
    explanationCircuitVersion === EXPLANATION;
    originalPrediction === 1;
    counterfactualPrediction === 0;
    component policy=ExplanationPolicyComparison(C);
    for(var i=0;i<C;i++) {
        policy.cQ[i] <== cQ[i];
        policy.cPrimeQ[i] <== cPrimeQ[i];
        policy.allowedMask[i] <== allowedMask[i];
    }
    policy.sparsityBound <== sparsityBound;
    policy.l1Bound <== l1Bound;
    for(var i=0;i<C;i++) {
        changedMask[i] <== policy.changedMask[i];
        deltaQ[i] <== policy.deltaQ[i];
    }
    L0 <== policy.L0;
    L1Q <== policy.L1Q;
    component state=AuthenticatedStateStress(C);
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
    for(var i=0;i<C;i++) {
        state.cQ[i] <== cQ[i];
        state.deltaWQ[i] <== deltaWQ[i];
    }
    state.deltaBQ <== deltaBQ;
    openedState <== state.commitment;
    openedState === C_state_v3;
    component explanation=ExplanationCommitmentComparison(C);
    explanation.explanationCircuitVersion <== explanationCircuitVersion;
    explanation.stateCircuitVersion <== stateCircuitVersion;
    explanation.modelVersion <== modelVersion;
    explanation.C_state_v3 <== C_state_v3;
    explanation.explanationNonce <== explanationNonce;
    for(var i=0;i<C;i++) explanation.cPrimeQ[i] <== cPrimeQ[i];
    explanation.commitment === C_explanation;
    component modified=MarginHeadStress(C);
    for(var i=0;i<C;i++) {
        modified.cQ[i] <== cPrimeQ[i];
        modified.deltaWQ[i] <== deltaWQ[i];
    }
    modified.deltaBQ <== deltaBQ;
    marginQ <== modified.marginQ;
    prediction <== modified.prediction;
    prediction === counterfactualPrediction;
}

template ExplanationOptimizedComparison(C,ARCH,SCHEMA,STATE,EXPLANATION,COMMITMENT) {
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
    component core=ExplanationCoreOptimizedComparison(C,ARCH,SCHEMA,STATE,EXPLANATION,COMMITMENT);
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
    for (var i=0;i<C;i++) core.allowedMask[i] <== allowedMask[i];
    core.sparsityBound <== sparsityBound;
    core.l1Bound <== l1Bound;
    core.C_explanation <== C_explanation;
    for (var i=0;i<C;i++) core.cQ[i] <== cQ[i];
    core.stateNonce <== stateNonce;
    core.explanationNonce <== explanationNonce;
    for (var i=0;i<C;i++) core.cPrimeQ[i] <== cPrimeQ[i];
    for (var i=0;i<C;i++) core.deltaWQ[i] <== deltaWQ[i];
    core.deltaBQ <== deltaBQ;
    _ <== core.openedState;
    for (var i=0;i<C;i++) _ <== core.changedMask[i];
    for (var i=0;i<C;i++) _ <== core.deltaQ[i];
    _ <== core.L0;
    _ <== core.L1Q;
    _ <== core.marginQ;
    _ <== core.prediction;
}
