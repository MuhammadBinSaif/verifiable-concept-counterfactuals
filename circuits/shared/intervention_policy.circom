pragma circom 2.2.3;
include "quantized_activations.circom";

template ExplanationPolicyStress(C) {
    assert(C == 16);
    signal input cQ[C];
    signal input cPrimeQ[C];
    signal input allowedMask[C];
    signal input sparsityBound;
    signal input l1Bound;
    signal output changedMask[C];
    signal output deltaQ[C];
    signal output L0;
    signal output L1Q;
    // This experiment certifies one exact policy, not caller-selected maxima.
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
