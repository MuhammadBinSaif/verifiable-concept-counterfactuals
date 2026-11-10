pragma circom 2.2.3;
include "quantized_activations.circom";

template AuthenticatedDeltaHeadStress(C) {
    signal input headParametersQ[2*C+2];
    signal input deltaWQ[C];
    signal input deltaBQ;
    component parameterBounds[2*C+2];
    for (var i=0; i<2*C+2; i++) {
        if (i<2*C) parameterBounds[i] = SignedRangeV1(25157,15);
        else parameterBounds[i] = SignedRangeV1(4927,13);
        parameterBounds[i].in <== headParametersQ[i];
    }
    for (var j=0; j<C; j++) {
        deltaWQ[j] === headParametersQ[j]-headParametersQ[C+j];
    }
    deltaBQ === headParametersQ[2*C]-headParametersQ[2*C+1];
}

template MarginHeadStress(C) {
    signal input cQ[C];
    signal input deltaWQ[C];
    signal input deltaBQ;
    signal output marginQ;
    signal output prediction;
    signal products[C];
    signal biasProduct;
    component differenceBounds[C];
    component productBounds[C];
    var sum = 0;
    for (var j=0; j<C; j++) {
        differenceBounds[j] = SignedRangeV1(50314,16);
        differenceBounds[j].in <== deltaWQ[j];
        products[j] <== cQ[j]*deltaWQ[j];
        productBounds[j] = SignedRangeV1(503140000,29);
        productBounds[j].in <== products[j];
        sum += products[j];
    }
    component biasDifferenceBound = SignedRangeV1(9854,14);
    biasDifferenceBound.in <== deltaBQ;
    biasProduct <== deltaBQ*10000;
    component biasProductBound = SignedRangeV1(98540000,27);
    biasProductBound.in <== biasProduct;
    marginQ <== biasProduct+sum;
    var M = C*503140000+98540000;
    component margin = SignedBoundV1(M,StressBits(M));
    margin.in <== marginQ;
    _ <== margin.magnitude;
    _ <== margin.zero;
    prediction <== margin.negative;
}
