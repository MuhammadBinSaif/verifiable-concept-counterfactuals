pragma circom 2.2.3;
include "quantized_activations.circom";

// Affine accumulator bounds follow the configured input count.
template QuantizedAffineStress(N,M,INPUT_MAXIMUM,WEIGHT_MAXIMUM,BIAS_MAXIMUM) {
    var PRODUCTS = N*M;
    var PRODUCT_MAXIMUM = INPUT_MAXIMUM*WEIGHT_MAXIMUM;
    var BIAS_PRODUCT_MAXIMUM = BIAS_MAXIMUM*10000;
    var ACCUMULATOR_MAXIMUM = N*PRODUCT_MAXIMUM+BIAS_PRODUCT_MAXIMUM;
    var ROUNDED_MAXIMUM = (ACCUMULATOR_MAXIMUM+9999)\10000;
    signal input xQ[N];
    signal input parametersQ[PRODUCTS+M];
    signal output preactivationQ[M];
    signal products[M][N];
    signal biasProducts[M];
    signal accumulators[M];
    component inputBounds[N];
    component parameterBounds[PRODUCTS+M];
    component productBounds[M][N];
    component biasBounds[M];
    component rounds[M];
    for (var i=0; i<N; i++) {
        inputBounds[i] = UnsignedBoundV1(INPUT_MAXIMUM,StressBits(INPUT_MAXIMUM));
        inputBounds[i].in <== xQ[i];
    }
    for (var i=0; i<PRODUCTS+M; i++) {
        if (i<PRODUCTS) parameterBounds[i] = SignedRangeV1(WEIGHT_MAXIMUM,StressBits(WEIGHT_MAXIMUM));
        else parameterBounds[i] = SignedRangeV1(BIAS_MAXIMUM,StressBits(BIAS_MAXIMUM));
        parameterBounds[i].in <== parametersQ[i];
    }
    for (var j=0; j<M; j++) {
        var total = 0;
        for (var i=0; i<N; i++) {
            products[j][i] <== xQ[i]*parametersQ[j*N+i];
            productBounds[j][i] = SignedRangeV1(PRODUCT_MAXIMUM,StressBits(PRODUCT_MAXIMUM));
            productBounds[j][i].in <== products[j][i];
            total += products[j][i];
        }
        biasProducts[j] <== parametersQ[PRODUCTS+j]*10000;
        biasBounds[j] = SignedRangeV1(BIAS_PRODUCT_MAXIMUM,StressBits(BIAS_PRODUCT_MAXIMUM));
        biasBounds[j].in <== biasProducts[j];
        accumulators[j] <== total+biasProducts[j];
        rounds[j] = RoundHalfAwayV1(ACCUMULATOR_MAXIMUM,StressBits(ACCUMULATOR_MAXIMUM),10000,StressBits(ROUNDED_MAXIMUM),14,ROUNDED_MAXIMUM);
        rounds[j].in <== accumulators[j];
        preactivationQ[j] <== rounds[j].out;
    }
}

template IntegerEncoderDeepStress(D,H1,H2,C) {
    var L1 = D*H1+H1;
    var L2 = H1*H2+H2;
    var L3 = H2*C+C;
    var E = L1+L2+L3;
    var A1 = D*334210000+70340000;
    var R1 = (A1+9999)\10000;
    var A2 = H1*R1*20465+100660000;
    var R2 = (A2+9999)\10000;
    var A3 = H2*R2*20465+100660000;
    var R3 = (A3+9999)\10000;
    signal input xQ[D];
    signal input parametersQ[E];
    signal output firstPreactivationQ[H1];
    signal output hidden1Q[H1];
    signal output secondPreactivationQ[H2];
    signal output hidden2Q[H2];
    signal output encoderPreactivationQ[C];
    signal output conceptsQ[C];
    component first = QuantizedAffineStress(D,H1,10000,33421,7034);
    component firstRelus[H1];
    for (var i=0; i<D; i++) first.xQ[i] <== xQ[i];
    for (var i=0; i<L1; i++) first.parametersQ[i] <== parametersQ[i];
    for (var i=0; i<H1; i++) {
        firstPreactivationQ[i] <== first.preactivationQ[i];
        firstRelus[i] = ReLUV1(R1,StressBits(R1));
        firstRelus[i].in <== firstPreactivationQ[i];
        hidden1Q[i] <== firstRelus[i].out;
    }
    component second = QuantizedAffineStress(H1,H2,R1,20465,10066);
    component secondRelus[H2];
    for (var i=0; i<H1; i++) second.xQ[i] <== hidden1Q[i];
    for (var i=0; i<L2; i++) second.parametersQ[i] <== parametersQ[L1+i];
    for (var i=0; i<H2; i++) {
        secondPreactivationQ[i] <== second.preactivationQ[i];
        secondRelus[i] = ReLUV1(R2,StressBits(R2));
        secondRelus[i].in <== secondPreactivationQ[i];
        hidden2Q[i] <== secondRelus[i].out;
    }
    component third = QuantizedAffineStress(H2,C,R2,20465,10066);
    component sigmoids[C];
    for (var i=0; i<H2; i++) third.xQ[i] <== hidden2Q[i];
    for (var i=0; i<L3; i++) third.parametersQ[i] <== parametersQ[L1+L2+i];
    for (var i=0; i<C; i++) {
        encoderPreactivationQ[i] <== third.preactivationQ[i];
        sigmoids[i] = StressHardSigmoid(R3);
        sigmoids[i].in <== encoderPreactivationQ[i];
        conceptsQ[i] <== sigmoids[i].out;
    }
}
