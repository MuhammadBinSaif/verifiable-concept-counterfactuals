pragma circom 2.2.3;
include "circomlib/circuits/comparators.circom";

template UnsignedBoundV1(maximum, bits) {
    assert(maximum >= 0);
    assert(maximum < (1 << bits));
    assert(bits < 120);
    signal input in;
    component valueBits = Num2Bits(bits);
    component slackBits = Num2Bits(bits);
    valueBits.in <== in;
    slackBits.in <== maximum - in;
    for (var i=0; i<bits; i++) {
        _ <== valueBits.out[i];
        _ <== slackBits.out[i];
    }
}

template BooleanV1() {
    signal input in;
    in * (in-1) === 0;
}

template NonnegativeLessV1(maximum,bits) {
    signal input a;
    signal input b;
    signal output out;
    component aBound = UnsignedBoundV1(maximum,bits);
    component bBound = UnsignedBoundV1(maximum,bits);
    aBound.in <== a;
    bBound.in <== b;
    component comparison = LessThan(bits);
    comparison.in[0] <== a;
    comparison.in[1] <== b;
    out <== comparison.out;
}

template SignedBoundV1(maximum, bits) {
    signal input in;
    signal output negative;
    signal output magnitude;
    signal output zero;
    negative <-- in < 0 ? 1 : 0;
    magnitude <-- negative == 1 ? -in : in;
    component sign = BooleanV1();
    sign.in <== negative;
    component bound = UnsignedBoundV1(maximum,bits);
    bound.in <== magnitude;
    in === magnitude - 2 * negative * magnitude;
    component isZero = IsZero();
    isZero.in <== magnitude;
    zero <== isZero.out;
    negative * zero === 0;
}

template SignedRangeV1(maximum,bits) {
    signal input in;
    component signedValue = SignedBoundV1(maximum,bits);
    signedValue.in <== in;
    _ <== signedValue.negative;
    _ <== signedValue.magnitude;
    _ <== signedValue.zero;
}

template RoundHalfAwayV1(maximum, bits, divisor, quotientBits, remainderBits, roundedMaximum) {
    assert(divisor > 0);
    signal input in;
    signal output out;
    signal floorQ;
    signal remainder;
    signal roundUp;
    signal roundedMagnitude;
    component signedInput = SignedBoundV1(maximum,bits);
    signedInput.in <== in;
    _ <== signedInput.zero;
    floorQ <-- signedInput.magnitude \ divisor;
    remainder <-- signedInput.magnitude % divisor;
    component qBound = UnsignedBoundV1(maximum \ divisor,quotientBits);
    qBound.in <== floorQ;
    component rBound = UnsignedBoundV1(divisor-1,remainderBits);
    rBound.in <== remainder;
    signedInput.magnitude === floorQ * divisor + remainder;
    component belowHalf = LessThan(remainderBits+1);
    belowHalf.in[0] <== 2 * remainder;
    belowHalf.in[1] <== divisor;
    roundUp <== 1 - belowHalf.out;
    roundedMagnitude <== floorQ + roundUp;
    component roundedBound = UnsignedBoundV1(roundedMaximum,quotientBits);
    roundedBound.in <== roundedMagnitude;
    out <== roundedMagnitude - 2 * signedInput.negative * roundedMagnitude;
    component outputBound = SignedRangeV1(roundedMaximum,quotientBits);
    outputBound.in <== out;
}

template ReLUV1(maximum,bits) {
    signal input in;
    signal output out;
    component signedValue = SignedBoundV1(maximum,bits);
    signedValue.in <== in;
    _ <== signedValue.zero;
    out <== (1-signedValue.negative)*signedValue.magnitude;
    component outputBound = UnsignedBoundV1(maximum,bits);
    outputBound.in <== out;
}

template HardSigmoidV1() {
    signal input in;
    signal output out;
    signal numerator;
    signal interior;
    signal upper;
    signal interiorNumerator;
    signal floorQ;
    signal remainder;
    component inputBound = SignedRangeV1(21032795,25);
    inputBound.in <== in;
    numerator <== in + 30000;
    component nBound = SignedBoundV1(21062795,25);
    nBound.in <== numerator;
    _ <== nBound.zero;
    component belowUpper = LessThan(25);
    belowUpper.in[0] <== nBound.magnitude;
    belowUpper.in[1] <== 60000;
    interior <== (1-nBound.negative)*belowUpper.out;
    upper <== (1-nBound.negative)*(1-belowUpper.out);
    interiorNumerator <== interior*nBound.magnitude;
    component iBound = UnsignedBoundV1(59999,16);
    iBound.in <== interiorNumerator;
    floorQ <-- (interiorNumerator+3) \ 6;
    remainder <-- (interiorNumerator+3) % 6;
    component qBound = UnsignedBoundV1(10000,14);
    qBound.in <== floorQ;
    component rBound = UnsignedBoundV1(5,3);
    rBound.in <== remainder;
    interiorNumerator+3 === floorQ*6+remainder;
    out <== interior*floorQ+upper*10000;
    component outputBound = UnsignedBoundV1(10000,14);
    outputBound.in <== out;
}

template SignedGreaterV1(maximum,bits,marginBits) {
    signal input a;
    signal input b;
    signal output out;
    component aBound = SignedRangeV1(maximum,bits);
    component bBound = SignedRangeV1(maximum,bits);
    aBound.in <== a;
    bBound.in <== b;
    component margin = SignedBoundV1(2*maximum,marginBits);
    margin.in <== a-b;
    _ <== margin.magnitude;
    out <== (1-margin.negative)*(1-margin.zero);
}

template DecisionV1() {
    signal input headAcc0;
    signal input headAcc1;
    signal output prediction;
    component greater = SignedGreaterV1(1055550000,30,31);
    greater.a <== headAcc1;
    greater.b <== headAcc0;
    prediction <== greater.out;
}
