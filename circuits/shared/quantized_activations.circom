pragma circom 2.2.3;
include "integer_arithmetic.circom";

function StressBits(maximum) {
    var bits = 0;
    var value = maximum;
    while (value > 0) {
        bits++;
        value = value \ 2;
    }
    return bits;
}

// Derive signed bounds from the encoder accumulator maximum.
template StressHardSigmoid(maximum) {
    signal input in;
    signal output out;
    signal numerator;
    signal interior;
    signal upper;
    signal interiorNumerator;
    signal floorQ;
    signal remainder;
    var numeratorMaximum = maximum + 30000;
    var comparisonBits = StressBits(numeratorMaximum);
    if (comparisonBits < 16) comparisonBits = 16;
    component inputBound = SignedRangeV1(maximum,StressBits(maximum));
    inputBound.in <== in;
    numerator <== in + 30000;
    component nBound = SignedBoundV1(numeratorMaximum,comparisonBits);
    nBound.in <== numerator;
    _ <== nBound.zero;
    component belowUpper = LessThan(comparisonBits);
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
