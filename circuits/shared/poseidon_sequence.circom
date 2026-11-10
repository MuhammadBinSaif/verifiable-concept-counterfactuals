pragma circom 2.2.3;
include "circomlib/circuits/poseidon.circom";

template StateSequenceV1(n,domain) {
    signal input payload[n];
    signal output commitment;
    signal accumulator[n+1];
    component initial = Poseidon(2);
    initial.inputs[0] <== domain;
    initial.inputs[1] <== n;
    accumulator[0] <== initial.out;
    component links[n];
    for (var i=0; i<n; i++) {
        links[i] = Poseidon(2);
        links[i].inputs[0] <== accumulator[i];
        links[i].inputs[1] <== payload[i];
        accumulator[i+1] <== links[i].out;
    }
    commitment <== accumulator[n];
}
