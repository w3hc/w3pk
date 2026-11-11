pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/**
 * Range Proof Circuit
 * Proves that a hidden value is within a range without revealing the value
 * 
 * Private inputs:
 *   - value: the actual value
 *   - blinding: random blinding factor for commitment
 * 
 * Public inputs:
 *   - min: minimum value (inclusive)
 *   - max: maximum value (inclusive)
 *   - commitment: Poseidon(value, blinding)
 * 
 * Proves: min <= value <= max, all three below 2^128
 */
template RangeProof() {
    // Private inputs
    signal input value;
    signal input blinding;
    
    // Public inputs
    signal input min;
    signal input max;
    signal input commitment;

    // 1. Verify commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    commitment === hasher.out;

    // 2. All under 2^128, or the comparators wrap around the field
    component valueBits = Num2Bits(128);
    valueBits.in <== value;
    component minBits = Num2Bits(128);
    minBits.in <== min;
    component maxBits = Num2Bits(128);
    maxBits.in <== max;

    // 3. Prove value >= min
    component greaterThanMin = GreaterEqThan(128);
    greaterThanMin.in[0] <== value;
    greaterThanMin.in[1] <== min;
    greaterThanMin.out === 1;

    // 4. Prove value <= max
    component lessThanMax = LessEqThan(128);
    lessThanMax.in[0] <== value;
    lessThanMax.in[1] <== max;
    lessThanMax.out === 1;
}

component main {public [min, max, commitment]} = RangeProof();