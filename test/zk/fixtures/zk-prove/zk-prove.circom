pragma circom 2.0.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

// Test circuit for zkProve: uses an injected secret, a value derived from it
// and the public input, a random value and a private extra witness.
// Built with circom 2.2.2 and snarkjs 0.7.6 on a throwaway 2^11 powers of tau
// (test only): circom --r1cs --wasm, groth16 setup, one zkey contribution,
// export verificationkey
template ZkProveTest() {
    signal input secret;
    signal input contextSecret;
    signal input r;
    signal input scope;
    signal input message;

    signal output commitment;
    signal output nullifier;
    signal output blinded;

    component derived = Poseidon(3);
    derived.inputs[0] <== secret;
    derived.inputs[1] <== scope;
    derived.inputs[2] <== 1;
    contextSecret === derived.out;

    component c = Poseidon(1);
    c.inputs[0] <== secret;
    commitment <== c.out;

    component n = Poseidon(1);
    n.inputs[0] <== contextSecret;
    nullifier <== n.out;

    component b = Poseidon(2);
    b.inputs[0] <== message;
    b.inputs[1] <== r;
    blinded <== b.out;
}

component main {public [scope]} = ZkProveTest();
