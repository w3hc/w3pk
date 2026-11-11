pragma circom 2.0.0;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/**
 * NFT Ownership Proof Circuit
 *
 * Proves that a Semaphore v4 identity holds at least `minBalance` tokens of
 * `contractAddress`, as recorded in a holders tree, without revealing which
 * holder it is.
 *
 * Leaf: Poseidon(commitment, contractAddress, balance), where commitment is
 * Poseidon(BabyPbk(secret)) as in Semaphore v4. Empty leaves are 0.
 *
 * Private inputs:
 *   - secret: the identity's secret scalar
 *   - balance: the holder's balance recorded in the leaf
 *   - pathElements[levels]: merkle proof sibling hashes
 *   - pathIndices[levels]: merkle proof path (0 = left, 1 = right)
 *
 * Public inputs:
 *   - root: merkle root of the holders tree
 *   - contractAddress: NFT contract address as a field element
 *   - minBalance: minimum balance proven
 *   - scope: external scope the nullifier is bound to
 *
 * Output:
 *   - nullifier: Poseidon(scope, secret), one per identity and scope
 */
template NFTOwnership(levels) {
    assert(levels < 21);

    signal input secret;
    signal input balance;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal input root;
    signal input contractAddress;
    signal input minBalance;
    signal input scope;

    signal output nullifier;

    // Below the Baby Jubjub subgroup order, so one commitment has one secret
    var l = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    component secretBits = Num2Bits(251);
    secretBits.in <== secret;
    component secretInRange = LessThan(251);
    secretInRange.in[0] <== secret;
    secretInRange.in[1] <== l;
    secretInRange.out === 1;

    component publicKey = BabyPbk();
    publicKey.in <== secret;

    component commitment = Poseidon(2);
    commitment.inputs[0] <== publicKey.Ax;
    commitment.inputs[1] <== publicKey.Ay;

    // Both under 2^64, or GreaterEqThan wraps around the field
    component balanceBits = Num2Bits(64);
    balanceBits.in <== balance;
    component minBalanceBits = Num2Bits(64);
    minBalanceBits.in <== minBalance;

    component enough = GreaterEqThan(64);
    enough.in[0] <== balance;
    enough.in[1] <== minBalance;
    enough.out === 1;

    component leafHasher = Poseidon(3);
    leafHasher.inputs[0] <== commitment.out;
    leafHasher.inputs[1] <== contractAddress;
    leafHasher.inputs[2] <== balance;

    component merkleProof[levels];
    signal computedHash[levels + 1];
    signal leftHash[levels];
    signal rightHash[levels];

    computedHash[0] <== leafHasher.out;

    for (var i = 0; i < levels; i++) {
        merkleProof[i] = Poseidon(2);

        pathIndices[i] * (pathIndices[i] - 1) === 0;
        leftHash[i] <== computedHash[i] + pathIndices[i] * (pathElements[i] - computedHash[i]);
        rightHash[i] <== pathElements[i] + pathIndices[i] * (computedHash[i] - pathElements[i]);

        merkleProof[i].inputs[0] <== leftHash[i];
        merkleProof[i].inputs[1] <== rightHash[i];
        computedHash[i + 1] <== merkleProof[i].out;
    }

    root === computedHash[levels];

    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== scope;
    nullifierHasher.inputs[1] <== secret;
    nullifier <== nullifierHasher.out;
}

component main {public [root, contractAddress, minBalance, scope]} = NFTOwnership(20);
