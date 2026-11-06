// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {W3pkAccount} from "./W3pkAccount.sol";

/**
 * @title W3pkAccountFactory
 * @notice Deploys {W3pkAccount} clones at addresses derived from the passkey's public key and a tag.
 *
 * The clone is created and initialized in the same call, and its CREATE2 salt commits to the key,
 * so no one can deploy the account at that address with another key.
 */
contract W3pkAccountFactory {
    W3pkAccount public immutable implementation;

    event AccountCreated(address indexed account, bytes32 qx, bytes32 qy, string tag);

    constructor() {
        implementation = new W3pkAccount();
    }

    /// @notice CREATE2 salt: `keccak256(abi.encode(qx, qy, keccak256(bytes(tag))))`.
    function salt(bytes32 qx, bytes32 qy, string calldata tag) public pure returns (bytes32) {
        return keccak256(abi.encode(qx, qy, keccak256(bytes(tag))));
    }

    function getAddress(bytes32 qx, bytes32 qy, string calldata tag) public view returns (address) {
        return Clones.predictDeterministicAddress(address(implementation), salt(qx, qy, tag));
    }

    /// @notice Deploy and initialize the account, or return it if it already exists.
    function createAccount(bytes32 qx, bytes32 qy, string calldata tag) external returns (address account) {
        account = getAddress(qx, qy, tag);
        if (account.code.length == 0) {
            account = Clones.cloneDeterministic(address(implementation), salt(qx, qy, tag));
            emit AccountCreated(account, qx, qy, tag);
            W3pkAccount(payable(account)).initialize(qx, qy);
        }
    }
}
