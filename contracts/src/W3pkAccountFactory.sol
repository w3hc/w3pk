// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {W3pkAccount} from "./W3pkAccount.sol";

/**
 * @title W3pkAccountFactory
 * @author w3hc
 * @notice Deploys {W3pkAccount} clones at addresses derived from the passkey's public key and a tag.
 * @dev The clone is created and initialized in the same call, and its CREATE2 salt commits to the key,
 * so no one can deploy the account at that address with another key. The factory is deployed
 * through the deterministic deployment proxy and creates the implementation in its constructor,
 * so the factory, the implementation and every account have the same addresses on every chain.
 * @custom:security-contact julien@strat.cc
 */
contract W3pkAccountFactory {
    /// @notice The account every clone delegates to, created by this factory's constructor.
    W3pkAccount public immutable implementation;

    /**
     * @notice Emitted when an account is deployed.
     * @param account The new account
     * @param qx x coordinate of the owner's P-256 public key
     * @param qy y coordinate of the owner's P-256 public key
     * @param tag The tag the address was derived with
     */
    event AccountCreated(address indexed account, bytes32 qx, bytes32 qy, string tag);

    /// @dev Deploys the implementation, at `CREATE` nonce 1 of this factory.
    constructor() {
        implementation = new W3pkAccount();
    }

    /**
     * @notice CREATE2 salt of the account for a key and a tag.
     * @param qx x coordinate of the owner's P-256 public key
     * @param qy y coordinate of the owner's P-256 public key
     * @param tag Account tag; the w3pk SDK uses `"MAIN"` by default
     * @return `keccak256(abi.encode(qx, qy, keccak256(bytes(tag))))`
     */
    function salt(bytes32 qx, bytes32 qy, string calldata tag) public pure returns (bytes32) {
        return keccak256(abi.encode(qx, qy, keccak256(bytes(tag))));
    }

    /**
     * @notice Address of the account for a key and a tag, deployed or not.
     * @param qx x coordinate of the owner's P-256 public key
     * @param qy y coordinate of the owner's P-256 public key
     * @param tag Account tag
     * @return The account's address
     */
    function getAddress(bytes32 qx, bytes32 qy, string calldata tag) public view returns (address) {
        return Clones.predictDeterministicAddress(address(implementation), salt(qx, qy, tag));
    }

    /**
     * @notice Deploys and initializes the account for a key and a tag, or returns it if it exists.
     * @dev Usable as ERC-4337 `initCode`. Anyone can call it: the key is fixed by the address.
     * @param qx x coordinate of the owner's P-256 public key
     * @param qy y coordinate of the owner's P-256 public key
     * @param tag Account tag
     * @return account The account's address
     * @custom:reverts SignerP256InvalidPublicKey if `(qx, qy)` is not on the curve
     */
    function createAccount(bytes32 qx, bytes32 qy, string calldata tag) external returns (address account) {
        account = getAddress(qx, qy, tag);
        if (account.code.length == 0) {
            account = Clones.cloneDeterministic(address(implementation), salt(qx, qy, tag));
            emit AccountCreated(account, qx, qy, tag);
            W3pkAccount(payable(account)).initialize(qx, qy);
        }
    }
}
