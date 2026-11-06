// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {AbstractSigner} from "@openzeppelin/contracts/utils/cryptography/signers/AbstractSigner.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {ERC721Holder} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import {ERC1155Holder} from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import {
    AccountERC7579Upgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579Upgradeable.sol";
import {
    AccountERC7579HookedUpgradeable
} from "@openzeppelin/contracts-upgradeable/account/extensions/draft-AccountERC7579HookedUpgradeable.sol";
import {
    SignerWebAuthnUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/SignerWebAuthnUpgradeable.sol";
import {
    ERC7739Upgradeable
} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/draft-ERC7739Upgradeable.sol";

/**
 * @title W3pkAccount
 * @author w3hc
 * @notice ERC-4337 account owned by a WebAuthn P-256 passkey (w3pk PRIMARY mode).
 * @dev
 * - User operations and ERC-1271 signatures are WebAuthn assertions over the hash: `type` is
 *   `webauthn.get`, the challenge is the hash, UP and UV are set, and `s` is low.
 * - ERC-1271 goes through ERC-7739 first, so a signature can't be replayed on another account
 *   owned by the same passkey; it falls back to installed ERC-7579 validator modules.
 * - ERC-7579 validator, executor, fallback and hook modules. A hook sees every execution,
 *   module change and fallback call, which is where spending policies plug in.
 * - Deployed as an ERC-1167 clone by {W3pkAccountFactory}. Not upgradeable.
 * - P-256 signatures are verified by the EIP-7951 precompile at `0x100`, with OpenZeppelin's
 *   Solidity verifier as a fallback on chains without it.
 * - The EntryPoint is v0.9 (`0x433709009B8330FDa32311DF1C2AFA402eD8D009`).
 * @custom:security-contact julien@strat.cc
 */
contract W3pkAccount is
    Account,
    AccountERC7579HookedUpgradeable,
    SignerWebAuthnUpgradeable,
    ERC7739Upgradeable,
    ERC721Holder,
    ERC1155Holder
{
    /// @dev Locks the implementation so only clones can be initialized.
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Sets the passkey that owns the account. Called once, by the factory, in the same
     * transaction as the clone's deployment.
     * @dev Sets the ERC-7739 EIP-712 domain to name `W3pkAccount`, version `1`.
     * @param qx x coordinate of the passkey's P-256 public key
     * @param qy y coordinate of the passkey's P-256 public key
     * @custom:reverts SignerP256InvalidPublicKey if `(qx, qy)` is not on the curve
     * @custom:reverts InvalidInitialization if the account is already initialized, or on the implementation
     */
    function initialize(bytes32 qx, bytes32 qy) external initializer {
        __EIP712_init("W3pkAccount", "1");
        __SignerP256_init(qx, qy);
    }

    /**
     * @notice ERC-1271 signature check.
     * @dev ERC-7739 first: `signature` is a WebAuthn assertion over the ERC-7739 nested hash, bound to
     * this account's domain. If ERC-7739 rejects it, the first 20 bytes of `signature` select an
     * installed ERC-7579 validator module, which checks the rest.
     * @param hash Hash of the signed data
     * @param signature ERC-7739 signature, or a validator module address followed by its signature
     * @return The ERC-1271 magic value `0x1626ba7e` if valid, `0x77390001` for ERC-7739 detection
     * requests, `0xffffffff` otherwise
     */
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        override(AccountERC7579Upgradeable, ERC7739Upgradeable)
        returns (bytes4)
    {
        bytes4 magic = ERC7739Upgradeable.isValidSignature(hash, signature);
        return magic == bytes4(0xffffffff) ? AccountERC7579Upgradeable.isValidSignature(hash, signature) : magic;
    }

    /**
     * @dev A user operation whose nonce key names an installed validator module is checked by that
     * module; any other is checked as a WebAuthn assertion with the user operation hash as challenge.
     * @param userOp The user operation
     * @param userOpHash Its hash, as computed by the EntryPoint
     * @param signature `userOp.signature`
     * @return `0` (`SIG_VALIDATION_SUCCESS`) or `1` (`SIG_VALIDATION_FAILED`)
     */
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        override(Account, AccountERC7579Upgradeable)
        returns (uint256)
    {
        return super._validateUserOp(userOp, userOpHash, signature);
    }

    /**
     * @dev Verifies an ABI-encoded `WebAuthn.WebAuthnAuth` against the owner key: `type` is
     * `webauthn.get`, the challenge is `hash`, UP and UV are set, BE/BS are consistent, and the
     * P-256 signature over `authenticatorData || sha256(clientDataJSON)` is valid with low `s`.
     * Never reverts on malformed input.
     * @param hash The expected challenge
     * @param signature `abi.encode(r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON)`
     * @return Whether the assertion is valid
     */
    function _rawSignatureValidation(bytes32 hash, bytes calldata signature)
        internal
        view
        override(AbstractSigner, AccountERC7579Upgradeable, SignerWebAuthnUpgradeable)
        returns (bool)
    {
        return SignerWebAuthnUpgradeable._rawSignatureValidation(hash, signature);
    }
}
