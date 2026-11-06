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
 * @notice ERC-4337 account owned by a WebAuthn P-256 passkey (w3pk PRIMARY mode).
 *
 * - User operations and ERC-1271 signatures are WebAuthn assertions over the hash: `type` is
 *   `webauthn.get`, the challenge is the hash, UP and UV are set, and `s` is low.
 * - ERC-1271 goes through ERC-7739 first, so a signature can't be replayed on another account
 *   owned by the same passkey; it falls back to installed ERC-7579 validator modules.
 * - ERC-7579 validator, executor, fallback and hook modules. A hook sees every execution,
 *   module change and fallback call, which is where spending policies plug in.
 * - Deployed as an ERC-1167 clone by {W3pkAccountFactory}. Not upgradeable.
 */
contract W3pkAccount is
    Account,
    AccountERC7579HookedUpgradeable,
    SignerWebAuthnUpgradeable,
    ERC7739Upgradeable,
    ERC721Holder,
    ERC1155Holder
{
    constructor() {
        _disableInitializers();
    }

    function initialize(bytes32 qx, bytes32 qy) external initializer {
        __EIP712_init("W3pkAccount", "1");
        __SignerP256_init(qx, qy);
    }

    /// @dev ERC-7739 first; if it rejects the signature, ERC-7579 validator modules.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        override(AccountERC7579Upgradeable, ERC7739Upgradeable)
        returns (bytes4)
    {
        bytes4 magic = ERC7739Upgradeable.isValidSignature(hash, signature);
        return magic == bytes4(0xffffffff) ? AccountERC7579Upgradeable.isValidSignature(hash, signature) : magic;
    }

    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata signature)
        internal
        override(Account, AccountERC7579Upgradeable)
        returns (uint256)
    {
        return super._validateUserOp(userOp, userOpHash, signature);
    }

    function _rawSignatureValidation(bytes32 hash, bytes calldata signature)
        internal
        view
        override(AbstractSigner, AccountERC7579Upgradeable, SignerWebAuthnUpgradeable)
        returns (bool)
    {
        return SignerWebAuthnUpgradeable._rawSignatureValidation(hash, signature);
    }
}
