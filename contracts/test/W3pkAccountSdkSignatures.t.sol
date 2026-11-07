// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {W3pkAccount} from "../src/W3pkAccount.sol";
import {W3pkAccountFactory} from "../src/W3pkAccountFactory.sol";

/**
 * @title W3pkAccountSdkSignaturesTest
 * @notice Verifies PRIMARY mode signatures made by the w3pk SDK (`test/fixtures/erc1271.json`, written by
 * `scripts/gen-erc1271-fixtures.ts`): ERC-7739 through `isValidSignature` on a deployed account, ERC-6492 on
 * an undeployed one, and no replay on another chain or account.
 */
contract W3pkAccountSdkSignaturesTest is Test {
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address constant SDK_FACTORY = 0xe341d909A1D7dEeec787796b8d305c064aEB5181;
    address constant MAIN_ACCOUNT = 0xC92aa436a4B825382f79c4d7a972b76409A45fC2;
    bytes32 constant ERC6492_MAGIC = 0x6492649264926492649264926492649264926492649264926492649264926492;
    bytes4 constant MAGIC = 0x1626ba7e;
    bytes4 constant INVALID = 0xffffffff;

    W3pkAccountFactory factory;
    bytes32 qx;
    bytes32 qy;
    string json;

    function setUp() public {
        (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(bytes32(uint256(1)), type(W3pkAccountFactory).creationCode));
        require(ok);
        factory = W3pkAccountFactory(SDK_FACTORY);
        (uint256 x, uint256 y) = vm.publicKeyP256(0xa11ce);
        (qx, qy) = (bytes32(x), bytes32(y));
        json = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/erc1271.json"));
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
    }

    function _fixture(string memory kind) internal view returns (bytes32 hash, bytes memory sig, bytes memory sig6492) {
        hash = vm.parseJsonBytes32(json, string.concat(".", kind, ".hash"));
        sig = vm.parseJsonBytes(json, string.concat(".", kind, ".signature"));
        sig6492 = vm.parseJsonBytes(json, string.concat(".", kind, ".signature6492"));
    }

    function _deploy() internal returns (W3pkAccount) {
        return W3pkAccount(payable(factory.createAccount(qx, qy, "MAIN")));
    }

    /// @dev ERC-6492 verification as a verifier runs it: deploy through the factory if needed, then ERC-1271.
    function _verify6492(address signer, bytes32 hash, bytes memory signature) internal returns (bytes4) {
        uint256 length = signature.length;
        bytes32 suffix;
        assembly {
            suffix := mload(add(signature, length))
        }
        assertEq(suffix, ERC6492_MAGIC);
        assembly {
            mstore(signature, sub(length, 32))
        }
        (address create2Factory, bytes memory factoryCalldata, bytes memory inner) =
            abi.decode(signature, (address, bytes, bytes));
        assembly {
            mstore(signature, length)
        }
        if (signer.code.length == 0) {
            (bool ok,) = create2Factory.call(factoryCalldata);
            require(ok);
        }
        return W3pkAccount(payable(signer)).isValidSignature(hash, inner);
    }

    function test_fixtureAccountIsTheFactoryAccount() public view {
        assertEq(factory.getAddress(qx, qy, "MAIN"), MAIN_ACCOUNT);
    }

    function test_personalSignOnDeployedAccount() public {
        (bytes32 hash, bytes memory sig,) = _fixture("personalSign");
        assertEq(_deploy().isValidSignature(hash, sig), MAGIC);
    }

    function test_typedDataOnDeployedAccount() public {
        (bytes32 hash, bytes memory sig,) = _fixture("typedData");
        assertEq(_deploy().isValidSignature(hash, sig), MAGIC);
    }

    function test_personalSign6492OnUndeployedAccount() public {
        (bytes32 hash,, bytes memory sig6492) = _fixture("personalSign");
        assertEq(MAIN_ACCOUNT.code.length, 0);
        assertEq(_verify6492(MAIN_ACCOUNT, hash, sig6492), MAGIC);
    }

    function test_typedData6492OnUndeployedAccount() public {
        (bytes32 hash,, bytes memory sig6492) = _fixture("typedData");
        assertEq(_verify6492(MAIN_ACCOUNT, hash, sig6492), MAGIC);
    }

    function test_6492OnDeployedAccount() public {
        (bytes32 hash,, bytes memory sig6492) = _fixture("personalSign");
        _deploy();
        assertEq(_verify6492(MAIN_ACCOUNT, hash, sig6492), MAGIC);
    }

    function test_otherMessageRejected() public {
        (, bytes memory sig,) = _fixture("personalSign");
        assertEq(_deploy().isValidSignature(keccak256("other"), sig), INVALID);
    }

    function test_noReplayOnOtherChain() public {
        (bytes32 hash, bytes memory sig,) = _fixture("personalSign");
        (bytes32 typedHash, bytes memory typedSig,) = _fixture("typedData");
        W3pkAccount account = _deploy();
        vm.chainId(10);
        assertEq(account.isValidSignature(hash, sig), INVALID);
        assertEq(account.isValidSignature(typedHash, typedSig), INVALID);
    }

    function test_noReplayOnOtherAccount() public {
        (bytes32 hash, bytes memory sig,) = _fixture("personalSign");
        (bytes32 typedHash, bytes memory typedSig,) = _fixture("typedData");
        W3pkAccount other = W3pkAccount(payable(factory.createAccount(qx, qy, "GAMING")));
        assertEq(other.isValidSignature(hash, sig), INVALID);
        assertEq(other.isValidSignature(typedHash, typedSig), INVALID);
    }
}
