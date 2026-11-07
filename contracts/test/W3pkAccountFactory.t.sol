// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {W3pkAccount} from "../src/W3pkAccount.sol";
import {W3pkAccountFactory} from "../src/W3pkAccountFactory.sol";

/**
 * @title W3pkAccountFactoryTest
 * @notice Tests of {W3pkAccountFactory}: deterministic addresses across chains, salt derivation,
 * idempotent creation, and that no other key or deployer can produce an account's address.
 */
contract W3pkAccountFactoryTest is Test {
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    W3pkAccountFactory factory;
    bytes32 qx;
    bytes32 qy;

    function setUp() public {
        factory = _deployDeterministic();
        (uint256 x, uint256 y) = vm.publicKeyP256(0xa11ce);
        (qx, qy) = (bytes32(x), bytes32(y));
    }

    function _deployDeterministic() internal returns (W3pkAccountFactory f) {
        address predicted =
            vm.computeCreate2Address(bytes32(0), keccak256(type(W3pkAccountFactory).creationCode), CREATE2_DEPLOYER);
        if (predicted.code.length == 0) {
            (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(bytes32(0), type(W3pkAccountFactory).creationCode));
            require(ok);
        }
        return W3pkAccountFactory(predicted);
    }

    function test_createAccountAtPredictedAddress() public {
        address predicted = factory.getAddress(qx, qy, "MAIN");
        address account = factory.createAccount(qx, qy, "MAIN");
        assertEq(account, predicted);
        (bytes32 x, bytes32 y) = W3pkAccount(payable(account)).signer();
        assertEq(x, qx);
        assertEq(y, qy);
    }

    function test_createAccountIsIdempotent() public {
        address first = factory.createAccount(qx, qy, "MAIN");
        assertEq(factory.createAccount(qx, qy, "MAIN"), first);
    }

    function test_saltDerivation() public view {
        assertEq(factory.salt(qx, qy, "MAIN"), keccak256(abi.encode(qx, qy, keccak256(bytes("MAIN")))));
    }

    function test_sameAddressOnEveryChain() public {
        address factoryAddress =
            vm.computeCreate2Address(bytes32(0), keccak256(type(W3pkAccountFactory).creationCode), CREATE2_DEPLOYER);
        address implementation = vm.computeCreateAddress(factoryAddress, 1);
        address account =
            Clones.predictDeterministicAddress(implementation, factory.salt(qx, qy, "MAIN"), factoryAddress);

        uint256[4] memory chainIds = [uint256(1), 11155111, 10, 8453];
        for (uint256 i; i < chainIds.length; ++i) {
            vm.chainId(chainIds[i]);
            assertEq(address(factory), factoryAddress);
            assertEq(address(factory.implementation()), implementation);
            assertEq(factory.getAddress(qx, qy, "MAIN"), account);
        }
        assertEq(factory.createAccount(qx, qy, "MAIN"), account);
    }

    function test_tagsGiveDistinctAccounts() public {
        assertTrue(factory.createAccount(qx, qy, "MAIN") != factory.createAccount(qx, qy, "OTHER"));
    }

    function test_otherKeyCannotProduceAddress() public {
        address target = factory.getAddress(qx, qy, "MAIN");
        (uint256 x, uint256 y) = vm.publicKeyP256(0xb0b);
        assertTrue(factory.createAccount(bytes32(x), bytes32(y), "MAIN") != target);
        assertEq(target.code.length, 0);
    }

    function test_cloneOutsideFactoryLandsElsewhere() public {
        bytes32 salt = factory.salt(qx, qy, "MAIN");
        address clone = Clones.cloneDeterministic(address(factory.implementation()), salt);
        assertTrue(clone != factory.getAddress(qx, qy, "MAIN"));
    }

    function test_invalidKeyReverts() public {
        vm.expectRevert();
        factory.createAccount(bytes32(0), bytes32(0), "MAIN");
    }

    function testFuzz_otherKeyOrTagNeverCollides(uint256 seed, string calldata tag) public {
        uint256 key = bound(seed, 1, 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550);
        vm.assume(key != 0xa11ce);
        (uint256 x, uint256 y) = vm.publicKeyP256(key);
        assertTrue(factory.getAddress(bytes32(x), bytes32(y), tag) != factory.getAddress(qx, qy, "MAIN"));
    }

    function test_cloneInitCodeHash() public {
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
                address(factory.implementation()),
                hex"5af43d82803e903d91602b57fd5bf3"
            )
        );
        bytes32 salt = factory.salt(qx, qy, "MAIN");
        assertEq(factory.createAccount(qx, qy, "MAIN"), vm.computeCreate2Address(salt, initCodeHash, address(factory)));
    }

    /// @dev Pins the vectors `test/smart-account-address.test.ts` checks the SDK against.
    function test_sdkVectors() public {
        (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(bytes32(uint256(1)), type(W3pkAccountFactory).creationCode));
        require(ok);
        W3pkAccountFactory deployed = W3pkAccountFactory(0xe341d909A1D7dEeec787796b8d305c064aEB5181);
        assertEq(address(deployed.implementation()), 0x289b99F5EfFE4b5aF6DBc3f3501881C98aF2740C);
        assertEq(
            keccak256(
                abi.encodePacked(
                    hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
                    address(deployed.implementation()),
                    hex"5af43d82803e903d91602b57fd5bf3"
                )
            ),
            0x25e8fe200bdf4198a104e71276a83130d745fc9bf71ce23b1e3690729bc6d0c6
        );
        assertEq(deployed.getAddress(qx, qy, "MAIN"), 0xC92aa436a4B825382f79c4d7a972b76409A45fC2);
        assertEq(deployed.getAddress(qx, qy, "GAMING"), 0x9bd3912f41dbA1b66425bD5B6046A31685b17143);
    }
}
