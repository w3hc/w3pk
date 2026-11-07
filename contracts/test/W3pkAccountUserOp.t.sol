// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {IEntryPoint, PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {IEntryPointExtra} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {W3pkAccount} from "../src/W3pkAccount.sol";
import {W3pkAccountFactory} from "../src/W3pkAccountFactory.sol";

/**
 * @title W3pkAccountUserOpTest
 * @notice Runs PRIMARY mode UserOperations made and signed by the w3pk SDK (`test/fixtures/userop.json`, written by
 * `scripts/gen-userop-fixtures.ts`) through the EntryPoint v0.9: the SDK's userOpHash is the EntryPoint's, the first
 * one deploys the account, batches are atomic, and a tampered UserOperation fails validation.
 * @dev The EntryPoint v0.9 and its SenderCreator are etched from their Ethereum mainnet runtime code
 * (`test/fixtures/entrypoint-v09.json`), immutables included.
 */
contract W3pkAccountUserOpTest is Test {
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address constant MAIN_ACCOUNT = 0xC92aa436a4B825382f79c4d7a972b76409A45fC2;
    address constant RECIPIENT = 0x000000000000000000000000000000000000bEEF;
    address constant OTHER_RECIPIENT = 0x000000000000000000000000000000000000cafE;
    address constant REVERTER = 0x000000000000000000000000000000000000dEaD;
    address payable constant BENEFICIARY = payable(address(0xB0B));
    IEntryPoint constant ENTRY_POINT = IEntryPoint(0x433709009B8330FDa32311DF1C2AFA402eD8D009);

    bytes32 constant USER_OPERATION_EVENT =
        keccak256("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");

    string json;

    function setUp() public {
        string memory root = vm.projectRoot();
        string memory entryPoint = vm.readFile(string.concat(root, "/test/fixtures/entrypoint-v09.json"));
        vm.etch(address(ENTRY_POINT), vm.parseJsonBytes(entryPoint, ".entryPointCode"));
        vm.etch(vm.parseJsonAddress(entryPoint, ".senderCreator"), vm.parseJsonBytes(entryPoint, ".senderCreatorCode"));
        (bool ok,) = CREATE2_DEPLOYER.call(abi.encodePacked(bytes32(uint256(1)), type(W3pkAccountFactory).creationCode));
        require(ok);
        vm.etch(REVERTER, hex"5f5ffd");

        json = vm.readFile(string.concat(root, "/test/fixtures/userop.json"));
        vm.chainId(vm.parseJsonUint(json, ".chainId"));
        vm.fee(1 gwei);
        vm.deal(MAIN_ACCOUNT, 1 ether);
    }

    function _uint(string memory name, string memory field) internal view returns (uint256) {
        return vm.parseJsonUint(json, string.concat(".", name, ".", field));
    }

    function _bytes(string memory name, string memory field) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", name, ".", field));
    }

    function _address(string memory name, string memory field) internal view returns (address) {
        return vm.parseJsonAddress(json, string.concat(".", name, ".", field));
    }

    function _op(string memory name) internal view returns (PackedUserOperation memory op) {
        address factory = _address(name, "factory");
        address paymaster = _address(name, "paymaster");
        op.sender = _address(name, "sender");
        op.nonce = _uint(name, "nonce");
        op.initCode = factory == address(0) ? bytes("") : abi.encodePacked(factory, _bytes(name, "factoryData"));
        op.callData = _bytes(name, "callData");
        op.accountGasLimits = bytes32(_uint(name, "verificationGasLimit") << 128 | _uint(name, "callGasLimit"));
        op.preVerificationGas = _uint(name, "preVerificationGas");
        op.gasFees = bytes32(_uint(name, "maxPriorityFeePerGas") << 128 | _uint(name, "maxFeePerGas"));
        op.paymasterAndData = paymaster == address(0)
            ? bytes("")
            : abi.encodePacked(
                paymaster,
                uint128(_uint(name, "paymasterVerificationGasLimit")),
                uint128(_uint(name, "paymasterPostOpGasLimit")),
                _bytes(name, "paymasterData")
            );
        op.signature = _bytes(name, "signature");
    }

    function _hash(string memory name) internal view returns (bytes32) {
        return vm.parseJsonBytes32(json, string.concat(".", name, ".userOpHash"));
    }

    /// @dev Bundles one UserOperation, as a bundler EOA does, and returns its `UserOperationEvent` success flag.
    function _handle(PackedUserOperation memory op) internal returns (bool success) {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.recordLogs();
        vm.prank(BENEFICIARY, BENEFICIARY);
        ENTRY_POINT.handleOps(ops, BENEFICIARY);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(ENTRY_POINT) && logs[i].topics[0] == USER_OPERATION_EVENT) {
                (, success,,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
                return success;
            }
        }
        revert("no UserOperationEvent");
    }

    function test_sdkHashIsTheEntryPointHash() public view {
        string[4] memory names = ["deploy", "batch", "revertingBatch", "paymaster"];
        for (uint256 i; i < names.length; ++i) {
            assertEq(IEntryPointExtra(address(ENTRY_POINT)).getUserOpHash(_op(names[i])), _hash(names[i]), names[i]);
        }
    }

    function test_paymasterSignatureIsNotHashed() public view {
        PackedUserOperation memory op = _op("paymaster");
        bytes memory data = op.paymasterAndData;
        data[data.length - 11] = 0xbb;
        assertEq(IEntryPointExtra(address(ENTRY_POINT)).getUserOpHash(op), _hash("paymaster"));
    }

    function test_firstUserOpDeploysTheAccount() public {
        assertEq(MAIN_ACCOUNT.code.length, 0);
        assertTrue(_handle(_op("deploy")));
        assertGt(MAIN_ACCOUNT.code.length, 0);
        assertEq(RECIPIENT.balance, 1000);
        assertEq(ENTRY_POINT.getNonce(MAIN_ACCOUNT, 0), 1);
        assertGt(BENEFICIARY.balance, 0, "the account paid the bundler");
    }

    function test_batchExecutes() public {
        _handle(_op("deploy"));
        assertTrue(_handle(_op("batch")));
        assertEq(RECIPIENT.balance, 1001);
        assertEq(OTHER_RECIPIENT.balance, 2);
    }

    function test_batchIsAtomic() public {
        _handle(_op("deploy"));
        _handle(_op("batch"));
        assertFalse(_handle(_op("revertingBatch")));
        assertEq(RECIPIENT.balance, 1001, "the call before the reverting one is undone");
        assertEq(ENTRY_POINT.getNonce(MAIN_ACCOUNT, 0), 3);
    }

    function test_validateUserOpAcceptsTheSdkSignature() public {
        _handle(_op("deploy"));
        PackedUserOperation memory op = _op("batch");
        vm.prank(address(ENTRY_POINT));
        assertEq(W3pkAccount(payable(MAIN_ACCOUNT)).validateUserOp(op, _hash("batch"), 0), 0);
    }

    function test_tamperedUserOpFails() public {
        PackedUserOperation memory op = _op("deploy");
        op.callData = _op("batch").callData;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.prank(BENEFICIARY, BENEFICIARY);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ENTRY_POINT.handleOps(ops, BENEFICIARY);
    }

    function test_noReplayOnOtherChain() public {
        vm.chainId(10);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _op("deploy");
        vm.prank(BENEFICIARY, BENEFICIARY);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ENTRY_POINT.handleOps(ops, BENEFICIARY);
    }
}
