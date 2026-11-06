// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/ERC4337Utils.sol";
import {
    ERC7579Utils,
    CallType,
    ExecType,
    ModeSelector,
    ModePayload,
    Mode
} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {Execution, MODULE_TYPE_HOOK, MODULE_TYPE_EXECUTOR} from "@openzeppelin/contracts/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "@openzeppelin/contracts/interfaces/IERC4337.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {W3pkAccount} from "../src/W3pkAccount.sol";
import {W3pkAccountFactory} from "../src/W3pkAccountFactory.sol";
import {MockHook, MockExecutor} from "./mocks/MockModules.sol";

contract W3pkAccountTest is Test {
    address constant ENTRYPOINT = address(ERC4337Utils.ENTRYPOINT_V09);
    bytes4 constant MAGIC = 0x1626ba7e;
    uint256 constant SIG_OK = 0;
    uint256 constant SIG_FAILED = 1;

    W3pkAccountFactory factory;
    uint256 pk = 0xa11ce;
    bytes32 qx;
    bytes32 qy;
    W3pkAccount account;
    address recipient = makeAddr("recipient");

    function setUp() public {
        factory = new W3pkAccountFactory();
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        (qx, qy) = (bytes32(x), bytes32(y));
        account = W3pkAccount(payable(factory.createAccount(qx, qy, "MAIN")));
        vm.deal(address(account), 10 ether);
    }

    // Real assertions from base/webauthn-sol (MIT): Safari and Chrome, flags UP|UV, origin http://localhost:3005

    bytes32 constant REAL_CHALLENGE = 0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;
    bytes32 constant REAL_X =
        bytes32(uint256(28573233055232466711029625910063034642429572463461595413086259353299906450061));
    bytes32 constant REAL_Y =
        bytes32(uint256(39367742072897599771788408398752356480431855827262528811857788332151452825281));

    function _realChrome() internal pure returns (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) {
        r = bytes32(uint256(29739767516584490820047863506833955097567272713519339793744591468032609909569));
        s = bytes32(uint256(45947455641742997809691064512762075989493430661170736817032030660832793108102));
        authData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a";
        cdj = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(REAL_CHALLENGE)),
            '","origin":"http://localhost:3005","crossOrigin":false}'
        );
    }

    function _realSafari() internal pure returns (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) {
        r = bytes32(uint256(43684192885701841787131392247364253107519555363555461570655060745499568693242));
        s = bytes32(uint256(22655632649588629308599201066602670461698485748654492451178007896016452673579));
        authData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        cdj = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(REAL_CHALLENGE)),
            '","origin":"http://localhost:3005"}'
        );
    }

    function _encode(bytes32 r, bytes32 s, bytes memory authData, string memory cdj)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(r, s, uint256(23), uint256(1), authData, cdj);
    }

    function _realAccount() internal returns (W3pkAccount) {
        return W3pkAccount(payable(factory.createAccount(REAL_X, REAL_Y, "MAIN")));
    }

    function _validate(W3pkAccount a, bytes32 hash, bytes memory signature) internal returns (uint256) {
        PackedUserOperation memory op;
        op.sender = address(a);
        op.signature = signature;
        vm.prank(ENTRYPOINT);
        return a.validateUserOp(op, hash, 0);
    }

    function test_realChromeAssertion() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        assertEq(_validate(_realAccount(), REAL_CHALLENGE, _encode(r, s, authData, cdj)), SIG_OK);
    }

    address constant P256_PRECOMPILE = address(0x100);

    function test_eip7951PrecompileVerifiesRealAssertion() public view {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(cdj))));
        (bool ok, bytes memory result) = P256_PRECOMPILE.staticcall(abi.encode(digest, r, s, REAL_X, REAL_Y));
        assertTrue(ok);
        assertEq(abi.decode(result, (uint256)), 1);
    }

    function test_userOpVerifiedThroughEip7951() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        bytes memory signature = _encode(r, s, authData, cdj);
        W3pkAccount a = _realAccount();
        PackedUserOperation memory op;
        op.sender = address(a);
        op.signature = signature;

        vm.prank(ENTRYPOINT);
        uint256 gasBefore = gasleft();
        uint256 result = a.validateUserOp(op, REAL_CHALLENGE, 0);
        uint256 gasUsed = gasBefore - gasleft();

        assertEq(result, SIG_OK);
        // The precompile costs 6,900 gas; OZ's Solidity fallback costs over 200k
        assertLt(gasUsed, 100_000);
    }

    function test_accountTrustsEip7951Result() public {
        bytes32 hash = keccak256("userOp");
        bytes memory forged = _assertion(0xb0b, hash, 0x05, "webauthn.get");
        assertEq(_validate(account, hash, forged), SIG_FAILED);

        vm.mockCall(P256_PRECOMPILE, bytes(""), abi.encode(uint256(1)));
        assertEq(_validate(account, hash, forged), SIG_OK);
    }

    function test_realSafariAssertion() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realSafari();
        assertEq(_validate(_realAccount(), REAL_CHALLENGE, _encode(r, s, authData, cdj)), SIG_OK);
    }

    function test_realAssertionOtherHash() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        assertEq(_validate(_realAccount(), keccak256("other"), _encode(r, s, authData, cdj)), SIG_FAILED);
    }

    function test_realAssertionTamperedOrigin() public {
        (bytes32 r, bytes32 s, bytes memory authData,) = _realChrome();
        string memory cdj = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(REAL_CHALLENGE)),
            '","origin":"http://localhost:3006","crossOrigin":false}'
        );
        assertEq(_validate(_realAccount(), REAL_CHALLENGE, _encode(r, s, authData, cdj)), SIG_FAILED);
    }

    function test_realAssertionTamperedAuthData() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        authData[36] = 0x0b;
        assertEq(_validate(_realAccount(), REAL_CHALLENGE, _encode(r, s, authData, cdj)), SIG_FAILED);
    }

    function test_realAssertionHighS() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        bytes32 highS = bytes32(P256.N - uint256(s));
        assertEq(_validate(_realAccount(), REAL_CHALLENGE, _encode(r, highS, authData, cdj)), SIG_FAILED);
    }

    function test_realAssertionWrongKey() public {
        (bytes32 r, bytes32 s, bytes memory authData, string memory cdj) = _realChrome();
        assertEq(_validate(account, REAL_CHALLENGE, _encode(r, s, authData, cdj)), SIG_FAILED);
    }

    // Synthetic assertions

    bytes constant RP_ID_HASH = hex"6ec2b7d8b1c9a5e6c1f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7";

    function _assertion(uint256 key, bytes32 challenge, bytes1 flags, string memory type_)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory authData = abi.encodePacked(RP_ID_HASH, flags, uint32(0));
        string memory cdj = string.concat(
            '{"type":"',
            type_,
            '","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"https://w3pk.w3hc.org","crossOrigin":false}'
        );
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(cdj))));
        (bytes32 r, bytes32 s) = vm.signP256(key, digest);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        return abi.encode(r, s, uint256(23), uint256(1), authData, cdj);
    }

    function _assertion(bytes32 challenge) internal view returns (bytes memory) {
        return _assertion(pk, challenge, 0x05, "webauthn.get");
    }

    function test_userOpSigned() public {
        bytes32 hash = keccak256("userOp");
        assertEq(_validate(account, hash, _assertion(hash)), SIG_OK);
    }

    function test_userOpWithoutUV() public {
        bytes32 hash = keccak256("userOp");
        assertEq(_validate(account, hash, _assertion(pk, hash, 0x01, "webauthn.get")), SIG_FAILED);
    }

    function test_userOpWithoutUP() public {
        bytes32 hash = keccak256("userOp");
        assertEq(_validate(account, hash, _assertion(pk, hash, 0x04, "webauthn.get")), SIG_FAILED);
    }

    function test_userOpCreateType() public {
        bytes32 hash = keccak256("userOp");
        assertEq(_validate(account, hash, _assertion(pk, hash, 0x05, "webauthn.create")), SIG_FAILED);
    }

    function test_userOpOnlyFromEntryPoint() public {
        PackedUserOperation memory op;
        vm.expectRevert();
        account.validateUserOp(op, bytes32(0), 0);
    }

    // ERC-1271 through ERC-7739

    function _personalSignHash(W3pkAccount a, bytes32 hash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = a.eip712Domain();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        return MessageHashUtils.toTypedDataHash(domain, ERC7739Utils.personalSignStructHash(hash));
    }

    function test_erc1271PersonalSign() public {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(bytes("hello"));
        bytes memory signature = _assertion(_personalSignHash(account, hash));
        assertEq(account.isValidSignature(hash, signature), MAGIC);
    }

    function test_erc1271NoReplayOnOtherTag() public {
        W3pkAccount other = W3pkAccount(payable(factory.createAccount(qx, qy, "OTHER")));
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(bytes("hello"));
        bytes memory signature = _assertion(_personalSignHash(account, hash));
        assertEq(other.isValidSignature(hash, signature), bytes4(0xffffffff));
    }

    function test_erc1271RawHashRejected() public {
        bytes32 hash = keccak256("raw");
        assertEq(account.isValidSignature(hash, _assertion(hash)), bytes4(0xffffffff));
    }

    // Execution

    function _mode(CallType callType) internal pure returns (bytes32) {
        return Mode.unwrap(
            ERC7579Utils.encodeMode(
                callType, ERC7579Utils.EXECTYPE_DEFAULT, ModeSelector.wrap(0x00000000), ModePayload.wrap(0x00)
            )
        );
    }

    function test_transfer() public {
        vm.prank(ENTRYPOINT);
        account.execute(_mode(ERC7579Utils.CALLTYPE_SINGLE), abi.encodePacked(recipient, uint256(1 ether)));
        assertEq(recipient.balance, 1 ether);
    }

    function test_batch() public {
        Execution[] memory batch = new Execution[](3);
        for (uint256 i; i < 3; ++i) {
            batch[i] = Execution(recipient, 1 ether, "");
        }
        vm.prank(ENTRYPOINT);
        account.execute(_mode(ERC7579Utils.CALLTYPE_BATCH), ERC7579Utils.encodeBatch(batch));
        assertEq(recipient.balance, 3 ether);
    }

    function test_executeOnlyFromEntryPointOrSelf() public {
        vm.expectRevert();
        account.execute(_mode(ERC7579Utils.CALLTYPE_SINGLE), abi.encodePacked(recipient, uint256(1 ether)));
    }

    // Modules

    function test_hookModuleSeesAndBlocksExecution() public {
        MockHook hook = new MockHook();
        vm.prank(ENTRYPOINT);
        account.installModule(MODULE_TYPE_HOOK, address(hook), abi.encode(recipient));
        assertEq(account.hook(), address(hook));

        vm.prank(ENTRYPOINT);
        account.execute(_mode(ERC7579Utils.CALLTYPE_SINGLE), abi.encodePacked(recipient, uint256(1 ether)));
        assertEq(hook.preChecks(address(account)), 1);
        assertEq(hook.postChecks(address(account)), 1);

        vm.prank(ENTRYPOINT);
        vm.expectRevert(MockHook.Blocked.selector);
        account.execute(_mode(ERC7579Utils.CALLTYPE_SINGLE), abi.encodePacked(makeAddr("x"), uint256(1 ether)));
    }

    function test_executorModule() public {
        MockExecutor executor = new MockExecutor();
        vm.prank(ENTRYPOINT);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor), "");
        executor.send(account, recipient, 1 ether);
        assertEq(recipient.balance, 1 ether);
    }

    // Initialization

    function test_implementationCannotBeInitialized() public {
        W3pkAccount impl = factory.implementation();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(qx, qy);
    }

    function test_accountCannotBeReinitialized() public {
        (uint256 x, uint256 y) = vm.publicKeyP256(0xb0b);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        account.initialize(bytes32(x), bytes32(y));
    }

    function test_signer() public view {
        (bytes32 x, bytes32 y) = account.signer();
        assertEq(x, qx);
        assertEq(y, qy);
    }

    // Fuzz

    function testFuzz_signatureParsingNeverReverts(bytes32 hash, bytes calldata signature) public {
        assertEq(_validate(account, hash, signature), SIG_FAILED);
        assertEq(account.isValidSignature(hash, signature), bytes4(0xffffffff));
    }

    function testFuzz_lowSAcceptedHighSRejected(uint256 seed, bytes32 hash) public {
        uint256 key = bound(seed, 1, P256.N - 1);
        (uint256 x, uint256 y) = vm.publicKeyP256(key);
        W3pkAccount a = W3pkAccount(payable(factory.createAccount(bytes32(x), bytes32(y), "MAIN")));

        bytes memory signature = _assertion(key, hash, 0x05, "webauthn.get");
        assertEq(_validate(a, hash, signature), SIG_OK);

        (bytes32 r, bytes32 s,,, bytes memory authData, string memory cdj) =
            abi.decode(signature, (bytes32, bytes32, uint256, uint256, bytes, string));
        bytes memory high = _encode(r, bytes32(P256.N - uint256(s)), authData, cdj);
        assertEq(_validate(a, hash, high), SIG_FAILED);
    }

    function testFuzz_otherKeyRejected(uint256 seed, bytes32 hash) public {
        uint256 key = bound(seed, 1, P256.N - 1);
        vm.assume(key != pk);
        assertEq(_validate(account, hash, _assertion(key, hash, 0x05, "webauthn.get")), SIG_FAILED);
    }
}
