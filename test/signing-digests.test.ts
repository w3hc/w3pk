/**
 * getSigningDigests returns the ERC-8213 digests of each request type
 */

import assert from "node:assert";
import { TypedDataEncoder } from "ethers";
import { getSigningDigests } from "../src/index";

const ERC191_HELLO = "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750";
const ERC191_HELLO_ACCENT = "0x42fd95dd8ed22d7d934d6ffff71ed0b730835b0de4bb3532a271568c8760c8d2";
const TRANSFER_CALLDATA =
  "0xa9059cbb0000000000000000000000004675c7e5baafbffbca748158becba61ef3b0a2630000000000000000000000000000000000000000000000000de0b6b3a7640000";
const TRANSFER_DIGEST = "0x812cee5d9cc7461c04bbcd7b70af9c28b243ac5d74d3453b008b93b7dac69985";
const EMPTY_CALLDATA_DIGEST = "0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563";

const MAIL = {
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
    Person: [
      { name: "name", type: "string" },
      { name: "wallet", type: "address" },
    ],
    Mail: [
      { name: "from", type: "Person" },
      { name: "to", type: "Person" },
      { name: "contents", type: "string" },
    ],
  },
  primaryType: "Mail",
  domain: {
    name: "Ether Mail",
    version: "1",
    chainId: 1,
    verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
  },
  message: {
    from: { name: "Cow", wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
    to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
    contents: "Hello, Bob!",
  },
};
const MAIL_DIGESTS = {
  eip712Digest: "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
  domainHash: "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
  messageHash: "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e",
};

const PERMIT_SINGLE = {
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "verifyingContract", type: "address" },
    ],
    PermitDetails: [
      { name: "token", type: "address" },
      { name: "amount", type: "uint160" },
      { name: "expiration", type: "uint48" },
      { name: "nonce", type: "uint48" },
    ],
    PermitSingle: [
      { name: "details", type: "PermitDetails" },
      { name: "spender", type: "address" },
      { name: "sigDeadline", type: "uint256" },
    ],
  },
  primaryType: "PermitSingle",
  domain: { name: "Permit2", chainId: 1, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
  message: {
    details: {
      token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      amount: "1461501637330902918203684832716283019655932542975",
      expiration: "1735689600",
      nonce: "0",
    },
    spender: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    sigDeadline: "1735689600",
  },
};

const ADDRESS = "0x4675C7e5BaAFBFFbca748158bEcBA61ef3b0a263";

async function runTests() {
  console.log("\n🔎 Running Signing Digests Tests...\n");

  console.log("Test 1: personal_sign returns the ERC-191 Digest");
  {
    assert.deepStrictEqual(getSigningDigests({ method: "personal_sign", params: ["hello", ADDRESS] }), {
      erc191Digest: ERC191_HELLO,
    });
    assert.strictEqual(
      getSigningDigests({ method: "personal_sign", params: ["héllo", ADDRESS] }).erc191Digest,
      ERC191_HELLO_ACCENT
    );
    console.log("✅ UTF-8 strings match the vectors");
  }

  console.log("\nTest 2: personal_sign decodes 0x hex to bytes");
  {
    assert.strictEqual(
      getSigningDigests({ method: "personal_sign", params: ["0x68656c6c6f", ADDRESS] }).erc191Digest,
      ERC191_HELLO
    );
    console.log("✅ Hex input matches the decoded bytes");
  }

  console.log("\nTest 3: eth_sign reads the message from its second param");
  {
    assert.strictEqual(
      getSigningDigests({ method: "eth_sign", params: [ADDRESS, "0x68656c6c6f"] }).erc191Digest,
      ERC191_HELLO
    );
    console.log("✅ eth_sign returns the ERC-191 Digest");
  }

  console.log("\nTest 4: eth_sendTransaction returns the Calldata Digest, to and value");
  {
    assert.deepStrictEqual(
      getSigningDigests({
        method: "eth_sendTransaction",
        params: [{ to: ADDRESS.toLowerCase(), value: "0xde0b6b3a7640000", data: TRANSFER_CALLDATA }],
      }),
      { calldataDigest: TRANSFER_DIGEST, to: ADDRESS, value: 10n ** 18n }
    );
    console.log("✅ Calldata matches the vector, to is checksummed, value is a bigint");
  }

  console.log("\nTest 5: empty calldata still has a Calldata Digest");
  {
    assert.deepStrictEqual(getSigningDigests({ method: "eth_sendTransaction", params: [{ to: ADDRESS }] }), {
      calldataDigest: EMPTY_CALLDATA_DIGEST,
      to: ADDRESS,
      value: 0n,
    });
    assert.strictEqual(
      getSigningDigests({ method: "eth_sendTransaction", params: [{ to: ADDRESS, data: "0x" }] }).calldataDigest,
      EMPTY_CALLDATA_DIGEST
    );
    assert.strictEqual(
      getSigningDigests({ method: "eth_sendTransaction", params: [{ data: TRANSFER_CALLDATA }] }).to,
      null
    );
    assert.throws(() => getSigningDigests({ method: "eth_sendTransaction", params: [{ to: "" }] }));
    console.log("✅ Missing or 0x data hashes 32 zero bytes, missing to is null, empty to throws");
  }

  console.log("\nTest 6: eth_signTypedData_v4 returns the EIP-712 Digest, Domain Hash and Message Hash");
  {
    assert.deepStrictEqual(
      getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, MAIL] }),
      MAIL_DIGESTS
    );
    assert.deepStrictEqual(
      getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, JSON.stringify(MAIL)] }),
      MAIL_DIGESTS
    );
    console.log("✅ Object and JSON string match the EIP-712 Mail vector");
  }

  console.log("\nTest 7: eth_signTypedData_v4 hashes the root type, named by primaryType");
  {
    const { EIP712Domain: _, ...types } = PERMIT_SINGLE.types;
    assert.deepStrictEqual(
      getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, PERMIT_SINGLE] }),
      {
        eip712Digest: TypedDataEncoder.hash(PERMIT_SINGLE.domain, types, PERMIT_SINGLE.message),
        domainHash: TypedDataEncoder.hashDomain(PERMIT_SINGLE.domain),
        messageHash: TypedDataEncoder.from(types).hash(PERMIT_SINGLE.message),
      }
    );
    assert.throws(
      () =>
        getSigningDigests({
          method: "eth_signTypedData_v4",
          params: [ADDRESS, { ...PERMIT_SINGLE, primaryType: "PermitDetails", message: PERMIT_SINGLE.message.details }],
        }),
      /types not reached from primaryType PermitDetails: PermitSingle/
    );
    assert.throws(
      () =>
        getSigningDigests({
          method: "eth_signTypedData_v4",
          params: [ADDRESS, { ...MAIL, types: { ...MAIL.types, Unused: [{ name: "x", type: "uint256" }] } }],
        }),
      /types not reached from primaryType Mail: Unused/
    );
    assert.throws(
      () =>
        getSigningDigests({
          method: "eth_signTypedData_v4",
          params: [ADDRESS, { ...MAIL, primaryType: "Letter" }],
        }),
      /primaryType Letter is not in types/
    );
    const { types: _types, ...untyped } = MAIL;
    assert.throws(
      () => getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, untyped as never] }),
      /typed data needs domain, types, primaryType and message/
    );
    console.log("✅ Permit2's nested root is hashed, a nested primaryType, unused types and an unknown primaryType or missing types throw");
  }

  console.log("\nTest 8: eth_signTypedData_v4 rejects a domain that types.EIP712Domain does not declare");
  {
    const undeclaredVersion = {
      ...MAIL,
      types: { ...MAIL.types, EIP712Domain: MAIL.types.EIP712Domain.filter((f) => f.name !== "version") },
    };
    assert.throws(
      () => getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, undeclaredVersion] }),
      /domain does not match types.EIP712Domain/
    );
    const { EIP712Domain: _, ...undeclaredDomain } = MAIL.types;
    assert.deepStrictEqual(
      getSigningDigests({ method: "eth_signTypedData_v4", params: [ADDRESS, { ...MAIL, types: undeclaredDomain }] }),
      MAIL_DIGESTS
    );
    console.log("✅ Mismatched EIP712Domain throws, a missing one is derived from the domain");
  }

  console.log("\nTest 9: unsupported methods throw");
  {
    assert.throws(
      () => getSigningDigests({ method: "eth_signTypedData", params: [] } as never),
      /unsupported method eth_signTypedData/
    );
    console.log("✅ Unsupported method rejected");
  }

  console.log("\n✅ All signing digests tests passed!\n");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
