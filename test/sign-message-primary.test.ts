/**
 * PRIMARY mode signMessage (#298): ERC-7739 signatures by the passkey's
 * P-256 smart account, ERC-6492-wrapped while it isn't known to be deployed
 *
 * Onchain verification of these signatures is in
 * contracts/test/W3pkAccountSdkSignatures.t.sol
 */

import assert from "node:assert";
import { AbiCoder, Interface, TypedDataEncoder, dataSlice, getBytes, hashMessage, hexlify } from "ethers";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  GAMING_ACCOUNT,
  MAIN_ACCOUNT,
  QX,
  QY,
  installPasskey,
  passkeyCalls,
  primarySdk,
} from "./fixtures/passkey-signer";
import { createSiweMessage } from "../src/siwe";
import { W3PK_ACCOUNT_FACTORY } from "../src/wallet/smart-account";
import {
  ERC6492_MAGIC,
  encodeTypedDataSignature,
  personalSignHash,
  typedDataSignPayload,
} from "../src/wallet/erc7739";
import { encodeWebAuthnSignature } from "../src/wallet/webauthn-signature";
import { UnauthorizedError } from "../src/index";

const coder = AbiCoder.defaultAbiCoder();
const factoryInterface = new Interface([
  "function createAccount(bytes32 qx, bytes32 qy, string tag) returns (address)",
]);

const DOMAIN = { name: "Mail", version: "1", chainId: 1, verifyingContract: "0x" + "cc".repeat(20) };
const TYPES = {
  Person: [
    { name: "name", type: "string" },
    { name: "wallet", type: "address" },
  ],
  Mail: [
    { name: "from", type: "Person" },
    { name: "contents", type: "string" },
  ],
};
const MAIL = { from: { name: "Alice", wallet: "0x" + "aa".repeat(20) }, contents: "Hello" };

function unwrap6492(signature: string): { factory: string; calldata: string; inner: string } {
  assert.strictEqual(dataSlice(signature, -32), ERC6492_MAGIC, "ends with the ERC-6492 magic");
  const [factory, calldata, inner] = coder.decode(["address", "bytes", "bytes"], dataSlice(signature, 0, -32));
  return { factory, calldata, inner };
}

/** Challenge of a W3pkAccount WebAuthn signature, checked against the passkey's key */
function verifiedChallenge(signature: string): string {
  const [r, s, challengeIndex, typeIndex, authData, cdj] = coder.decode(
    ["bytes32", "bytes32", "uint256", "uint256", "bytes", "string"],
    signature
  );
  assert(cdj.startsWith('"challenge":"', Number(challengeIndex)), "challengeIndex points at the challenge");
  assert(cdj.startsWith('"type":"webauthn.get"', Number(typeIndex)), "typeIndex points at the type");
  const message = new Uint8Array([...getBytes(authData), ...sha256(new TextEncoder().encode(cdj))]);
  const publicKey = getBytes("0x04" + QX.slice(2) + QY.slice(2));
  assert(p256.verify(getBytes(r + s.slice(2)), message, publicKey), "P-256 signature verifies");
  return hexlify(Buffer.from(JSON.parse(cdj).challenge, "base64url"));
}

async function rejection(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    return (error as any).originalError?.message ?? (error as Error).message;
  }
  throw new Error("expected a rejection");
}

async function runTests() {
  console.log("\n✍️  PRIMARY mode signMessage tests\n");
  installPasskey();
  const sdk = await primarySdk();

  console.log("Test 1: EIP-191 is an ERC-7739 PersonalSign, ERC-6492-wrapped with no RPC");
  {
    passkeyCalls.length = 0;
    const result = await sdk.signMessage("Hello, Web3!", { mode: "PRIMARY", chainId: 1 });
    assert.strictEqual(result.address, MAIN_ACCOUNT);
    assert.strictEqual(result.mode, "PRIMARY");
    assert.strictEqual(result.tag, "MAIN");
    assert.strictEqual(passkeyCalls.length, 1, "one passkey assertion");
    assert.strictEqual(passkeyCalls[0].userVerification, "required");

    const { factory, calldata, inner } = unwrap6492(result.signature);
    assert.strictEqual(factory, W3PK_ACCOUNT_FACTORY);
    const [qx, qy, tag] = factoryInterface.decodeFunctionData("createAccount", calldata);
    assert.deepStrictEqual([qx, qy, tag], [QX, QY, "MAIN"], "factory calldata deploys this account");
    assert.strictEqual(
      verifiedChallenge(inner),
      personalSignHash(hashMessage("Hello, Web3!"), { address: MAIN_ACCOUNT, chainId: 1 })
    );
    console.log("✅ EIP-191 works");
  }

  console.log("\nTest 2: bytes are signed as the same EIP-191 message");
  {
    const bytes = new TextEncoder().encode("Hello, Web3!");
    const { inner } = unwrap6492((await sdk.signMessage(bytes, { mode: "PRIMARY", chainId: 1 })).signature);
    assert.strictEqual(
      verifiedChallenge(inner),
      personalSignHash(hashMessage(bytes), { address: MAIN_ACCOUNT, chainId: 1 })
    );
    console.log("✅ bytes work");
  }

  console.log("\nTest 3: a deployed account gets the bare ERC-7739 signature");
  {
    const calls: unknown[][] = [];
    const deployed = await primarySdk({ rpcUrls: { 10: ["https://op.example"] } });
    (deployed as any).isDeployed = async (...args: unknown[]) => {
      calls.push(args);
      return true;
    };
    const result = await deployed.signMessage("hi", { mode: "PRIMARY", chainId: 10 });
    assert.notStrictEqual(dataSlice(result.signature, -32), ERC6492_MAGIC, "not wrapped");
    assert.strictEqual(
      verifiedChallenge(result.signature),
      personalSignHash(hashMessage("hi"), { address: MAIN_ACCOUNT, chainId: 10 })
    );
    await deployed.signMessage("hi", { mode: "PRIMARY", chainId: 10, rpcUrl: "https://rpc.example" });
    assert.deepStrictEqual(calls, [
      [MAIN_ACCOUNT, 10, undefined],
      [MAIN_ACCOUNT, 10, "https://rpc.example"],
    ]);
    console.log("✅ deployment check works");
  }

  console.log("\nTest 4: the signature is bound to the tag's account and the chain");
  {
    const gaming = await sdk.signMessage("hi", { mode: "PRIMARY", tag: "GAMING", chainId: 1 });
    assert.strictEqual(gaming.address, GAMING_ACCOUNT);
    const { calldata, inner } = unwrap6492(gaming.signature);
    assert.strictEqual(factoryInterface.decodeFunctionData("createAccount", calldata)[2], "GAMING");
    assert.strictEqual(
      verifiedChallenge(inner),
      personalSignHash(hashMessage("hi"), { address: GAMING_ACCOUNT, chainId: 1 })
    );

    const main1 = personalSignHash(hashMessage("hi"), { address: MAIN_ACCOUNT, chainId: 1 });
    const main10 = personalSignHash(hashMessage("hi"), { address: MAIN_ACCOUNT, chainId: 10 });
    const gaming1 = personalSignHash(hashMessage("hi"), { address: GAMING_ACCOUNT, chainId: 1 });
    assert.strictEqual(new Set([main1, main10, gaming1]).size, 3, "distinct per account and chain");
    console.log("✅ binding works");
  }

  console.log("\nTest 4b: options.from other than the smart account throws 4100 before the passkey prompt");
  {
    passkeyCalls.length = 0;
    const error = await sdk.signMessage("hi", { mode: "PRIMARY", chainId: 1, from: GAMING_ACCOUNT }).catch((e) => e);
    assert(error instanceof UnauthorizedError, String(error));
    assert.strictEqual(error.code, 4100);
    assert.strictEqual(passkeyCalls.length, 0, "no passkey prompt");
    const signed = await sdk.signMessage("hi", { mode: "PRIMARY", chainId: 1, from: MAIN_ACCOUNT.toLowerCase() });
    assert.strictEqual(signed.address, MAIN_ACCOUNT, "lowercase from signs");
    console.log("✅ from checked against the smart account");
  }

  console.log("\nTest 5: EIP-191 needs a chain ID");
  {
    const cause = await rejection(sdk.signMessage("hi", { mode: "PRIMARY" }));
    assert(cause.includes("requires options.chainId"), cause);
    console.log("✅ rejected without chainId");
  }

  console.log("\nTest 6: SIWE takes the chain ID from the message");
  {
    const siwe = createSiweMessage({
      domain: "localhost",
      address: MAIN_ACCOUNT,
      uri: "http://localhost",
      version: "1",
      chainId: 8453,
      nonce: "abcdefgh1234",
      issuedAt: new Date().toISOString(),
    });
    for (const signingMethod of ["SIWE", "EIP191"] as const) {
      const { inner } = unwrap6492((await sdk.signMessage(siwe, { mode: "PRIMARY", signingMethod })).signature);
      assert.strictEqual(
        verifiedChallenge(inner),
        personalSignHash(hashMessage(siwe), { address: MAIN_ACCOUNT, chainId: 8453 })
      );
    }

    const other = siwe.replace("localhost wants", "evil.example wants");
    const cause = await rejection(sdk.signMessage(other, { mode: "PRIMARY", signingMethod: "SIWE" }));
    assert(/domain/i.test(cause), `another domain is rejected: ${cause}`);
    console.log("✅ SIWE works");
  }

  console.log("\nTest 7: EIP-712 is an ERC-7739 TypedDataSign");
  {
    const result = await sdk.signMessage(JSON.stringify(MAIL), {
      mode: "PRIMARY",
      signingMethod: "EIP712",
      eip712Domain: DOMAIN,
      eip712Types: TYPES,
      eip712PrimaryType: "Mail",
    });
    const payload = typedDataSignPayload(DOMAIN, TYPES, "Mail", MAIL, { address: MAIN_ACCOUNT, chainId: 1 });
    assert.strictEqual(payload.hash, TypedDataEncoder.hash(DOMAIN, TYPES, MAIL), "app hash is the EIP-712 hash");
    assert.strictEqual(payload.contentsDescr, "Mail(Person from,string contents)Person(string name,address wallet)");

    const { inner } = unwrap6492(result.signature);
    const descrLength = Number(dataSlice(inner, -2));
    const passkeySignature = dataSlice(inner, 0, -(64 + descrLength + 2));
    assert.strictEqual(inner, encodeTypedDataSignature(passkeySignature, payload), "packed as ERC-7739");
    assert.strictEqual(verifiedChallenge(passkeySignature), payload.challenge);
    console.log("✅ EIP-712 works");
  }

  console.log("\nTest 8: rawHash is refused before any passkey prompt");
  {
    passkeyCalls.length = 0;
    const cause = await rejection(
      sdk.signMessage("0x" + "ab".repeat(32), { mode: "PRIMARY", signingMethod: "rawHash" })
    );
    assert(cause.includes("rawHash signing is not supported in PRIMARY mode"), cause);
    assert.strictEqual(passkeyCalls.length, 0);
    console.log("✅ rawHash refused");
  }

  console.log("\nTest 9: the encoding normalizes high s");
  {
    const n = p256.Point.CURVE().n;
    const der = (r: bigint, s: bigint) => {
      const int = (v: bigint) => {
        let bytes = getBytes("0x" + v.toString(16).padStart(64, "0"));
        if (bytes[0] & 0x80) bytes = new Uint8Array([0, ...bytes]);
        return [0x02, bytes.length, ...bytes];
      };
      const body = [...int(r), ...int(s)];
      return new Uint8Array([0x30, body.length, ...body]);
    };
    const cdj = new TextEncoder().encode('{"type":"webauthn.get","challenge":"AA"}');
    const encoded = encodeWebAuthnSignature({
      authenticatorData: new Uint8Array(37),
      clientDataJSON: cdj,
      signature: der(5n, n - 7n),
    });
    const [, s, challengeIndex, typeIndex] = coder.decode(
      ["bytes32", "bytes32", "uint256", "uint256", "bytes", "string"],
      encoded
    );
    assert.strictEqual(BigInt(s), 7n);
    assert.strictEqual(challengeIndex, 23n);
    assert.strictEqual(typeIndex, 1n);
    console.log("✅ low s");
  }

  console.log("\n✅ All PRIMARY mode signMessage tests passed\n");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
