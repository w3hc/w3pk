/**
 * PRIMARY mode address (#296): getAddress('PRIMARY') and
 * deriveWallet('PRIMARY') return the passkey's W3pkAccount address, one
 * per tag, as W3pkAccountFactory computes it
 *
 * The vectors are pinned by test_sdkVectors in
 * contracts/test/W3pkAccountFactory.t.sol and match the factory deployed
 * on Ethereum Sepolia. The key is the P-256 public key of scalar 0xa11ce.
 *
 * NOTE: the mnemonic is the standard Hardhat test vector, not a real secret
 */

import assert from "node:assert";
import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import { CredentialStorage } from "../src/auth/storage";
import { getOriginSpecificAddress, deriveAddressFromP256PublicKey } from "../src/wallet/origin-derivation";
import {
  W3PK_ACCOUNT_FACTORY,
  W3PK_ACCOUNT_INIT_CODE_HASH,
  getP256Coordinates,
  getSmartAccountSalt,
  getSmartAccountAddress,
} from "../src/wallet/smart-account";

const QX = "0x7268876e19db7d7a651d55d5f3cd08b0f14f0f2d99ac383d56e705cc58b2de09";
const QY = "0x272f3460d10844d9d8a77c0f6f5754c8e1c7fa3a58c6671f9199d8710af43878";
const PUBLIC_KEY_SPKI = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d03010703420004" + QX.slice(2) + QY.slice(2),
  "hex"
).toString("base64url");
const MAIN_ACCOUNT = "0xC92aa436a4B825382f79c4d7a972b76409A45fC2";
const GAMING_ACCOUNT = "0x9bd3912f41dbA1b66425bD5B6046A31685b17143";
const MNEMONIC = "test test test test test test test test test test test junk";
const CREDENTIAL_ID = "smart-account-credential";
const ORIGIN = "http://localhost";

async function runTests() {
  console.log("\n🧪 PRIMARY mode smart account address tests\n");

  await new CredentialStorage(mockLocalStorage).saveCredential({
    id: CREDENTIAL_ID,
    publicKey: PUBLIC_KEY_SPKI,
    username: "smart-account",
    ethereumAddress: MAIN_ACCOUNT,
    createdAt: new Date().toISOString(),
    lastUsed: new Date().toISOString(),
  });

  const newSdk = (config = {}) => {
    const sdk = createWeb3Passkey({ debug: false, ...config });
    (sdk as any).currentUser = {
      username: "smart-account",
      ethereumAddress: "0x0000000000000000000000000000000000000000",
      credentialId: CREDENTIAL_ID,
    };
    (sdk as any).currentPublicKey = PUBLIC_KEY_SPKI;
    (sdk as any).getMnemonicFromSession = async () => MNEMONIC;
    return sdk;
  };

  console.log("Test 1: helpers match W3pkAccountFactory");
  {
    const { qx, qy } = await getP256Coordinates(PUBLIC_KEY_SPKI);
    assert.strictEqual(qx, QX);
    assert.strictEqual(qy, QY);
    assert.strictEqual(await getSmartAccountAddress(PUBLIC_KEY_SPKI), MAIN_ACCOUNT);
    assert.strictEqual(await getSmartAccountAddress(PUBLIC_KEY_SPKI, "GAMING"), GAMING_ACCOUNT);
    assert.strictEqual(W3PK_ACCOUNT_FACTORY, "0xe341d909A1D7dEeec787796b8d305c064aEB5181");
    assert.strictEqual(
      W3PK_ACCOUNT_INIT_CODE_HASH,
      "0x25e8fe200bdf4198a104e71276a83130d745fc9bf71ce23b1e3690729bc6d0c6"
    );
    assert.notStrictEqual(getSmartAccountSalt(QX, QY, "MAIN"), getSmartAccountSalt(QX, QY, "GAMING"));
    console.log("✅ Salt and address match the factory");
  }

  console.log("\nTest 2: getAddress('PRIMARY') and deriveWallet('PRIMARY') return the account");
  {
    const sdk = newSdk();
    assert.strictEqual(await sdk.getAddress("PRIMARY"), MAIN_ACCOUNT);
    assert.strictEqual(await sdk.getAddress("PRIMARY", "MAIN"), MAIN_ACCOUNT);
    const wallet = await sdk.deriveWallet("PRIMARY");
    assert.strictEqual(wallet.address, MAIN_ACCOUNT);
    assert.strictEqual(wallet.tag, "MAIN");
    assert.strictEqual(wallet.privateKey, undefined);
    assert.notStrictEqual(
      MAIN_ACCOUNT.toLowerCase(),
      (await deriveAddressFromP256PublicKey(PUBLIC_KEY_SPKI)).toLowerCase()
    );
    console.log("✅ Both return the MAIN account");
  }

  console.log("\nTest 3: two tags give two accounts");
  {
    const sdk = newSdk();
    assert.strictEqual(await sdk.getAddress("PRIMARY", "GAMING"), GAMING_ACCOUNT);
    assert.strictEqual((await sdk.deriveWallet("PRIMARY", "GAMING")).address, GAMING_ACCOUNT);
    assert.notStrictEqual(MAIN_ACCOUNT, GAMING_ACCOUNT);
    console.log("✅ GAMING has its own account");
  }

  console.log("\nTest 4: smartAccount config overrides the factory");
  {
    const factoryAddress = "0x000000000000000000000000000000000000dEaD";
    const sdk = newSdk({ smartAccount: { factoryAddress } });
    const address = await sdk.getAddress("PRIMARY");
    assert.notStrictEqual(address, MAIN_ACCOUNT);
    assert.strictEqual(address, await getSmartAccountAddress(PUBLIC_KEY_SPKI, "MAIN", { factoryAddress }));
    console.log("✅ Override is used");
  }

  console.log("\nTest 5: STRICT, STANDARD and YOLO addresses are unchanged");
  {
    const sdk = newSdk();
    for (const mode of ["STRICT", "STANDARD", "YOLO"] as const) {
      for (const tag of ["MAIN", "GAMING"]) {
        const expected = (await getOriginSpecificAddress(MNEMONIC, ORIGIN, mode, tag)).address;
        assert.strictEqual(await sdk.getAddress(mode, tag), expected, `${mode} ${tag}`);
        assert.strictEqual((await sdk.deriveWallet(mode, tag)).address, expected, `${mode} ${tag}`);
      }
    }
    console.log("✅ Mnemonic-derived addresses unchanged");
  }

  console.log("\n✅ All PRIMARY smart account address tests passed");
}

runTests().catch((error) => {
  console.error("❌ Test failed:", error);
  process.exit(1);
});
