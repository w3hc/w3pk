/**
 * Social recovery: Shamir Secret Sharing and the guardian flow through the SDK
 *
 * NOTE: the mnemonics are standard BIP39 test vectors, not real secrets
 */

import { Wallet } from "ethers";
import { Web3Passkey, WeakPasswordError } from "../src/index";
import {
  splitSecret,
  combineShares,
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
} from "../src/recovery/shamir";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  assert,
  assertEqual,
  assertThrows,
} from "./test-utils";

class MemoryStorage {
  private items = new Map<string, string>();
  get length() {
    return this.items.size;
  }
  key(i: number) {
    return [...this.items.keys()][i] ?? null;
  }
  getItem(k: string) {
    return this.items.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.items.set(k, String(v));
  }
  removeItem(k: string) {
    this.items.delete(k);
  }
  clear() {
    this.items.clear();
  }
}

const localStorage = new MemoryStorage();
(globalThis as any).localStorage = localStorage;
(globalThis as any).window = {
  location: { hostname: "localhost", origin: "http://localhost" },
  localStorage,
};

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADDRESS = Wallet.fromPhrase(MNEMONIC).address;
const OTHER_MNEMONIC =
  "test test test test test test test test test test test junk";
const PASSWORD = "TestStrongPass123!NotReal";

function loggedInSdk(mnemonic = MNEMONIC): Web3Passkey {
  const sdk = new Web3Passkey();
  (sdk as any).currentUser = {
    username: "alice",
    ethereumAddress: Wallet.fromPhrase(mnemonic).address,
    credentialId: "test-credential",
  };
  (sdk as any).getMnemonicFromSession = async () => mnemonic;
  return sdk;
}

async function shareFiles(sdk: Web3Passkey, guardianShares: any[]): Promise<string[]> {
  return Promise.all(
    guardianShares.map(async (share) => {
      const invite = await sdk.generateGuardianInvite(share);
      return invite.downloadBlob.text();
    })
  );
}

async function runTests() {
  startTestSuite("Social Recovery Tests");

  await runTest("Shamir 3-of-5 recovers from any 3 shares", async () => {
    const secret = "test secret message for recovery";
    const shares = splitSecret(stringToBytes(secret), 3, 5);

    assertEqual(shares.length, 5, "5 shares");
    assertEqual(shares[0][0], 1, "first share has X=1");
    assertEqual(shares[4][0], 5, "last share has X=5");
    for (const combo of [[0, 1, 2], [1, 2, 3], [0, 2, 4]]) {
      const recovered = combineShares(combo.map((i) => shares[i]), 3);
      assertEqual(bytesToString(recovered), secret, `combo ${combo.join(",")}`);
    }
    await assertThrows(
      () => {
        combineShares(shares.slice(0, 2), 3);
      },
      "2 shares can't rebuild a 3-of-5 secret"
    );
    passTest();
  });

  await runTest("Hex encoding round-trips", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5, 255, 128, 64]);
    const hex = bytesToHex(bytes);

    assertEqual(hex, "0102030405ff8040", "hex encoding");
    assertEqual(hexToBytes(hex).join(","), bytes.join(","), "hex decoding");
    passTest();
  });

  await runTest("setupSocialRecovery gives each guardian a share", async () => {
    localStorage.clear();
    const guardians = [
      { name: "Alice", email: "alice@example.com" },
      { name: "Bob" },
      { name: "Charlie" },
      { name: "Diana" },
      { name: "Eve" },
    ];

    const { guardianShares, setupComplete } = await loggedInSdk().setupSocialRecovery(
      guardians,
      3,
      PASSWORD
    );

    assert(setupComplete, "setup complete");
    assertEqual(guardianShares.length, 5, "one share per guardian");
    guardianShares.forEach((share, i) => {
      assertEqual(share.guardianName, guardians[i].name, "guardian name");
      assertEqual(share.shareIndex, i + 1, "1-based share index");
      assertEqual(share.threshold, 3, "threshold");
      assertEqual(share.walletAddress, ADDRESS, "wallet address");
    });
    assertEqual(
      new Set(guardianShares.map((s) => s.shareData)).size,
      5,
      "shares differ"
    );
    assertEqual(localStorage.length, 0, "no share is stored on the device");
    passTest();
  });

  await runTest("setupSocialRecovery rejects invalid input", async () => {
    const guardians = [{ name: "Alice" }, { name: "Bob" }];

    await assertThrows(
      () => new Web3Passkey().setupSocialRecovery(guardians, 2, PASSWORD).then(() => {}),
      "needs a logged-in user"
    );
    await assertThrows(
      () => loggedInSdk().setupSocialRecovery(guardians, 2, "").then(() => {}),
      "needs a password"
    );
    await assertThrows(
      () => loggedInSdk().setupSocialRecovery(guardians, 3, PASSWORD).then(() => {}),
      "threshold can't exceed the guardians"
    );
    await assertThrows(
      () => loggedInSdk().setupSocialRecovery(guardians, 1, PASSWORD).then(() => {}),
      "threshold is at least 2"
    );
    passTest();
  });

  await runTest("setupSocialRecovery refuses a weak password before the passkey prompt", async () => {
    const sdk = loggedInSdk();
    let prompted = false;
    (sdk as any).getMnemonicFromSession = async () => {
      prompted = true;
      return MNEMONIC;
    };

    let error: unknown;
    try {
      await sdk.setupSocialRecovery([{ name: "Alice" }, { name: "Bob" }], 2, "Password1!");
    } catch (e) {
      error = e;
    }

    assert(error instanceof WeakPasswordError, "throws WeakPasswordError");
    assert(
      (error as WeakPasswordError).feedback.includes("Password is too common"),
      "carries the feedback"
    );
    assertEqual(prompted, false, "no passkey prompt");
    passTest();
  });

  await runTest("generateGuardianInvite builds a share file and document", async () => {
    const sdk = loggedInSdk();
    const { guardianShares } = await sdk.setupSocialRecovery(
      [{ name: "Alice Smith" }, { name: "Bob" }],
      2,
      PASSWORD
    );

    const invite = await sdk.generateGuardianInvite(guardianShares[0], "Keep this safe");
    const file = JSON.parse(await invite.downloadBlob.text());

    assertEqual(invite.filename, "w3pk-guardian-Alice-Smith-share-1.json", "filename");
    assertEqual(file.type, "w3pk-guardian-share", "file type");
    assertEqual(file.shareData, guardianShares[0].shareData, "file holds the share");
    assertEqual(file.threshold, 2, "file holds the threshold");
    assertEqual(file.walletAddress, ADDRESS, "file holds the address");
    assert(invite.shareDocument.includes(guardianShares[0].shareData), "document holds the share");
    assert(invite.shareDocument.includes("Keep this safe"), "document holds the message");
    passTest();
  });

  await runTest("recoverFromGuardians restores from any threshold of shares", async () => {
    const sdk = loggedInSdk();
    const { guardianShares } = await sdk.setupSocialRecovery(
      Array.from({ length: 5 }, (_, i) => ({ name: `Guardian${i + 1}` })),
      3,
      PASSWORD
    );
    const files = await shareFiles(sdk, guardianShares);

    for (const combo of [[0, 1, 2], [1, 3, 4], [0, 2, 4]]) {
      const result = await new Web3Passkey().recoverFromGuardians(
        combo.map((i) => files[i]),
        PASSWORD
      );
      assertEqual(result.mnemonic, MNEMONIC, `mnemonic from ${combo.join(",")}`);
      assertEqual(result.ethereumAddress, ADDRESS, `address from ${combo.join(",")}`);
    }

    const fromObjects = await new Web3Passkey().recoverFromGuardians(
      guardianShares.slice(0, 3),
      PASSWORD
    );
    assertEqual(fromObjects.mnemonic, MNEMONIC, "parsed share objects work too");
    passTest();
  });

  await runTest("recoverFromGuardians rejects bad shares or password", async () => {
    const sdk = loggedInSdk();
    const { guardianShares } = await sdk.setupSocialRecovery(
      [{ name: "Alice" }, { name: "Bob" }, { name: "Charlie" }],
      3,
      PASSWORD
    );
    const files = await shareFiles(sdk, guardianShares);
    const other = loggedInSdk(OTHER_MNEMONIC);
    const otherFiles = await shareFiles(
      other,
      (await other.setupSocialRecovery(
        [{ name: "Alice" }, { name: "Bob" }, { name: "Charlie" }],
        3,
        PASSWORD
      )).guardianShares
    );

    await assertThrows(
      () => new Web3Passkey().recoverFromGuardians(files.slice(0, 2), PASSWORD).then(() => {}),
      "below the threshold"
    );
    await assertThrows(
      () => new Web3Passkey().recoverFromGuardians(files, "WrongPass123!NotReal").then(() => {}),
      "wrong password"
    );
    await assertThrows(
      () =>
        new Web3Passkey()
          .recoverFromGuardians([files[0], files[1], otherFiles[2]], PASSWORD)
          .then(() => {}),
      "shares of two wallets"
    );
    await assertThrows(
      () =>
        new Web3Passkey()
          .recoverFromGuardians([JSON.stringify({ type: "other" }), files[1], files[2]], PASSWORD)
          .then(() => {}),
      "not a guardian share"
    );
    passTest();
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
