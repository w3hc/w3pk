/**
 * Social recovery: Shamir Secret Sharing and the guardian flow through the SDK
 *
 * NOTE: the mnemonics are standard BIP39 test vectors, not real secrets
 */

import { Wallet } from "ethers";
import { InvalidGuardianShareError, Web3Passkey, WeakPasswordError } from "../src/index";
import { guardianShareChecksum } from "../src/recovery/backup-based-recovery";
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
      await sdk.setupSocialRecovery([{ name: "Alice" }, { name: "Bob" }], 2, "passwordpassword");
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
    assert(invite.shareDocument.includes("any\n   2 guardians"), "document states the threshold");
    assert(!invite.shareDocument.includes("-of-N"), "document has no placeholder threshold");
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
      const recovering = new Web3Passkey();
      const result = await recovering.recoverFromGuardians(
        combo.map((i) => files[i]),
        PASSWORD
      );
      assert(!("mnemonic" in result), "doesn't return the mnemonic");
      assertEqual(result.ethereumAddress, ADDRESS, `address from ${combo.join(",")}`);
      assertEqual(
        (recovering as any).currentWallet?.mnemonic,
        MNEMONIC,
        `wallet kept in memory from ${combo.join(",")}`
      );
    }

    const fromObjects = new Web3Passkey();
    await fromObjects.recoverFromGuardians(guardianShares.slice(0, 3), PASSWORD);
    assertEqual(
      (fromObjects as any).currentWallet?.address,
      ADDRESS,
      "parsed share objects work too"
    );
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

  await runTest("a wrong or corrupted share is named in the error", async () => {
    const sdk = loggedInSdk();
    const guardians = [{ name: "Alice" }, { name: "Bob" }, { name: "Charlie" }];
    const { guardianShares } = await sdk.setupSocialRecovery(guardians, 2, PASSWORD);
    const files = await shareFiles(sdk, guardianShares);
    const file = JSON.parse(files[0]);
    assertEqual(file.version, 2, "share file is version 2");
    assert(/^[0-9a-f]{32}$/.test(file.splitId), "share file holds the split id");
    assert(/^[0-9a-f]{64}$/.test(file.checksum), "share file holds the checksum");
    assert(new Set(guardianShares.map((s) => s.splitId)).size === 1, "one split id per setup");

    async function rejection(shares: Array<string | object>): Promise<InvalidGuardianShareError> {
      try {
        await new Web3Passkey().recoverFromGuardians(shares as any, PASSWORD);
      } catch (error) {
        assert(error instanceof InvalidGuardianShareError, `InvalidGuardianShareError, got ${error}`);
        assertEqual((error as InvalidGuardianShareError).code, "GUARDIAN_SHARE_INVALID", "code");
        return error as InvalidGuardianShareError;
      }
      throw new Error("recovery succeeded");
    }
    function named(error: InvalidGuardianShareError, index: number, name: string, label: string) {
      assertEqual(error.shareIndex, index, `${label}: shareIndex`);
      assertEqual(error.guardianName, name, `${label}: guardianName`);
      assert(error.message.startsWith(`Guardian share ${index} (${name})`), `${label}: message names it`);
    }

    const bob = JSON.parse(files[1]);
    const flipped = bob.shareData.slice(0, 10) + (bob.shareData[10] === "0" ? "1" : "0") + bob.shareData.slice(11);
    const corrupted = await rejection([files[0], JSON.stringify({ ...bob, shareData: flipped })]);
    named(corrupted, 2, "Bob", "corrupted share");
    assert(/checksum/.test(corrupted.message), "corrupted share: says the checksum doesn't match");

    const truncated = await rejection([files[0], JSON.stringify({ ...bob, shareData: bob.shareData.slice(0, -1) })]);
    named(truncated, 2, "Bob", "truncated share");

    const relabelled = await rejection([files[0], JSON.stringify({ ...bob, threshold: 3 })]);
    named(relabelled, 2, "Bob", "edited threshold");
    named(await rejection([files[0], JSON.stringify({ ...bob, guardianName: "Charlie" })]), 2, "Charlie", "renamed share");

    const misfit = { ...bob, shareData: "03" + bob.shareData.slice(2) };
    const wrongX = await rejection([files[0], JSON.stringify({ ...misfit, checksum: await guardianShareChecksum(misfit) })]);
    named(wrongX, 2, "Bob", "x-coordinate other than the share index");
    assert(/x-coordinate 3, not its share index/.test(wrongX.message), "wrong x: says so");

    const upper = { ...bob, shareData: bob.shareData.toUpperCase(), splitId: bob.splitId.toUpperCase() };
    const fromUpper = await new Web3Passkey().recoverFromGuardians([files[0], JSON.stringify(upper)], PASSWORD);
    assertEqual(fromUpper.ethereumAddress, ADDRESS, "uppercase hex is accepted");

    const again = await sdk.setupSocialRecovery(guardians, 2, PASSWORD);
    const againFiles = await shareFiles(sdk, again.guardianShares);
    const otherSplit = await rejection([files[0], files[1], againFiles[2]]);
    named(otherSplit, 3, "Charlie", "share from another split of the same wallet");
    assert(/another social recovery setup than share 1 \(Alice\)/.test(otherSplit.message), "another split: names the share it differs from");

    const other = loggedInSdk(OTHER_MNEMONIC);
    const otherFiles = await shareFiles(other, (await other.setupSocialRecovery(guardians, 2, PASSWORD)).guardianShares);
    named(await rejection([files[0], files[1], otherFiles[2]]), 3, "Charlie", "share of another wallet");

    named(await rejection([files[0], files[0]]), 1, "Alice", "the same share twice");

    const { splitId: _, checksum: __, ...v1 } = file;
    const old = await rejection([JSON.stringify({ ...v1, version: 1 }), files[1]]);
    named(old, 1, "Alice", "version 1 share");
    assert(/set up social recovery again/.test(old.message), "version 1 share: says what to do");

    const { checksum: ___, ...noChecksum } = guardianShares[0];
    named(await rejection([noChecksum, guardianShares[1]]), 1, "Alice", "share object without checksum");

    const restored = await new Web3Passkey().recoverFromGuardians([files[2], files[0]], PASSWORD);
    assertEqual(restored.ethereumAddress, ADDRESS, "the untouched shares still restore");
    passTest();
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
