/**
 * Backup status: hasBackup, lastBackupAt, methods and the security score cap
 *
 * NOTE: the mnemonic is the standard BIP39 test vector, not a real secret
 */

import { Wallet } from "ethers";
import { Web3Passkey } from "../src/index";
import { BackupManager } from "../src/backup";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  assert,
  assertEqual,
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

function loggedInSdk(): Web3Passkey {
  const sdk = new Web3Passkey();
  (sdk as any).currentUser = {
    username: "alice",
    ethereumAddress: ADDRESS,
    credentialId: "test-credential",
  };
  (sdk as any).getMnemonicFromSession = async () => MNEMONIC;
  return sdk;
}

async function runTests() {
  startTestSuite("Backup Status Tests");

  await runTest("No backup right after registration", async () => {
    localStorage.clear();
    const status = await loggedInSdk().getBackupStatus();

    assertEqual(status.hasBackup, false, "hasBackup is false");
    assertEqual(status.lastBackupAt, undefined, "no lastBackupAt");
    assertEqual(status.methods.length, 0, "no methods");
    assertEqual(await new BackupManager().hasBackup(ADDRESS), false, "manager agrees");
    passTest("hasBackup: false");
  });

  await runTest("Score is capped and vulnerable without a backup", async () => {
    localStorage.clear();
    const status = await loggedInSdk().getBackupStatus();

    assert(status.securityScore.total <= 20, "score capped at 20");
    assertEqual(status.securityScore.level, "vulnerable", "level is vulnerable");
    assert(
      status.securityScore.nextMilestone.includes("backup"),
      "next milestone asks for a backup"
    );
    passTest(`score ${status.securityScore.total}/100`);
  });

  await runTest("createBackupFile records a file backup", async () => {
    localStorage.clear();
    const sdk = loggedInSdk();
    const before = await sdk.getBackupStatus();

    await sdk.createBackupFile("TestStrongPass123!NotReal");
    const after = await sdk.getBackupStatus();

    assertEqual(after.hasBackup, true, "hasBackup is true");
    assertEqual(after.methods.join(","), "file", "method is file");
    assert(!!after.lastBackupAt, "lastBackupAt is set");
    assert(
      after.securityScore.total > before.securityScore.total,
      "score rises once a backup exists"
    );
    passTest(`score ${before.securityScore.total} → ${after.securityScore.total}`);
  });

  await runTest("confirmRecoveryPhraseBackup records a phrase backup", async () => {
    localStorage.clear();
    const sdk = loggedInSdk();

    await sdk.confirmRecoveryPhraseBackup();
    const status = await sdk.getBackupStatus();

    assertEqual(status.hasBackup, true, "hasBackup is true");
    assertEqual(status.methods.join(","), "phrase", "method is phrase");
    assertEqual(
      status.recoveryPhrase.encryptedBackups.length,
      0,
      "a phrase is not an encrypted backup"
    );
    passTest("hasBackup: true");
  });

  await runTest("lastBackupAt is the most recent backup", async () => {
    localStorage.clear();
    const sdk = loggedInSdk();

    await sdk.confirmRecoveryPhraseBackup();
    await new Promise((r) => setTimeout(r, 5));
    await sdk.createBackupFile("TestStrongPass123!NotReal");
    const status = await sdk.getBackupStatus();

    const createdAts = JSON.parse(localStorage.getItem("w3pk_backups")!).map(
      (b: { createdAt: string }) => b.createdAt
    );
    assertEqual(status.lastBackupAt, createdAts.sort().pop(), "latest createdAt");
    assertEqual(status.methods.length, 2, "both methods listed");
    passTest(status.lastBackupAt);
  });

  await runTest("Backups of another wallet don't count", async () => {
    localStorage.clear();
    const other = Wallet.createRandom().address;
    await new BackupManager().confirmRecoveryPhraseBackup(other, "checksum");

    const status = await loggedInSdk().getBackupStatus();
    assertEqual(status.hasBackup, false, "hasBackup is false");
    passTest("scoped to the current wallet");
  });

  await runTest("createBackupFile rejects the removed encryptionType argument", async () => {
    localStorage.clear();
    let error: unknown;
    try {
      await (loggedInSdk() as any).createBackupFile("password", "TestStrongPass123!NotReal");
    } catch (e) {
      error = e;
    }
    assert(error instanceof Error && /only the password/.test(error.message), "throws");
    assertEqual(localStorage.getItem("w3pk_backups"), null, "no backup recorded");
    passTest("rejected");
  });

  await runTest("recommendedMode is password first, then prf", async () => {
    localStorage.clear();
    const sdk = loggedInSdk();
    assertEqual((await sdk.getBackupStatus()).recommendedMode, "password", "no backup: password");

    await sdk.createBackupFile("TestStrongPass123!NotReal");
    assertEqual((await sdk.getBackupStatus()).recommendedMode, "prf", "password backup: prf");

    await (sdk as any).recordBackup("prf");
    assertEqual((await sdk.getBackupStatus()).recommendedMode, undefined, "both: none");
    passTest("password, prf, then none");
  });

  await runTest("A PRF backup alone doesn't count as a backup", async () => {
    localStorage.clear();
    const sdk = loggedInSdk();
    await (sdk as any).recordBackup("prf");
    const status = await sdk.getBackupStatus();

    assertEqual(status.methods.join(","), "prf", "method is prf");
    assertEqual(status.hasBackup, false, "hasBackup is false");
    assertEqual(await new BackupManager().hasBackup(ADDRESS), false, "manager agrees");
    assertEqual(status.recommendedMode, "password", "recommends a password backup");
    assert(status.securityScore.total <= 20, "score capped at 20");
    assertEqual(status.securityScore.level, "vulnerable", "level is vulnerable");
    passTest(`score ${status.securityScore.total}/100`);
  });

  await runTest("A password backup alone isn't penalized", async () => {
    const score = (methods: string[], restoresWithoutPasskey: boolean) =>
      (new BackupManager() as any).calculateSecurityScore(
        { enabled: true, deviceCount: 1 },
        methods.map((method) => ({ id: method, method, location: "local", createdAt: "" })),
        undefined,
        undefined,
        restoresWithoutPasskey
      );
    const passwordOnly = score(["file"], true);
    const prfOnly = score(["prf"], false);
    const both = score(["file", "prf"], true);

    assertEqual(passwordOnly.level, "protected", "password-only: protected");
    assertEqual(both.total, passwordOnly.total, "adding a PRF backup doesn't change the score");
    assert(prfOnly.total <= 20 && prfOnly.level === "vulnerable", "prf-only: capped, vulnerable");
    passTest(`password-only ${passwordOnly.total}, prf-only ${prfOnly.total}`);
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
