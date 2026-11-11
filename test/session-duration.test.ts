import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import { SessionManager } from "../src/core/session";
import { PersistentSessionStorage } from "../src/core/persistent-session";
import { derivePrfSessionKey } from "../src/wallet/crypto";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
} from "./test-utils";

const MNEMONIC =
  "test test test test test test test test test test test junk";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
  passTest(message);
}

async function runTests() {
  startTestSuite("Session Duration Tests");

  await runTest("sessionDuration: 0 caches nothing", async () => {
    const manager = new SessionManager(0);
    await manager.startSession(MNEMONIC, "cred-id");

    assert(manager.getMnemonic() === null, "getMnemonic() returns null");
    assert(manager.getCredentialId() === null, "getCredentialId() returns null");
    assert(!manager.isActive(), "isActive() is false");
    assert(manager.getRemainingTime() === 0, "getRemainingTime() is 0");

    let threw = false;
    try {
      manager.extendSession();
    } catch {
      threw = true;
    }
    assert(threw, "extendSession() throws");
  });

  await runTest("sessionDuration: 0 keeps the persistent session", async () => {
    const address = "0x1234567890123456789012345678901234567890";
    const storage = new PersistentSessionStorage();
    await storage.clear();

    const manager = new SessionManager(0, { enabled: true });
    const prfKey = await derivePrfSessionKey(crypto.getRandomValues(new Uint8Array(32)));
    await manager.startSession(MNEMONIC, "cred-id", address, prfKey, "STANDARD");

    assert(manager.getMnemonic() === null, "getMnemonic() returns null");
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert((await storage.retrieve("cred-id")) !== null, "persistent session survives");

    const restored = await manager.restoreFromPersistentStorage(address, "cred-id", prfKey);
    assert(restored === MNEMONIC, "restore returns the mnemonic");
    assert(manager.getMnemonic() === null, "restore caches nothing");

    await storage.clear();
  });

  await runTest("setSessionDuration(0) caches nothing", async () => {
    const manager = new SessionManager(1);
    manager.setSessionDuration(0);
    await manager.startSession(MNEMONIC, "cred-id");

    assert(manager.getMnemonic() === null, "getMnemonic() returns null");
  });

  await runTest("STRICT caches nothing", async () => {
    const address = "0x1234567890123456789012345678901234567890";
    const storage = new PersistentSessionStorage();
    await storage.clear();

    const manager = new SessionManager(1, { enabled: true });
    const prfKey = await derivePrfSessionKey(crypto.getRandomValues(new Uint8Array(32)));
    await manager.startSession(MNEMONIC, "cred-id", address, prfKey, "STRICT");

    assert(manager.getMnemonic() === null, "getMnemonic() returns null");
    assert(!manager.isActive(), "isActive() is false");
    assert((await storage.retrieve("cred-id")) === null, "nothing is persisted");
  });

  await runTest("STRICT leaves the live session as it is", async () => {
    const manager = new SessionManager(1);
    await manager.startSession(MNEMONIC, "cred-id", undefined, undefined, "STANDARD");
    const remaining = manager.getRemainingTime();
    await manager.startSession("other mnemonic", "other-id", undefined, undefined, "STRICT");

    assert(manager.getMnemonic() === MNEMONIC, "the session keeps its mnemonic");
    assert(manager.getCredentialId() === "cred-id", "the session keeps its credential");
    assert(manager.getRemainingTime() <= remaining, "the session isn't extended");
  });

  await runTest("SDK keeps sessionDuration: 0", async () => {
    const sdk = createWeb3Passkey({
      storage: mockLocalStorage,
      sessionDuration: 0,
    });
    const manager = (sdk as unknown as { sessionManager: SessionManager })
      .sessionManager;
    await manager.startSession(MNEMONIC, "cred-id");

    assert(manager.getMnemonic() === null, "getMnemonic() returns null");
    assert(!sdk.hasActiveSession(), "hasActiveSession() is false");
  });

  await runTest("default duration still caches", async () => {
    const sdk = createWeb3Passkey({ storage: mockLocalStorage });
    const manager = (sdk as unknown as { sessionManager: SessionManager })
      .sessionManager;
    await manager.startSession(MNEMONIC, "cred-id");

    assert(manager.getMnemonic() === MNEMONIC, "getMnemonic() returns the mnemonic");
    assert(sdk.getSessionRemainingTime() > 3590, "about an hour remains");
  });

  endTestSuite();
}

runTests().catch((error) => {
  console.error(error);
  process.exit(1);
});
