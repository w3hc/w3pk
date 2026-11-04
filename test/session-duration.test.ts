import { mockLocalStorage } from "./setup";
import { createWeb3Passkey } from "../src/index";
import { SessionManager } from "../src/core/session";
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

  await runTest("setSessionDuration(0) caches nothing", async () => {
    const manager = new SessionManager(1);
    manager.setSessionDuration(0);
    await manager.startSession(MNEMONIC, "cred-id");

    assert(manager.getMnemonic() === null, "getMnemonic() returns null");
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
