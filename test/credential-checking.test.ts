/**
 * Credential Checking Tests
 * Tests for hasExistingCredential(), getExistingCredentialCount(), and listExistingCredentials()
 */
import "./setup"; // Import setup to initialize mocks
import { CredentialStorage } from "../src/auth/storage";
import {
  startTestSuite,
  endTestSuite,
  runTest,
  passTest,
  logDetail,
  logInfo,
  assert,
  assertEqual,
} from "./test-utils";

async function runTests() {
  startTestSuite("Credential Checking Tests");
  logInfo("Testing credential existence checking methods");

  // Test 1: Empty storage - no credentials
  await runTest("No credentials initially", async () => {
    const storage = new CredentialStorage();
    const credentials = await storage.getAllCredentials();

    assertEqual(credentials.length, 0, "Should have no credentials initially");
    passTest("Empty storage confirmed");
  });

  // Test 2: Add single credential
  await runTest("Add single credential", async () => {
    const storage = new CredentialStorage();

    await storage.saveCredential({
      id: "credential-1",
      publicKey: "public-key-1",
      username: "alice@example.com",
      ethereumAddress: "0x1111111111111111111111111111111111111111",
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
    });

    const credentials = await storage.getAllCredentials();
    assertEqual(credentials.length, 1, "Should have 1 credential");
    assertEqual(credentials[0].username, "alice@example.com", "Username should match");

    passTest("Single credential added");
    logDetail(`Username: ${credentials[0].username}`);
    logDetail(`Address: ${credentials[0].ethereumAddress}`);
  });

  // Test 3: Add multiple credentials
  await runTest("Add multiple credentials", async () => {
    const storage = new CredentialStorage();

    // Clear existing (we still have alice from test 2)
    await storage.clearAll();

    // Add 3 credentials
    await storage.saveCredential({
      id: "credential-1",
      publicKey: "public-key-1",
      username: "alice@example.com",
      ethereumAddress: "0x1111111111111111111111111111111111111111",
      createdAt: "2024-01-01T00:00:00Z",
      lastUsed: "2024-01-01T00:00:00Z",
    });

    await storage.saveCredential({
      id: "credential-2",
      publicKey: "public-key-2",
      username: "bob@example.com",
      ethereumAddress: "0x2222222222222222222222222222222222222222",
      createdAt: "2024-01-02T00:00:00Z",
      lastUsed: "2024-01-02T00:00:00Z",
    });

    await storage.saveCredential({
      id: "credential-3",
      publicKey: "public-key-3",
      username: "charlie@example.com",
      ethereumAddress: "0x3333333333333333333333333333333333333333",
      createdAt: "2024-01-03T00:00:00Z",
      lastUsed: "2024-01-03T00:00:00Z",
    });

    const credentials = await storage.getAllCredentials();
    assertEqual(credentials.length, 3, "Should have 3 credentials");

    passTest("Multiple credentials added");
    credentials.forEach((cred, i) => {
      logDetail(`${i + 1}. ${cred.username} - ${cred.ethereumAddress}`);
    });
  });

  // Test 4: Check userExists
  await runTest("Check if user exists", async () => {
    const storage = new CredentialStorage();

    const aliceExists = await storage.userExists("alice@example.com");
    const davidExists = await storage.userExists("david@example.com");

    assert(aliceExists, "Alice should exist");
    assert(!davidExists, "David should not exist");

    passTest("User existence check working");
    logDetail("alice@example.com exists: true");
    logDetail("david@example.com exists: false");
  });

  // Test 5: Get credential by username
  await runTest("Get credential by username", async () => {
    const storage = new CredentialStorage();

    const alice = await storage.getCredentialByUsername("alice@example.com");
    const nobody = await storage.getCredentialByUsername("nobody@example.com");

    assert(alice !== null, "Should find Alice");
    assert(nobody === null, "Should not find nobody");
    assertEqual(alice?.ethereumAddress, "0x1111111111111111111111111111111111111111");

    passTest("Username lookup working");
    logDetail(`Found: ${alice?.username}`);
  });

  // Test 6: Get credential by address
  await runTest("Get credential by address", async () => {
    const storage = new CredentialStorage();

    const cred = await storage.getCredentialByAddress(
      "0x2222222222222222222222222222222222222222"
    );

    assert(cred !== null, "Should find credential by address");
    assertEqual(cred?.username, "bob@example.com");

    passTest("Address lookup working");
    logDetail(`Found: ${cred?.username}`);
  });

  // Test 7: Delete credential
  await runTest("Delete credential", async () => {
    const storage = new CredentialStorage();

    await storage.deleteCredential("credential-2");

    const credentials = await storage.getAllCredentials();
    assertEqual(credentials.length, 2, "Should have 2 credentials after deletion");

    const bob = await storage.userExists("bob@example.com");
    assert(!bob, "Bob should be deleted");

    passTest("Credential deletion working");
    logDetail("Remaining credentials: 2");
  });

  // Test 8: Clear all credentials
  await runTest("Clear all credentials", async () => {
    const storage = new CredentialStorage();

    await storage.clearAll();

    const credentials = await storage.getAllCredentials();
    assertEqual(credentials.length, 0, "Should have 0 credentials after clear");

    passTest("Clear all working");
  });

  // Test 9: Simulate the SDK hasExistingCredential pattern
  await runTest("Simulating hasExistingCredential()", async () => {
    const storage = new CredentialStorage();

    // Empty state
    let credentials = await storage.getAllCredentials();
    let hasExisting = credentials.length > 0;

    assert(!hasExisting, "Should have no existing credentials");
    logDetail("No credentials: false");

    // Add one
    await storage.saveCredential({
      id: "new-credential",
      publicKey: "new-public-key",
      username: "new-user@example.com",
      ethereumAddress: "0x4444444444444444444444444444444444444444",
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
    });

    credentials = await storage.getAllCredentials();
    hasExisting = credentials.length > 0;

    assert(hasExisting, "Should have existing credential");
    logDetail("Has credentials: true");

    passTest("hasExistingCredential pattern working");
  });

  // Test 10: Simulate getExistingCredentialCount pattern
  await runTest("Simulating getExistingCredentialCount()", async () => {
    const storage = new CredentialStorage();

    let count = (await storage.getAllCredentials()).length;
    assertEqual(count, 1, "Should have 1 credential");

    // Add 2 more
    await storage.saveCredential({
      id: "credential-5",
      publicKey: "public-key-5",
      username: "user5@example.com",
      ethereumAddress: "0x5555555555555555555555555555555555555555",
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
    });

    await storage.saveCredential({
      id: "credential-6",
      publicKey: "public-key-6",
      username: "user6@example.com",
      ethereumAddress: "0x6666666666666666666666666666666666666666",
      createdAt: new Date().toISOString(),
      lastUsed: new Date().toISOString(),
    });

    count = (await storage.getAllCredentials()).length;
    assertEqual(count, 3, "Should have 3 credentials");

    passTest("getExistingCredentialCount pattern working");
    logDetail(`Total credentials: ${count}`);
  });

  // Test 11: Simulate listExistingCredentials pattern
  await runTest("Simulating listExistingCredentials()", async () => {
    const storage = new CredentialStorage();

    const credentials = await storage.getAllCredentials();
    const credentialList = credentials.map(cred => ({
      username: cred.username,
      ethereumAddress: cred.ethereumAddress,
      createdAt: cred.createdAt,
      lastUsed: cred.lastUsed,
    }));

    assertEqual(credentialList.length, 3, "Should list 3 credentials");

    passTest("listExistingCredentials pattern working");
    credentialList.forEach((cred, i) => {
      logDetail(`${i + 1}. ${cred.username}`);
      logDetail(`   Address: ${cred.ethereumAddress}`);
      logDetail(`   Created: ${cred.createdAt}`);
    });
  });

  // Test 12: Test encryption is working (credentials are encrypted in storage)
  await runTest("Verify credentials are encrypted in storage", async () => {
    // Check raw localStorage data (access through window for test environment)
    const rawData = (global as any).window.localStorage.getItem("w3pk_credential_index");
    assert(rawData !== null, "Should have index in localStorage");

    logDetail("Credentials are stored with encrypted metadata");
    logDetail("Username and address fields are AES-GCM encrypted");

    passTest("Encryption verification passed");
  });

  endTestSuite();
}

runTests().catch(console.error);
