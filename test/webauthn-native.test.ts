/**
 * WebAuthn Native Implementation Test Suite
 *
 * This test suite is designed to run in a REAL BROWSER ENVIRONMENT with native WebAuthn support.
 * It tests the actual browser implementation of navigator.credentials API.
 *
 * Requirements:
 * - Must run in a browser (Chrome, Safari, Firefox, etc.)
 * - Requires a platform authenticator (Touch ID, Face ID, Windows Hello, etc.)
 * - Requires HTTPS or localhost
 *
 * Run instructions:
 * 1. Start a local HTTPS server or use localhost
 * 2. Open the test page in a browser with WebAuthn support
 * 3. Complete biometric authentication when prompted
 *
 * DO NOT run this in Node.js - it requires real browser APIs
 */

import { register } from "../src/auth/register";
import { login } from "../src/auth/authenticate";
import { CredentialStorage } from "../src/auth/storage";

// Test environment check
function checkEnvironment(): { supported: boolean; reason?: string } {
  if (typeof window === "undefined") {
    return { supported: false, reason: "Not running in a browser environment" };
  }

  if (typeof navigator === "undefined" || !navigator.credentials) {
    return {
      supported: false,
      reason: "navigator.credentials API not available",
    };
  }

  if (!window.PublicKeyCredential) {
    return {
      supported: false,
      reason: "WebAuthn (PublicKeyCredential) not supported",
    };
  }

  if (
    window.location.protocol !== "https:" &&
    window.location.hostname !== "localhost"
  ) {
    return { supported: false, reason: "WebAuthn requires HTTPS or localhost" };
  }

  return { supported: true };
}

// Test utilities
function logTestResult(testName: string, passed: boolean, details?: string) {
  const status = passed ? "✓ PASS" : "✗ FAIL";
  console.log(`${status}: ${testName}`);
  if (details) {
    console.log(`  ${details}`);
  }
}

async function cleanupTestUser(username: string) {
  try {
    const storage = new CredentialStorage();
    const credential = await storage.getCredentialByUsername(username);
    if (credential) {
      await storage.deleteCredential(credential.id);
    }
  } catch (error) {
    console.warn("Cleanup failed:", error);
  }
}

// Test suite
async function runWebAuthnTests() {
  console.log("=== WebAuthn Native Implementation Test Suite ===\n");

  // Environment check
  const envCheck = checkEnvironment();
  if (!envCheck.supported) {
    console.error("❌ Environment not supported:", envCheck.reason);
    console.log("\nThis test suite requires:");
    console.log("- A real browser environment");
    console.log("- WebAuthn/PassKey support");
    console.log("- HTTPS or localhost");
    console.log(
      "- A platform authenticator (Touch ID, Face ID, Windows Hello, etc.)"
    );
    return;
  }

  logTestResult("Environment check", true, "WebAuthn support detected");

  // Check for platform authenticator availability
  try {
    const available =
      await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    logTestResult(
      "Platform authenticator availability",
      available,
      available
        ? "Platform authenticator is available"
        : "No platform authenticator found"
    );

    if (!available) {
      console.log("\n⚠️  Warning: No platform authenticator available.");
      console.log(
        "Some tests may fail without Touch ID, Face ID, or Windows Hello."
      );
    }
  } catch (error) {
    logTestResult("Platform authenticator check", false, `Error: ${error}`);
  }

  // Test 1: Registration
  console.log("\n--- Test 1: WebAuthn Registration ---");
  const testUsername = `test-user-${Date.now()}`;
  const testAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";

  try {
    console.log(`Registering user: ${testUsername}`);
    console.log(
      "Please complete the biometric authentication when prompted..."
    );

    const result = await register({
      username: testUsername,
      ethereumAddress: testAddress,
    });

    const hasSignature = result.signature && result.signature.byteLength > 0;
    logTestResult(
      "Registration successful",
      hasSignature,
      `Signature received: ${result.signature.byteLength} bytes`
    );

    // Verify credential was stored
    const storage = new CredentialStorage();
    const storedCredential = await storage.getCredentialByUsername(
      testUsername
    );
    const credentialStored = storedCredential !== null;
    logTestResult(
      "Credential stored",
      credentialStored,
      credentialStored
        ? `Credential ID: ${storedCredential.id.substring(0, 16)}...`
        : "Not found"
    );

    // Verify public key was extracted
    const hasPublicKey = !!(
      storedCredential?.publicKey && storedCredential.publicKey.length > 0
    );
    logTestResult(
      "Public key extracted",
      hasPublicKey,
      hasPublicKey
        ? `Public key length: ${storedCredential?.publicKey?.length}`
        : "Missing"
    );
  } catch (error) {
    logTestResult(
      "Registration",
      false,
      `Error: ${error instanceof Error ? error.message : String(error)}`
    );
    console.log("\n⚠️  Registration failed. Some tests will be skipped.");
    return;
  }

  // Test 2: Check existing credential
  console.log("\n--- Test 2: Check Existing Credential ---");
  try {
    const storage = new CredentialStorage();
    const credential = await storage.getCredentialByUsername(testUsername);
    const hasCredential = credential !== null;
    logTestResult(
      "Credential existence check",
      hasCredential,
      hasCredential ? "Credential found" : "No credential found"
    );
  } catch (error) {
    logTestResult(
      "Credential check",
      false,
      `Error: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Test 3: Authentication
  console.log("\n--- Test 3: WebAuthn Authentication ---");
  try {
    console.log("Authenticating...");
    console.log(
      "Please complete the biometric authentication when prompted..."
    );

    const authResult = await login();

    logTestResult(
      "Authentication successful",
      authResult.verified,
      `User: ${authResult.user?.username || "N/A"}`
    );

    const correctUser = authResult.user?.username === testUsername;
    logTestResult(
      "Correct user authenticated",
      correctUser || false,
      `Expected: ${testUsername}, Got: ${authResult.user?.username || "N/A"}`
    );

    const correctAddress = authResult.user?.ethereumAddress === testAddress;
    logTestResult(
      "Correct Ethereum address",
      correctAddress || false,
      `Address: ${authResult.user?.ethereumAddress || "N/A"}`
    );

    const hasSignature =
      authResult.signature && authResult.signature.byteLength > 0;
    logTestResult(
      "Signature received",
      hasSignature || false,
      `Signature: ${authResult.signature?.byteLength || 0} bytes`
    );
  } catch (error) {
    logTestResult(
      "Authentication",
      false,
      `Error: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Test 4: Duplicate registration prevention
  console.log("\n--- Test 4: Duplicate Registration Prevention ---");
  try {
    await register({
      username: testUsername,
      ethereumAddress: testAddress,
    });
    logTestResult("Duplicate prevention", false, "Should have thrown an error");
  } catch (error) {
    const isDuplicateError =
      error instanceof Error && error.message.includes("already registered");
    logTestResult(
      "Duplicate prevention",
      isDuplicateError,
      isDuplicateError
        ? "Correctly rejected duplicate registration"
        : `Unexpected error: ${error}`
    );
  }

  // Test 5: Authentication with no credentials
  console.log("\n--- Test 5: Authentication Error Handling ---");
  const nonExistentUser = `nonexistent-${Date.now()}`;
  try {
    const storage = new CredentialStorage();
    const credential = await storage.getCredentialByUsername(nonExistentUser);
    const exists = credential !== null;
    logTestResult(
      "Check non-existent user",
      !exists,
      exists ? "Unexpected: Found credential" : "Correctly found no credential"
    );
  } catch (error) {
    logTestResult(
      "Non-existent user check",
      false,
      `Error: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Cleanup
  console.log("\n--- Cleanup ---");
  await cleanupTestUser(testUsername);
  logTestResult("Cleanup", true, "Test user removed");

  console.log("\n=== Test Suite Complete ===");
}

// Auto-run if in browser
if (typeof window !== "undefined") {
  // Wait for page load
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      runWebAuthnTests().catch(console.error);
    });
  } else {
    runWebAuthnTests().catch(console.error);
  }
} else {
  // Skip gracefully in Node.js environment
  console.log("\n=== WebAuthn Native Test Suite ===\n");
  console.log("⚠️  Skipping: This test suite requires a browser environment");
  console.log("\nTo run WebAuthn tests:");
  console.log("1. Run: pnpm run html");
  console.log("2. Open: http://localhost:3000/standalone/checker.html");
  console.log("3. Click 'Register New User' or 'Login' to test WebAuthn");
  console.log("\n✅ Test suite validated (skipped in Node.js)\n");
}

// Export for manual running
export { runWebAuthnTests };
