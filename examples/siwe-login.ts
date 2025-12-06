/**
 * SIWE (Sign-In with Ethereum) Example
 *
 * This example demonstrates how to implement Web3 authentication
 * using SIWE (EIP-4361) with w3pk.
 */

import { createWeb3Passkey, generateSiweNonce, createSiweMessage, verifySiweSignature } from 'w3pk';

async function siweLoginExample() {
  // Initialize w3pk
  const w3pk = createWeb3Passkey();

  // Register or login user
  console.log('1. Registering user...');
  await w3pk.register({ username: 'alice' });

  // Get user's address
  const address = await w3pk.getAddress();
  console.log('User address:', address);

  // ===== SERVER SIDE =====
  // Generate a nonce (should be done server-side and stored in session)
  const nonce = generateSiweNonce();
  const issuedAt = new Date().toISOString();
  const expirationTime = new Date(Date.now() + 3600000).toISOString(); // 1 hour

  console.log('\n2. Creating SIWE message...');

  // Create SIWE message
  const siweMessage = createSiweMessage({
    domain: 'example.com',
    address,
    statement: 'Sign in to Example App',
    uri: 'https://example.com/login',
    version: '1',
    chainId: 1,
    nonce,
    issuedAt,
    expirationTime,
  });

  console.log('SIWE message:');
  console.log(siweMessage);

  // ===== CLIENT SIDE =====
  console.log('\n3. Signing SIWE message...');

  // Sign the SIWE message using w3pk
  const result = await w3pk.signMessage(siweMessage, {
    signingMethod: 'SIWE', // Use SIWE signing method
  });

  console.log('Signature:', result.signature);
  console.log('Signed by:', result.address);

  // ===== SERVER SIDE =====
  console.log('\n4. Verifying signature...');

  // Verify the signature (server-side)
  const verification = await verifySiweSignature(
    siweMessage,
    result.signature,
    address
  );

  if (verification.valid) {
    console.log('✅ Authentication successful!');
    console.log('User authenticated as:', verification.address);

    // Create session, issue JWT, etc.
    // session.userId = verification.address;
    // session.nonce = nonce;
  } else {
    console.log('❌ Authentication failed:', verification.error);
  }
}

// Advanced example with full validation
async function siweWithValidation() {
  console.log('\n\n=== Advanced SIWE Example with Validation ===\n');

  const w3pk = createWeb3Passkey();
  await w3pk.register({ username: 'bob' });
  const address = await w3pk.getAddress();

  // Server generates nonce and creates challenge
  const nonce = generateSiweNonce();
  const domain = 'app.example.com';
  const chainId = 1;

  const siweMessage = createSiweMessage({
    domain,
    address,
    statement: 'I accept the Terms of Service: https://example.com/tos',
    uri: 'https://app.example.com/login',
    version: '1',
    chainId,
    nonce,
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 600000).toISOString(), // 10 minutes
    resources: [
      'https://example.com/tos',
      'https://example.com/privacy'
    ],
  });

  // Client signs
  const result = await w3pk.signMessage(siweMessage, {
    signingMethod: 'SIWE',
  });

  // Server validates message structure
  const { validateSiweMessage } = await import('w3pk');
  const validation = validateSiweMessage(siweMessage, {
    domain, // Ensure domain matches
    chainId, // Ensure chain ID matches
    checkExpiration: true, // Check if message expired
  });

  if (!validation.valid) {
    console.log('❌ Message validation failed:', validation.errors);
    return;
  }

  console.log('✅ Message structure valid');

  // Server verifies signature
  const verification = await verifySiweSignature(
    siweMessage,
    result.signature,
    address
  );

  if (verification.valid) {
    console.log('✅ Signature valid - user authenticated!');
    console.log('Parsed message:', validation.parsed);
  } else {
    console.log('❌ Signature invalid:', verification.error);
  }
}

// Run examples
async function main() {
  try {
    await siweLoginExample();
    await siweWithValidation();
  } catch (error) {
    console.error('Error:', error);
  }
}

main();
