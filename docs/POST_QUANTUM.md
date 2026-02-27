# Post-Quantum Cryptography

## Executive Summary

The w3pk SDK has **strong conventional cryptography** but is vulnerable to future quantum attacks through its ECDSA signature schemes (secp256k1 and P-256). Based on expert consensus, we have **10-15 years** before cryptographically relevant quantum computers (CRQC) pose real threats. Our strategy: **plan deliberately, not panic**.

This document is aligned with the [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132) (February 2026), which outlines Ethereum's protocol-level approach to quantum threats.

### Current Status: Quantum-Aware Architecture

w3pk can be characterized as:

- ✅ **Quantum-aware** - Architecture designed with quantum migration in mind
- ✅ **Quantum-resistant encryption** - AES-256-GCM provides 128-bit quantum security
- ✅ **Migration-ready** - Account abstraction (EIP-7702 / EIP-4337) enables smooth transition
- ⚠️ **Signature vulnerability** - secp256k1 and P-256 vulnerable to Shor's algorithm
- 🔮 **Timeline to full quantum-readiness** - 18-24 months (Phase 2 completion)

### Risk Assessment

**Low/Moderate Risk Components:**
- ✅ **Encrypted backups** (AES-256-GCM) - Minimal harvest-now-decrypt-later (HNDL) risk
- ✅ **Session encryption** (AES-256-GCM) - Quantum-safe with 128-bit security
- ✅ **PBKDF2** - Moderate risk (Grover's algorithm), easily mitigated

**High Risk Components:**
- ⚠️ **Transaction signatures** (secp256k1 ECDSA) - Shor's algorithm enables private key recovery
- ⚠️ **WebAuthn passkeys** (P-256 ECDSA) - Same vulnerability as secp256k1
- ⚠️ **Stealth addresses** (ERC-5564 ECDH) - Key agreement vulnerable to quantum attacks

---

## Ethereum's Quantum Threat Landscape

Based on the [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132), **four components** of Ethereum are quantum-vulnerable:

1. **Consensus-layer BLS signatures** - Vulnerable to Shor's algorithm
2. **Data availability (KZG commitments+proofs)** - Relies on elliptic curve pairings
3. **EOA signatures (ECDSA)** - **w3pk's primary concern**
4. **Application-layer ZK proofs (KZG or Groth16)** - Pairing-based cryptography

**w3pk addresses #3 (EOA signatures)** through account abstraction and hybrid post-quantum signatures.

### Ethereum's Protocol-Level Solutions

| Component | Current State | Quantum-Safe Solution | Status |
|-----------|---------------|----------------------|--------|
| Consensus signatures | BLS12-381 | Hash-based signatures (Winternitz) + STARKs | Research phase |
| Data availability | KZG | STARKs (recursive proofs for blob verification) | Engineering phase |
| EOA signatures | ECDSA (secp256k1) | **Native AA (EIP-8141) + hash/lattice signatures** | Specification phase |
| ZK proofs | KZG/Groth16 | **Protocol-layer recursive proof aggregation** | Research phase |

**Key insight from the [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132):** Quantum-resistant signatures are **~200,000 gas** for hash-based (Winternitz) and require **vectorized math precompiles** for lattice-based schemes. Protocol-layer proof aggregation will reduce costs to near-zero by replacing validation frames with STARKs.

---

## Current Cryptographic Architecture

### Cryptographic Primitives in Use

#### Asymmetric Cryptography (Quantum-Vulnerable)

| Component | Algorithm | Use Case | Quantum Threat | Ethereum Equivalent |
|-----------|-----------|----------|----------------|---------------------|
| Ethereum Signing | secp256k1 ECDSA | Transaction/message signatures | **HIGH** - Shor's algorithm | EOA signatures (#3) |
| WebAuthn Passkeys | P-256 (ES256) | Authentication signatures | **HIGH** - Shor's algorithm | Not applicable |
| Stealth Addresses | secp256k1 ECDH | Privacy-preserving key exchange | **HIGH** - Shor's algorithm | Application-layer |
| HD Derivation | BIP32/BIP44 | Hierarchical key generation | **HIGH** - Depends on ECDSA | Not applicable |

#### Symmetric Cryptography (Quantum-Resistant)

| Component | Algorithm | Use Case | Quantum Security |
|-----------|-----------|----------|------------------|
| Wallet Encryption | AES-256-GCM | Mnemonic storage | **128-bit** (sufficient) |
| Backup Encryption | AES-256-GCM | Password-based backups | **128-bit** (sufficient) |
| Session Storage | AES-256-GCM | Persistent sessions | **128-bit** (sufficient) |

#### Key Derivation Functions

| Component | Algorithm | Parameters | Quantum Resistance |
|-----------|-----------|------------|-------------------|
| Wallet Encryption | PBKDF2-SHA256 | 210,000 iterations | **Moderate** (Grover's reduces by ~50%) |
| Backup Encryption | PBKDF2-SHA256 | 310,000 iterations | **Moderate** (Grover's reduces by ~50%) |
| Metadata Encryption | PBKDF2-SHA256 | 100,000 iterations | **Moderate** (Grover's reduces by ~50%) |

#### Hash Functions

| Component | Algorithm | Use Case | Quantum Security |
|-----------|-----------|----------|------------------|
| General Hashing | SHA-256 | Checksums, derivation | **128-bit collision** (sufficient) |
| Ethereum Hashing | Keccak-256 | ERC-5564, addresses | **128-bit collision** (sufficient) |

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    WebAuthn Passkey                         │
│              (P-256 ECDSA - Quantum Vulnerable)             │
└──────────────────────┬──────────────────────────────────────┘
                       │ Authentication
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              PBKDF2-SHA256 Key Derivation                   │
│           (210k iterations - Moderate Quantum Risk)         │
└──────────────────────┬──────────────────────────────────────┘
                       │ Derives Encryption Key
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                  AES-256-GCM Encryption                     │
│            (128-bit quantum security - SAFE)                │
└──────────────────────┬──────────────────────────────────────┘
                       │ Decrypts Mnemonic
                       ↓
┌─────────────────────────────────────────────────────────────┐
│                    BIP39 Mnemonic                           │
│                  (12-word seed phrase)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │ BIP44 HD Derivation
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              secp256k1 Private Keys                         │
│           (ECDSA - Quantum Vulnerable)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │ Public Key Generation
                       ↓
┌─────────────────────────────────────────────────────────────┐
│            Ethereum Addresses (Keccak-256)                  │
│              (Hash function - Quantum Safe)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Post-Quantum Migration Strategy

### Implementation Plan Using Ethereum's Native AA Roadmap

We align with the [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132) for quantum-safe EOA signatures:

**Ethereum's Native AA Approach (EIP-8141):**
- ✅ **First-class accounts** that can use any signature algorithm
- ✅ **Validation frames** - Isolated signature verification with STARKs
- ✅ **Protocol-layer recursive aggregation** - Reduces gas costs to near-zero
- ✅ **Hash-based signatures** - ~200,000 gas (Winternitz variants)
- ✅ **Lattice-based signatures** - Requires vectorized math precompiles

**w3pk Interim Solution (Until EIP-8141):**

We will leverage the **[Ethereum Kohaku](https://github.com/ethereum/kohaku)** `pq-account` package, which provides:

- ✅ **ERC-4337 Account Abstraction** - Smart contract accounts with custom signature verification
- ✅ **Dilithium & Falcon Support** - NIST-standardized post-quantum signature schemes
- ✅ **Solidity Verifiers** - On-chain signature verification optimized for gas efficiency
- ✅ **Ethereum Foundation Support** - Official post-quantum cryptography roadmap

**Transition to [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141):** Once native AA is deployed, w3pk will migrate from [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) (bundler-based) to validation frames (protocol-native).

### Phase 1: Foundation (0-6 months) - **CURRENT PHASE**

**Goal:** Establish quantum migration architecture and protect long-term secrets

#### 1.1 Documentation & Planning ⭐ HIGH PRIORITY
- [x] Document quantum threat model (this document)
- [ ] Create Architecture Decision Record (ADR) for quantum migration
- [ ] Establish monitoring for quantum computing advances
- [ ] Define success criteria for quantum readiness

#### 1.2 Increase Key Derivation Security ⭐ MEDIUM PRIORITY
**Rationale:** Grover's algorithm reduces PBKDF2 effective security by ~50%

**Implementation:**
```typescript
// src/wallet/crypto.ts
const PBKDF2_ITERATIONS = {
  backup: {
    classical: 310_000,
    quantumReady: 500_000, // Double security margin
  },
  wallet: {
    classical: 210_000,
    quantumReady: 350_000,
  },
  metadata: {
    classical: 100_000,
    quantumReady: 200_000,
  }
};

// Feature flag for gradual rollout
export async function deriveEncryptionKeyFromWebAuthn(
  credentialId: string,
  publicKey?: string,
  quantumReady: boolean = false
): Promise<CryptoKey> {
  const iterations = quantumReady
    ? PBKDF2_ITERATIONS.wallet.quantumReady
    : PBKDF2_ITERATIONS.wallet.classical;

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array(salt),
      iterations,
      hash: "SHA-256",
    },
    importedKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
```

**Timeline:** 3 months
**Breaking Changes:** None (backward compatible with feature flag)

#### 1.3 Add Crypto-Agility Infrastructure ⭐ HIGH PRIORITY
**Rationale:** Enable algorithm swapping without breaking changes

**Implementation:**
```typescript
// src/core/config.ts
export interface CryptoConfig {
  version: number;

  signatures: {
    ethereum: 'secp256k1' | 'hybrid-pq';
    webauthn: 'p256' | 'hybrid-pq';
    postQuantum?: 'ml-dsa-87' | 'falcon-1024';
    hybridMode: boolean; // Require both classical + PQ
  };

  encryption: {
    symmetric: 'aes-256-gcm';
    kdf: 'pbkdf2-sha256' | 'argon2id';
    quantumReady: boolean;
  };

  minimumSecurityLevel: 'classical' | 'quantum-resistant';
}

// Default configuration
export const DEFAULT_CRYPTO_CONFIG: CryptoConfig = {
  version: 1,
  signatures: {
    ethereum: 'secp256k1',
    webauthn: 'p256',
    hybridMode: false,
  },
  encryption: {
    symmetric: 'aes-256-gcm',
    kdf: 'pbkdf2-sha256',
    quantumReady: false,
  },
  minimumSecurityLevel: 'classical',
};
```

**Timeline:** 2 months
**Breaking Changes:** None (extends existing config)

#### 1.4 Audit Current Implementation ⭐ MEDIUM PRIORITY
- [ ] Review all cryptographic code for side-channel vulnerabilities
- [ ] Verify constant-time operations for sensitive comparisons
- [ ] Test backup/recovery edge cases
- [ ] Conduct security audit of WebAuthn integration

**Timeline:** 3 months
**Cost:** ~$15,000-30,000 for professional audit

### Phase 2: Infrastructure (6-18 months) - **PREPARE**

**Goal:** Integrate Kohaku pq-account and design hybrid signature system

#### 2.1 Integrate Kohaku PQ Account ⭐ HIGH PRIORITY
**Rationale:** Leverage Ethereum Foundation's official post-quantum implementation

Kohaku's `pq-account` provides **production-ready ERC-4337 accounts** with:
- ✅ Hybrid signature verification (classical + post-quantum)
- ✅ Multiple PQ algorithms: MLDSA (Dilithium), MLDSAETH, FALCON, ETHFALCON
- ✅ Deployed on Sepolia testnet
- ✅ Gas-optimized Solidity verifiers

**Kohaku Architecture:**
```
┌──────────────────────────────────────────────────────────┐
│         ERC-4337 User Account Contract                   │
├──────────────────────────────────────────────────────────┤
│  • pre_quantum_pubkey (Ethereum address or P-256 point)  │
│  • post_quantum_pubkey (MLDSA/FALCON public key)         │
│  • pre_quantum_logic_contract_address                    │
│  • post_quantum_logic_contract_address                   │
│  • hybrid_verifier_logic_contract_address                │
└──────────────────────────────────────────────────────────┘
                         ↓
┌──────────────────────────────────────────────────────────┐
│            Hybrid Verifier Contract                      │
│         (Sepolia: 0xD22492F0b9dd284a9EC0fFef3C1675...）  │
├──────────────────────────────────────────────────────────┤
│  Verifies BOTH signatures:                               │
│  • ECDSA (K1/R1) via precompiles                         │
│  • PQ signature via logic contracts                      │
└──────────────────────────────────────────────────────────┘
```

**Deployed Verifier Contracts (Sepolia Testnet):**

| Signature Scheme | Contract Address | Description |
|------------------|------------------|-------------|
| MLDSA (Dilithium) | `0x10c978aacef41c74e35fc30a4e203bf8d9a9e548` | NIST ML-DSA signature verification |
| MLDSAETH | `0x710f295f1715c2b08bccdb1d9841b4f833f6dde4` | Ethereum-optimized ML-DSA |
| FALCON | `0x0724bb7c9e52f3be199964a2d70ff83a103ed99c` | NIST Falcon signature verification |
| ETHFALCON | `0x146f0d9087001995ca63b648e865f6dbbb2d2915` | Ethereum-optimized Falcon |
| ECDSA K1 (secp256k1) | `0xe2c354d06cce8f18fd0fd6e763a858b6963456d1` | Classical Ethereum signatures |
| ECDSA R1 (P-256) | `0x4023f2e318A3c7cbCf2fFAB11A75f99aC9625214` | Classical P-256 (WebAuthn) |
| **Hybrid Verifier** | `0xD22492F0b9dd284a9EC0fFef3C1675deA9f01d85` | **Dual signature verification** |

**Implementation:**
```typescript
// src/pq/kohaku-integration.ts
import { ethers } from 'ethers';

// Kohaku contract addresses (Sepolia testnet)
export const KOHAKU_CONTRACTS = {
  sepolia: {
    mldsa: '0x10c978aacef41c74e35fc30a4e203bf8d9a9e548',
    mldsaeth: '0x710f295f1715c2b08bccdb1d9841b4f833f6dde4',
    falcon: '0x0724bb7c9e52f3be199964a2d70ff83a103ed99c',
    ethfalcon: '0x146f0d9087001995ca63b648e865f6dbbb2d2915',
    ecdsaK1: '0xe2c354d06cce8f18fd0fd6e763a858b6963456d1',
    ecdsaR1: '0x4023f2e318A3c7cbCf2fFAB11A75f99aC9625214',
    hybridVerifier: '0xD22492F0b9dd284a9EC0fFef3C1675deA9f01d85',
  },
  arbitrumSepolia: {
    mldsa: '0x10c978aacef41c74e35fc30a4e203bf8d9a9e548',
    mldsaeth: '0x710f295f1715c2b08bccdb1d9841b4f833f6dde4',
    falcon: '0x0724bb7c9e52f3be199964a2d70ff83a103ed99c',
    ethfalcon: '0x146f0d9087001995ca63b648e865f6dbbb2d2915',
    ecdsaK1: '0xe2c354d06cce8f18fd0fd6e763a858b6963456d1',
    ecdsaR1: '0x4023f2e318A3c7cbCf2fFAB11A75f99aC9625214',
    hybridVerifier: '0xD22492F0b9dd284a9EC0fFef3C1675deA9f01d85',
  },
};

export type PQAlgorithm = 'mldsa' | 'mldsaeth' | 'falcon' | 'ethfalcon';
export type ClassicalAlgorithm = 'secp256k1' | 'p256';

export interface PQAccountConfig {
  algorithm: PQAlgorithm;
  classicalAlgorithm: ClassicalAlgorithm;
  chainId: number; // 11155111 (Sepolia) or 421614 (Arbitrum Sepolia)
  hybridMode: boolean; // Require both signatures
}

/**
 * Deploy w3pk quantum-safe account using Kohaku infrastructure
 * Uses existing Kohaku verifier contracts on Sepolia
 */
export async function deployW3PKQuantumAccount(
  config: PQAccountConfig,
  signer: ethers.Signer
): Promise<string> {
  const network = config.chainId === 11155111 ? 'sepolia' : 'arbitrumSepolia';
  const contracts = KOHAKU_CONTRACTS[network];

  // Get classical public key (secp256k1 or P-256)
  const classicalAddress = await signer.getAddress();
  const classicalPubKey = config.classicalAlgorithm === 'p256'
    ? await extractP256PublicKey(signer) // 64 bytes
    : classicalAddress; // 20 bytes (Ethereum address)

  // Generate post-quantum keypair (using Kohaku's Python signer or WASM)
  const pqKeypair = await generatePQKeypair(config.algorithm);

  // Deploy PK contract for MLDSA/MLDSAETH (stores 20KB public key)
  let pqPubKeyRef: string;
  if (config.algorithm === 'mldsa' || config.algorithm === 'mldsaeth') {
    pqPubKeyRef = await deployPKContract(pqKeypair.publicKey, signer);
  } else {
    pqPubKeyRef = ethers.hexlify(pqKeypair.publicKey); // FALCON stores directly
  }

  // Select logic contract addresses
  const preQuantumLogic = config.classicalAlgorithm === 'secp256k1'
    ? contracts.ecdsaK1
    : contracts.ecdsaR1;
  const postQuantumLogic = contracts[config.algorithm];

  // Deploy ERC-4337 account contract
  const accountFactory = new ethers.ContractFactory(
    KOHAKU_ACCOUNT_ABI,
    KOHAKU_ACCOUNT_BYTECODE,
    signer
  );

  const account = await accountFactory.deploy(
    classicalPubKey,
    pqPubKeyRef,
    preQuantumLogic,
    postQuantumLogic,
    contracts.hybridVerifier
  );

  await account.waitForDeployment();
  const accountAddress = await account.getAddress();

  console.log(`✅ Deployed quantum-safe account: ${accountAddress}`);
  console.log(`   Classical: ${config.classicalAlgorithm} (${preQuantumLogic})`);
  console.log(`   Post-Quantum: ${config.algorithm} (${postQuantumLogic})`);

  return accountAddress;
}

/**
 * Generate post-quantum keypair using Kohaku Python signer
 * Note: Python signer is slow for Falcon (~several seconds)
 */
async function generatePQKeypair(algorithm: PQAlgorithm): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  // Option 1: Use Kohaku Python signer (via child process)
  // Option 2: Use WASM implementation (faster, browser-compatible)
  // Option 3: Use liboqs-js (comprehensive)

  // Placeholder - integrate with actual Kohaku Python signer
  throw new Error('Integrate Kohaku Python signer or WASM alternative');
}

/**
 * Deploy PK contract for MLDSA public key (~20 KB)
 * Required because MLDSA public keys are too large for direct storage
 */
async function deployPKContract(
  publicKey: Uint8Array,
  signer: ethers.Signer
): Promise<string> {
  const pkFactory = new ethers.ContractFactory(
    PK_CONTRACT_ABI,
    PK_CONTRACT_BYTECODE,
    signer
  );

  const pkContract = await pkFactory.deploy(ethers.hexlify(publicKey));
  await pkContract.waitForDeployment();
  const pkAddress = await pkContract.getAddress();

  console.log(`   Deployed PK contract: ${pkAddress}`);
  return pkAddress;
}

/**
 * Sign UserOperation with hybrid signatures (classical + PQ)
 */
export async function signUserOpHybrid(
  userOp: any, // ERC-4337 UserOperation
  classicalWallet: ethers.Wallet,
  pqSigner: any, // Kohaku PQ signer
  config: PQAccountConfig
): Promise<string> {
  const userOpHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['address', 'uint256', 'bytes32', 'bytes32', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'bytes32'],
    [
      userOp.sender,
      userOp.nonce,
      ethers.keccak256(userOp.initCode),
      ethers.keccak256(userOp.callData),
      userOp.callGasLimit,
      userOp.verificationGasLimit,
      userOp.preVerificationGas,
      userOp.maxFeePerGas,
      userOp.maxPriorityFeePerGas,
      ethers.keccak256(userOp.paymasterAndData),
    ]
  ));

  // Classical signature (secp256k1 or P-256)
  const classicalSig = await classicalWallet.signMessage(
    ethers.getBytes(userOpHash)
  );

  // Post-quantum signature (MLDSA, FALCON, etc.)
  const pqSig = await pqSigner.sign(ethers.getBytes(userOpHash));

  // Pack hybrid signature
  // Format: [flags (1 byte)][classical sig (65 bytes)][pq sig (variable)]
  const flags = 0x03; // Both signatures present
  const packedSig = ethers.concat([
    new Uint8Array([flags]),
    ethers.getBytes(classicalSig),
    pqSig,
  ]);

  return ethers.hexlify(packedSig);
}
```

**Example: Deploying w3pk quantum account:**
```typescript
// Example usage in w3pk SDK
const w3pk = createWeb3Passkey({
  quantumSafe: true,
  pqAlgorithm: 'mldsaeth', // Ethereum-optimized Dilithium
});

await w3pk.register({ username: 'alice' });

// Deploy quantum-safe account on Sepolia
const pqAccountAddress = await w3pk.deployQuantumAccount({
  algorithm: 'mldsaeth',
  classicalAlgorithm: 'secp256k1',
  chainId: 11155111, // Sepolia
  hybridMode: true,
});

// Sign transaction with hybrid signatures
const tx = await w3pk.sendTransaction({
  to: '0xRecipient...',
  value: ethers.parseEther('1'),
  chainId: 11155111,
  quantumSafe: true, // Use hybrid signatures
});
```

**Gas Costs (Estimated from Kohaku Tests):**

| Operation | Classical (ECDSA) | Hybrid (ECDSA + MLDSA) | Overhead |
|-----------|-------------------|------------------------|----------|
| Account deployment | ~250,000 gas | ~3,500,000 gas | **14x** |
| Transaction verification | ~21,000 gas | ~800,000 gas | **38x** |
| PK contract deployment | N/A | ~5,000,000 gas | One-time cost |

**Note:** High gas costs are acceptable because:
1. Users deploy account only once
2. PK contract deployed only once per user
3. Transaction verification happens off-chain via bundlers (ERC-4337)
4. L2 deployment (Arbitrum Sepolia) reduces costs by ~10x

**Timeline:** 6 months (integration + testing + mainnet deployment)
**Breaking Changes:** None (opt-in via `quantumSafe: true` flag)

#### 2.2 Design Smart Contract Account Abstraction ⭐ HIGH PRIORITY
**Rationale:** Enable gradual migration without breaking existing wallets

**Architecture Note:** This design follows the validation frame concept from [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141), but implemented using current [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) until native AA is available.

**Smart Contract Architecture:**
```solidity
// contracts/W3PKQuantumAccount.sol
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "@kohaku-eth/pq-account/contracts/verifiers/DilithiumVerifier.sol";
import "@account-abstraction/contracts/core/BaseAccount.sol";

/**
 * W3PK Quantum-Safe Smart Contract Account
 * Supports hybrid classical + post-quantum signature verification
 *
 * FUTURE: This will be replaced by EIP-8141 validation frames when available.
 * Validation frames enable protocol-layer STARK aggregation, reducing gas costs
 * from ~800k to near-zero.
 */
contract W3PKQuantumAccount is BaseAccount {
    // Legacy secp256k1 owner (backward compatibility)
    address public legacyOwner;

    // Post-quantum Dilithium public key (2592 bytes for ML-DSA-87)
    bytes public dilithiumPubKey;

    // Migration state
    bool public quantumMigrationEnabled;
    bool public hybridModeRequired; // Both signatures required

    event QuantumMigrationStarted(address indexed account, bytes pqPubKey);
    event HybridModeEnabled(address indexed account);
    event SignatureVerified(bool classical, bool postQuantum);

    constructor(
        address _legacyOwner,
        bytes memory _dilithiumPubKey
    ) {
        legacyOwner = _legacyOwner;
        dilithiumPubKey = _dilithiumPubKey;
        quantumMigrationEnabled = false;
        hybridModeRequired = false;
    }

    /**
     * Enable quantum migration (add PQ signature requirement)
     */
    function enableQuantumMigration(bytes memory _pqPubKey) external {
        require(msg.sender == legacyOwner, "Only owner");
        dilithiumPubKey = _pqPubKey;
        quantumMigrationEnabled = true;
        emit QuantumMigrationStarted(address(this), _pqPubKey);
    }

    /**
     * Enable hybrid mode (require both signatures)
     */
    function enableHybridMode() external {
        require(msg.sender == legacyOwner, "Only owner");
        require(quantumMigrationEnabled, "Quantum migration not enabled");
        hybridModeRequired = true;
        emit HybridModeEnabled(address(this));
    }

    /**
     * Validate signature (hybrid or single)
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData) {
        bytes memory signature = userOp.signature;

        // Parse signature format
        (bool hasClassical, bool hasPostQuantum, bytes memory classicalSig, bytes memory pqSig) =
            parseHybridSignature(signature);

        bool classicalValid = false;
        bool pqValid = false;

        // Verify classical secp256k1 signature
        if (hasClassical) {
            bytes32 hash = userOpHash.toEthSignedMessageHash();
            address recovered = hash.recover(classicalSig);
            classicalValid = (recovered == legacyOwner);
        }

        // Verify post-quantum Dilithium signature
        if (hasPostQuantum) {
            pqValid = DilithiumVerifier.verify(
                dilithiumPubKey,
                abi.encodePacked(userOpHash),
                pqSig
            );
        }

        emit SignatureVerified(classicalValid, pqValid);

        // Validation logic based on mode
        if (hybridModeRequired) {
            require(classicalValid && pqValid, "Both signatures required");
        } else if (quantumMigrationEnabled) {
            require(classicalValid || pqValid, "At least one signature required");
        } else {
            require(classicalValid, "Classical signature required");
        }

        return 0; // Valid
    }

    /**
     * Parse hybrid signature format
     * Format: [flags (1 byte)][classical sig (65 bytes)][pq sig (variable)]
     */
    function parseHybridSignature(bytes memory signature)
        internal pure
        returns (
            bool hasClassical,
            bool hasPostQuantum,
            bytes memory classicalSig,
            bytes memory pqSig
        )
    {
        require(signature.length > 0, "Empty signature");

        uint8 flags = uint8(signature[0]);
        hasClassical = (flags & 0x01) != 0;
        hasPostQuantum = (flags & 0x02) != 0;

        uint256 offset = 1;

        if (hasClassical) {
            classicalSig = new bytes(65);
            for (uint i = 0; i < 65; i++) {
                classicalSig[i] = signature[offset + i];
            }
            offset += 65;
        }

        if (hasPostQuantum) {
            uint256 pqLength = signature.length - offset;
            pqSig = new bytes(pqLength);
            for (uint i = 0; i < pqLength; i++) {
                pqSig[i] = signature[offset + i];
            }
        }
    }
}
```

**Timeline:** 8 months (including testing and audit)
**Breaking Changes:** None (opt-in smart contract deployment)

#### 2.3 Evaluate Post-Quantum Signature Algorithms ⭐ MEDIUM PRIORITY

**Ethereum Quantum Resistance Roadmap Recommendations:**

**Hash Function Selection (Critical for Hash-Based Signatures):**
The [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132) notes this may be "Ethereum's last hash function", with three candidates:
1. **Poseidon2 + extra rounds** - Potential non-arithmetic layers (eg. Monolith)
2. **Poseidon1** - Older version, not vulnerable to recent Poseidon2 attacks, but 2x slower
3. **BLAKE3 or similar** - Most efficient conventional hash

**Signature Algorithm Options:**

**Hash-Based Signatures (Winternitz variants):**
- ✅ **~200,000 gas** for verification (Vitalik's estimate)
- ✅ Well-understood security
- ⚠️ Large signature sizes (~1-3 KB per signature)
- ⚠️ Stateful (requires careful nonce management)

**Lattice-Based Signatures (ML-DSA / Dilithium):**
- ✅ NIST-standardized ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))
- ✅ Stateless (no nonce management issues)
- ⚠️ **Extremely high gas costs today** (~800,000 gas)
- ✅ **Future optimization:** Vectorized math precompiles could reduce costs significantly
- ✅ The [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132) mentions: "vectorized math precompiles for (+, *, %, dot product, NTT/butterfly)"

**w3pk Strategy:**
1. **Phase 2 (interim):** Use [Kohaku](https://github.com/ethereum/kohaku)'s Dilithium implementation ([ERC-4337](https://eips.ethereum.org/EIPS/eip-4337))
2. **Phase 4 (long-term):** Adopt Ethereum's chosen hash function + Winternitz or optimized lattice signatures via [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) validation frames

**Candidate Libraries:**
```typescript
// Option 1: Kohaku (Ethereum Foundation - RECOMMENDED for interim)
import { DilithiumSigner, FalconSigner } from '@kohaku-eth/pq-account';

// Option 2: Open Quantum Safe (comprehensive, C-based)
import { pqcrypto } from 'liboqs-js';

// Option 3: Future native support (EIP-8141 validation frames)
// Ethereum protocol will provide vectorized math precompiles
```

**Evaluation Matrix:**

| Algorithm | Gas Cost (current) | Gas Cost (with EIP-8141) | Security | Recommendation |
|-----------|-------------------|-------------------------|----------|----------------|
| **Hash-based (Winternitz)** | N/A | ~200,000 gas | ✅ High | **LONG-TERM** |
| **Dilithium (Kohaku)** | ~800,000 gas | ~10,000 gas (optimized) | ✅ NIST Level 5 | **INTERIM** |
| **Falcon (Kohaku)** | ~250,000 gas | ~5,000 gas (optimized) | ✅ NIST Level 5 | Backup |

**Timeline:** 3 months
**Cost:** Free (open source)

#### 2.4 Create Migration Utilities ⭐ MEDIUM PRIORITY
**Rationale:** Enable users to upgrade existing wallets to quantum-safe accounts

**Implementation:**
```typescript
// src/pq/migration.ts
export interface MigrationStatus {
  phase: 'classical' | 'hybrid-testing' | 'hybrid-active' | 'quantum-only';
  classicalKeyActive: boolean;
  pqKeyActive: boolean;
  accountType: 'EOA' | 'smart-contract';
  migrationProgress: number; // 0-100
}

/**
 * Migrate existing w3pk wallet to quantum-safe account
 */
export async function migrateToQuantumAccount(
  w3pk: Web3Passkey,
  options: {
    algorithm: 'dilithium' | 'falcon';
    testMode?: boolean; // Enable hybrid testing first
  }
): Promise<MigrationResult> {
  // 1. Generate PQ keypair
  const pqSigner = options.algorithm === 'dilithium'
    ? new DilithiumSigner()
    : new FalconSigner();
  const { publicKey, privateKey } = await pqSigner.generateKeyPair();

  // 2. Deploy smart contract account
  const classicalAddress = await w3pk.getAddress('STANDARD');
  const pqAccount = await createPQAccount({
    algorithm: options.algorithm,
    hybridMode: !options.testMode, // Start in test mode
    accountAddress: classicalAddress,
  });

  // 3. Transfer assets from EOA to smart contract account
  // (User must manually transfer funds)

  // 4. Store PQ private key (encrypted with WebAuthn)
  await w3pk.storage.saveEncrypted('pq-private-key', privateKey);

  // 5. Update configuration
  await w3pk.updateConfig({
    signatures: {
      ethereum: 'hybrid-pq',
      postQuantum: options.algorithm === 'dilithium' ? 'ml-dsa-87' : 'falcon-1024',
      hybridMode: !options.testMode,
    },
  });

  return {
    success: true,
    newAccountAddress: pqAccount.address,
    pqAlgorithm: options.algorithm,
    phase: options.testMode ? 'hybrid-testing' : 'hybrid-active',
    instructions: [
      'Transfer assets from your existing wallet to new quantum-safe account',
      'Test transactions in hybrid mode',
      'Enable quantum-only mode when ready',
    ],
  };
}

/**
 * Check migration readiness
 */
export async function checkMigrationReadiness(): Promise<ReadinessReport> {
  const checks = {
    browserSupport: await checkWebAssemblySupport(),
    librariesLoaded: await checkKohakuLibraries(),
    accountAbstractionSupport: await checkEIP4337Support(),
    userFundsAvailable: await checkGasBalance(),
  };

  const allPassed = Object.values(checks).every(Boolean);

  return {
    ready: allPassed,
    checks,
    estimatedGasCost: '0.05 ETH', // Approximate deployment cost
    recommendedAction: allPassed
      ? 'Proceed with migration'
      : 'Resolve issues before migrating',
  };
}
```

**Timeline:** 4 months
**Breaking Changes:** None (opt-in migration)

### Phase 3: Transition (18-36 months) - **DEPLOY**

**Goal:** Deploy hybrid signature system and enable user migration

**Important:** This phase assumes [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) as interim solution. Timeline may shift based on [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) native AA deployment.

#### 3.1 Deploy Quantum-Safe Smart Contract Accounts ⭐ HIGH PRIORITY
- [ ] Audit smart contracts (W3PKQuantumAccount)
- [ ] Deploy to testnets (Sepolia, Holesky)
- [ ] Run bug bounty program
- [ ] Deploy to mainnets (Ethereum, Polygon, Arbitrum)
- [ ] Create deployment scripts and documentation
- [ ] **Monitor EIP-8141 progress** - Prepare migration plan from ERC-4337 to validation frames

**Timeline:** 12 months (may extend if waiting for EIP-8141)
**Cost:** ~$50,000-100,000 (audits + bug bounty)

#### 3.2 Launch Hybrid Signature Mode ⭐ HIGH PRIORITY
- [ ] Enable hybrid signatures (classical + PQ) by default for new users
- [ ] Add UI for migration in demo app
- [ ] Create educational content explaining quantum threats
- [ ] Monitor gas costs and optimize verifier contracts

**Timeline:** 6 months
**Breaking Changes:** None (opt-in for existing users)

#### 3.3 Update Documentation & Education ⭐ MEDIUM PRIORITY
- [ ] Update API documentation for PQ methods
- [ ] Create migration guides
- [ ] Publish blog posts on quantum readiness
- [ ] Record video tutorials
- [ ] Update integration examples

**Timeline:** 3 months

#### 3.4 Community & Ecosystem Coordination ⭐ MEDIUM PRIORITY
- [ ] Coordinate with Ethereum Foundation [Kohaku](https://github.com/ethereum/kohaku) team
- [ ] **Track [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) development** - Participate in discussion and testing
- [ ] **Monitor Ethereum's hash function selection** - Prepare to adopt chosen hash ([Poseidon2](https://eprint.iacr.org/2023/323)/[Poseidon1](https://eprint.iacr.org/2019/458)/[BLAKE3](https://github.com/BLAKE3-team/BLAKE3))
- [ ] Participate in [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) quantum standardization
- [ ] Engage with wallet providers (MetaMask, Rainbow)
- [ ] Present at conferences (Devcon, ETHGlobal)

**Timeline:** Ongoing

### Phase 4: Migration (36+ months) - **COMPLETE**

**Goal:** Complete transition to quantum-safe infrastructure

**Critical Dependency:** This phase assumes [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) is deployed. If not, continue with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) solution.

#### 4.1 Migrate to EIP-8141 Validation Frames ⭐ CRITICAL
- [ ] **Adopt native AA** once [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) is deployed
- [ ] **Integrate with protocol-layer proof aggregation** - Leverage STARK-based validation frame verification
- [ ] **Reduce gas costs to near-zero** - Replace individual signature verifications with aggregated STARKs
- [ ] **Adopt Ethereum's chosen hash function** - Implement Winternitz signatures with selected hash ([Poseidon2](https://eprint.iacr.org/2023/323)/[Poseidon1](https://eprint.iacr.org/2019/458)/[BLAKE3](https://github.com/BLAKE3-team/BLAKE3))
- [ ] **Test vectorized math precompiles** - Optimize lattice-based signature verification if precompiles are available
- [ ] **Deprecate [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) bundler dependency** - Transition to protocol-native validation

**Key Insight from the [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132):**
> "Validation frames cannot access the outside world, they can only look at their calldata and return a value... it's possible to replace any validation frame with a STARK that verifies it (potentially a single STARK for all validation frames in a block)."

This means transaction validation happens at **mempool layer** with recursive proofs, making w3pk transactions quantum-safe at near-zero gas overhead.

**Timeline:** 12 months (after [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) deployment)
**Breaking Changes:** Backend migration, transparent to users

#### 4.2 Sunset Legacy Secp256k1-Only Accounts ⭐ LOW PRIORITY
- [ ] Set deprecation timeline (12 months notice)
- [ ] Notify users of legacy accounts
- [ ] Offer free migration assistance
- [ ] Maintain backward compatibility layer
- [ ] Archive legacy code

**Timeline:** 12 months
**Breaking Changes:** Yes (requires user action)

#### 4.3 Default to Post-Quantum for All New Wallets ⭐ HIGH PRIORITY
- [ ] Update `register()` to create PQ accounts by default
- [ ] Update `createWeb3Passkey()` config defaults
- [ ] Remove `quantumReady` feature flags
- [ ] Simplify migration code paths

**Timeline:** 6 months
**Breaking Changes:** None (seamless for new users)

#### 4.4 Monitor Quantum Computing Progress ⭐ ONGOING
- [ ] Subscribe to [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) mailing list
- [ ] Track quantum computing announcements critically
- [ ] Update threat models annually
- [ ] **Participate in Ethereum quantum working groups** - Stay aligned with protocol development
- [ ] **Monitor [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) deployment timeline** - Coordinate w3pk Phase 4 accordingly

**Timeline:** Continuous

---

## Technical Implementation Details

### Signature Size & Gas Cost Comparison

| Scheme | Signature Size | Public Key Size | Security Level | Gas Cost (ERC-4337) | Gas Cost (EIP-8141) |
|--------|----------------|-----------------|----------------|---------------------|---------------------|
| **Classical** |
| secp256k1 | 65 bytes | 33 bytes | Classical only | ~21,000 gas | ~21,000 gas |
| P-256 | 64 bytes | 64 bytes | Classical only | ~40,000 gas | ~40,000 gas |
| **Post-Quantum** |
| **Winternitz (hash-based)** | ~1,500 bytes | ~1,000 bytes | Quantum-safe | N/A | **~200,000 gas** ⭐ |
| ML-DSA-65 (Dilithium3) | 3,309 bytes | 1,952 bytes | NIST Level 3 | ~500,000 gas | **~10,000 gas** (w/ precompiles) |
| ML-DSA-87 (Dilithium5) | 4,627 bytes | 2,592 bytes | NIST Level 5 | ~800,000 gas | **~15,000 gas** (w/ precompiles) |
| Falcon-512 | 666 bytes | 897 bytes | NIST Level 1 | ~150,000 gas | **~5,000 gas** (w/ precompiles) |
| Falcon-1024 | 1,280 bytes | 1,793 bytes | NIST Level 5 | ~250,000 gas | **~8,000 gas** (w/ precompiles) |
| **Hybrid (Classical + PQ)** |
| secp256k1 + ML-DSA-87 | 4,692 bytes | 2,625 bytes | Quantum-safe | ~850,000 gas | **Near-zero** (STARK aggregation) |
| secp256k1 + Falcon-1024 | 1,345 bytes | 1,826 bytes | Quantum-safe | ~300,000 gas | **Near-zero** (STARK aggregation) |

**Key Insights:**
1. **ERC-4337 (Phase 2-3):** Off-chain bundler verification reduces costs, but still ~300k-850k gas per transaction
2. **EIP-8141 (Phase 4):** Validation frames + STARK aggregation reduces costs to **near-zero** via mempool-layer proof composition
3. **Winternitz signatures:** Vitalik's recommended approach (~200k gas) when EIP-8141 is deployed
4. **Vectorized math precompiles:** Enable efficient lattice-based signatures (Dilithium/Falcon) with 10-100x gas reduction

### Hybrid Encryption for Backups

**Current Implementation:**
```typescript
// AES-256-GCM only (quantum-resistant symmetric)
const backup = {
  encrypted: await encryptWithAES(mnemonic, password),
  iv: randomIV,
  salt: randomSalt,
};
```

**Hybrid Implementation (Future):**
```typescript
import { Kyber1024 } from '@kohaku-eth/ml-kem';

// Hybrid: AES-256-GCM + ML-KEM-1024
const kyberKEM = new Kyber1024();
const { publicKey, privateKey } = await kyberKEM.generateKeyPair();

// Encapsulate AES key with Kyber
const { ciphertext, sharedSecret } = await kyberKEM.encapsulate(publicKey);

// Encrypt mnemonic with AES (using KEM-derived key)
const aesKey = await deriveKeyFromKEM(sharedSecret);
const backup = {
  version: 3,
  kemCiphertext: ciphertext,       // Kyber encapsulation
  kemPublicKey: publicKey,          // For decapsulation
  aesEncrypted: await encryptWithAES(mnemonic, aesKey),
  algorithm: 'hybrid-aes-kyber1024',
};

// Decapsulation
const recovered = await kyberKEM.decapsulate(privateKey, backup.kemCiphertext);
const aesKey = await deriveKeyFromKEM(recovered);
const mnemonic = await decryptWithAES(backup.aesEncrypted, aesKey);
```

**Benefits:**
- ✅ Protects against harvest-now-decrypt-later attacks
- ✅ Backward compatible (version field)
- ✅ Only ~1.5 KB overhead
- ✅ No gas costs (off-chain backups)

**Timeline:** Phase 2 (12-18 months, pending stable ML-KEM libraries)

### Quantum-Safe Stealth Addresses

**Current ERC-5564 (ECDH-based):**
```typescript
// Vulnerable to quantum attacks
const sharedSecret = computeECDH(ephemeralPrivKey, viewingPubKey);
const stealthAddress = deriveAddress(sharedSecret);
```

**Quantum-Safe ERC-5564 (ML-KEM-based):**
```typescript
import { Kyber1024 } from '@kohaku-eth/ml-kem';

// Generate ephemeral KEM keypair
const kem = new Kyber1024();
const { publicKey: ephemeralPubKey, privateKey: ephemeralPrivKey } =
  await kem.generateKeyPair();

// Encapsulate to recipient's viewing key
const { ciphertext: kemCiphertext, sharedSecret } =
  await kem.encapsulate(recipientViewingPubKey);

// Derive stealth address from shared secret
const stealthAddress = deriveAddress(sharedSecret);

// Announcement includes KEM ciphertext instead of ephemeral pubkey
const announcement = {
  stealthAddress,
  kemCiphertext,        // ~1,568 bytes (vs 33 bytes for ECDH)
  viewTag: sharedSecret[0],
  protocol: 'erc5564-pq',
};
```

**Challenges:**
- ⚠️ Large announcement size (~1,568 bytes vs 33 bytes)
- ⚠️ Requires ERC-5564 community consensus
- ⚠️ Not backward compatible

**Timeline:** Phase 4 (36+ months, wait for standards)

---

## Quantum Computing Timeline

### Expert Consensus

Based on research from **a16z crypto**, **NIST**, and **Ethereum Foundation**:

- **Conservative estimate:** 10-15 years to CRQC
- **Optimistic estimate:** 5-10 years to CRQC
- **Current risk level:** **Low** (but rising)

### What is a CRQC?

A **Cryptographically Relevant Quantum Computer** must:
- Execute Shor's algorithm to break 256-bit ECDSA in <24 hours
- Maintain ~10,000+ logical qubits with error correction
- Achieve gate fidelity >99.9%

**Current state (2026):**
- IBM: ~1,000 physical qubits (noisy, no error correction)
- Google: ~100 logical qubits (limited coherence time)
- D-Wave: Quantum annealing (not useful for Shor's algorithm)

### Risk Prioritization

```
Priority Ranking (Today):
1. ⚠️  CVE vulnerabilities & implementation bugs - CRITICAL
2. ⚠️  Phishing & social engineering attacks - HIGH
3. ⚠️  Side-channel attacks (timing, power) - HIGH
4. 📊 Monitor quantum computing progress - MEDIUM
5. 📋 Plan quantum migration architecture - MEDIUM
6. 🔮 Deploy post-quantum cryptography - LOW (future)
```

---

## Integration with Existing Features

### Account Abstraction (EIP-7702, EIP-4337, EIP-8141)

**Advantage:** w3pk's existing [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) support provides natural quantum migration path

**Migration Path:**
1. **Phase 1-2:** [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) (current) - Delegate EOA to smart contract
2. **Phase 2-3:** [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) - Bundler-based account abstraction with PQ signatures
3. **Phase 4:** [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) - Native AA with validation frames + STARK aggregation

```typescript
// Existing EIP-7702 authorization (classical)
const auth = await w3pk.signAuthorization({
  contractAddress: '0xSmartContract...',
  chainId: 1,
  nonce: 0n,
});

// Phase 2-3: Hybrid authorization via ERC-4337 (classical + PQ)
const hybridAuth = await w3pk.signAuthorizationHybrid({
  contractAddress: '0xQuantumSafeContract...',
  chainId: 1,
  nonce: 0n,
  algorithm: 'ml-dsa-87',
});

// Phase 4: Native AA with validation frames (EIP-8141)
const validationFrameAuth = await w3pk.signAuthorizationNativeAA({
  contractAddress: '0xQuantumSafeContract...',
  chainId: 1,
  nonce: 0n,
  algorithm: 'winternitz', // Or 'ml-dsa-87' with vectorized precompiles
  useValidationFrames: true, // Protocol-layer STARK aggregation
});
```

**Phase 2-3: ERC-4337 Smart Contract Verification:**
```solidity
function verifyAuthorization(Authorization memory auth) public view {
  // Verify classical signature
  bool classicalValid = ecrecover(auth.hash, auth.signature) == auth.owner;

  // Verify PQ signature
  bool pqValid = DilithiumVerifier.verify(
    auth.pqPublicKey,
    auth.hash,
    auth.pqSignature
  );

  require(classicalValid && pqValid, "Hybrid verification failed");
}
```

**Phase 4: EIP-8141 Validation Frame (Pseudocode):**
```solidity
// Validation frame: isolated, cannot access external state
function validateUserOp(UserOperation calldata userOp) internal pure returns (bool) {
  // Parse hybrid signature from calldata
  (bytes memory classicalSig, bytes memory pqSig) = parseSignature(userOp.signature);

  // Verify both signatures
  bool classicalValid = verifyECDSA(userOp.hash, classicalSig);
  bool pqValid = verifyWinternitz(userOp.hash, pqSig); // Or lattice-based

  return classicalValid && pqValid;
}

// Protocol replaces this validation frame with a STARK proof at mempool layer
// Gas cost: near-zero (single STARK for entire block's validation frames)
```

### External Wallet Integration

**Challenge:** MetaMask, Ledger, etc. don't support PQ signatures yet

**Solution:** Use [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) delegation to w3pk's PQ account
```typescript
// Delegate external wallet to w3pk's quantum-safe account
const delegation = await w3pk.requestExternalWalletDelegation({
  chainId: 1,
  nonce: 0n,
  quantumSafe: true, // Use PQ account as delegation target
});

// External wallet signs classical authorization
// w3pk's smart contract handles PQ verification
```

### WebAuthn & Passkeys

**Challenge:** [FIDO Alliance](https://fidoalliance.org/) doesn't support PQ yet

**FIDO Quantum Roadmap:**
- 2024: Working group formed
- 2025-2026: Specification development
- 2027: First implementations
- 2028+: Browser support

**w3pk Strategy:**
- ✅ Continue using [P-256](https://eips.ethereum.org/EIPS/eip-7951) for authentication (low risk)
- ✅ Use PQ for transaction signatures (high risk)
- ✅ Monitor FIDO specs and update when available

---

## Success Metrics

### Phase 1 Success Criteria (0-6 months)
- [ ] PBKDF2 iterations increased to quantum-ready levels
- [ ] Crypto-agility infrastructure deployed
- [ ] Security audit completed with no critical findings
- [ ] Quantum migration ADR published

### Phase 2 Success Criteria (6-18 months)
- [ ] Kohaku pq-account integrated
- [ ] Smart contract accounts deployed to testnet
- [ ] Migration utilities tested with 100+ users
- [ ] Gas costs optimized below 300,000 per transaction

### Phase 3 Success Criteria (18-36 months)
- [ ] 10,000+ users migrated to quantum-safe accounts
- [ ] Zero critical vulnerabilities in PQ implementation
- [ ] Average gas cost <200,000 per hybrid transaction
- [ ] Integration with 5+ major dApps

### Phase 4 Success Criteria (36+ months)
- [ ] 90%+ of active users on quantum-safe accounts
- [ ] Legacy account deprecation completed
- [ ] Quantum-safe by default for all new registrations
- [ ] Published research papers on implementation

---

## Key Takeaways

### For Developers

1. **Don't panic** - You have 10-15 years before quantum computers threaten cryptography
2. **Plan now, deploy later** - Architecture decisions matter more than rushing code
3. **Follow the [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132)** - [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) validation frames will solve gas costs
4. **Use [Kohaku](https://github.com/ethereum/kohaku) as interim** - Leverage Ethereum Foundation's PQ implementation until native AA
5. **Account abstraction wins** - Smart contract accounts enable smooth migration
6. **Hybrid signatures** - Maintain backward compatibility during transition
7. **Prepare for validation frames** - Design with protocol-layer aggregation in mind
8. **Monitor hash function selection** - Ethereum's choice will impact all applications

### For Users

1. **Your funds are safe today** - No immediate quantum threat
2. **w3pk is quantum-aware** - We're preparing for the future
3. **Backups are protected** - AES-256-GCM is quantum-resistant
4. **Migration will be optional** - You control when to upgrade
5. **No action needed yet** - We'll notify you when migration is ready
6. **Education first** - We'll explain every step of the process

### For Auditors

1. **Current implementation is sound** - Standard cryptography best practices
2. **Quantum threat is acknowledged** - Clear migration roadmap exists
3. **No premature optimization** - Waiting for mature PQ libraries
4. **Backward compatibility prioritized** - Hybrid approach prevents breaking changes
5. **Gas costs optimized** - Off-chain PQ verification via account abstraction
6. **Continuous monitoring** - Regular security audits planned

---

## References & Resources

### Standards & Specifications

- **[EIP-8141: Native Account Abstraction](https://eips.ethereum.org/EIPS/eip-8141)** ⭐ Vitalik's proposed solution for quantum-safe EOAs
- [EIP-4337: Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337) - Current interim solution
- [EIP-7702: Set EOA Account Code](https://eips.ethereum.org/EIPS/eip-7702)
- [EIP-7951: P-256 Signature Verification](https://eips.ethereum.org/EIPS/eip-7951)
- [ERC-5564: Stealth Address Protocol](https://eips.ethereum.org/EIPS/eip-5564)
- [NIST FIPS 204: ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 203: ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)

### Research & Articles

- **[Ethereum Quantum Resistance Roadmap](https://x.com/VitalikButerin/status/2027075026378543132)** ⭐ February 2026 - Ethereum's official quantum plan
- [Quantum Computing Misconceptions - a16z crypto](https://a16zcrypto.com/posts/article/quantum-computing-misconceptions-realities-blockchains-planning-migrations/)
- [Post-Quantum Ethereum - Ethereum Research](https://ethresear.ch/t/the-road-to-post-quantum-ethereum-transaction-is-paved-with-account-abstraction-aa/21783)
- [Ethereum Kohaku Project](https://github.com/ethereum/kohaku)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

### Hash Functions (Ethereum's "Last Hash Function")

- [Poseidon2](https://eprint.iacr.org/2023/323) - ZK-friendly hash with extra security rounds
- [Poseidon1 (original)](https://eprint.iacr.org/2019/458) - 2x slower but not vulnerable to Poseidon2 attacks
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) - Efficient conventional cryptographic hash

### Implementation Libraries

- **Ethereum Kohaku** - [`@kohaku-eth/pq-account`](https://github.com/ethereum/kohaku/tree/master/packages/pq-account)
- **Open Quantum Safe** - [liboqs](https://github.com/open-quantum-safe/liboqs)
- **PQClean** - [Reference implementations](https://github.com/PQClean/PQClean)

---

## Document Maintenance

**Version:** 1.1
**Last Updated:** 2026-02-27
**Next Review:** 2026-08-27 (6 months)
**Maintained By:** Julien Béranger ([@julienbrg](https://github.com/julienbrg))

**Changelog:**
- 2026-02-27: **Updated to align with [Ethereum quantum resistance roadmap](https://x.com/VitalikButerin/status/2027075026378543132)** (February 2026)
  - Added Ethereum's four quantum-vulnerable components
  - Integrated [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141) (native AA) as long-term solution
  - Added validation frames + STARK aggregation approach
  - Updated gas cost estimates for EIP-8141 (near-zero with aggregation)
  - Added hash function selection discussion ([Poseidon2](https://eprint.iacr.org/2023/323)/[Poseidon1](https://eprint.iacr.org/2019/458)/[BLAKE3](https://github.com/BLAKE3-team/BLAKE3))
  - Clarified w3pk uses [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) as interim solution until [EIP-8141](https://eips.ethereum.org/EIPS/eip-8141)
  - Added Phase 4.1: Migration to validation frames
  - Added active links throughout document for all standards, specifications, and resources
- 2026-02-26: Initial version, comprehensive quantum readiness assessment
- 2026-02-26: Added [Kohaku](https://github.com/ethereum/kohaku) pq-account integration plan
- 2026-02-26: Defined 4-phase migration roadmap with timelines

---

## Questions or Feedback?

If you have questions about w3pk's quantum readiness:

1. Open an issue: [GitHub Issues](https://github.com/w3hc/w3pk/issues)
2. Join the discussion: [Element Matrix](https://matrix.to/#/@julienbrg:matrix.org)
3. Email: See [README.md](../README.md) for contact details

**Remember:** Quantum computing is an exciting challenge, not a panic-inducing crisis. We're prepared. 🔐
