# ERC-5564 Stealth Address Flow

Visual guide to understanding how ERC-5564 stealth addresses work.

## Overview Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ERC-5564 Stealth Address Flow                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐                                               ┌──────────────┐
│  RECIPIENT   │                                               │    SENDER    │
│    (Alice)   │                                               │     (Bob)    │
└──────┬───────┘                                               └──────┬───────┘
       │                                                              │
       │ 1. Generate stealth keys                                    │
       │    - Viewing key (private)                                  │
       │    - Spending key (private)                                 │
       │    - Stealth meta-address (public)                          │
       │                                                              │
       │ 2. Share stealth meta-address publicly                      │
       │────────────────────────────────────────────────────────────>│
       │    "0x03f2e32f...037f40766..." (66 bytes)                   │
       │                                                              │
       │                                                              │
       │                              3. Generate ephemeral keypair  │
       │                                 - Random private key        │
       │                                 - Ephemeral public key      │
       │                                                              │
       │                              4. Compute shared secret (ECDH)│
       │                                 ephemeral_priv × viewing_pub│
       │                                                              │
       │                              5. Hash shared secret          │
       │                                 s_h = keccak256(shared)     │
       │                                                              │
       │                              6. Extract view tag            │
       │                                 viewTag = s_h[0] (1 byte)   │
       │                                                              │
       │                              7. Compute stealth pubkey      │
       │                                 stealth = spending + s_h×G  │
       │                                                              │
       │                              8. Derive stealth address      │
       │                                 0x1234...                   │
       │                                                              │
       │ 9. Publish announcement on-chain                            │
       │<────────────────────────────────────────────────────────────│
       │    Event: {                                                 │
       │      stealthAddress: 0x1234...,                             │
       │      ephemeralPubKey: 0x02abcd...,                          │
       │      viewTag: 0xa4                                          │
       │    }                                                         │
       │                                                              │
       │ 10. Send ETH/tokens to stealth address                      │
       │<────────────────────────────────────────────────────────────│
       │     Transfer: 1 ETH → 0x1234...                             │
       │                                                              │
       │ 11. Scan announcements                                      │
       │     For each announcement:                                  │
       │       a. Compute shared secret                              │
       │          viewing_priv × ephemeral_pub                       │
       │       b. Hash it: s_h = keccak256(shared)                   │
       │       c. CHECK VIEW TAG FIRST (optimization!)               │
       │          if s_h[0] != viewTag:                              │
       │            skip (255/256 probability)                       │
       │       d. If matches, compute stealth pubkey                 │
       │          and verify address                                 │
       │                                                              │
       │ 12. If announcement is for Alice:                           │
       │     Compute stealth private key                             │
       │     stealth_priv = spending_priv + s_h                      │
       │                                                              │
       │ 13. Spend funds                                             │
       │     Use stealth_priv to sign transaction                    │
       │                                                              │
       └──────────────────────────────────────────────────────────────
```

## Key Generation Flow

```
┌─────────────────────────────────────────────────────────────┐
│              Recipient Key Generation (One-time)            │
└─────────────────────────────────────────────────────────────┘

    Mnemonic Phrase
    "abandon abandon ... about"
            │
            │
    ┌───────┴────────┐
    │                │
    ▼                ▼
Viewing Path     Spending Path
m/44'/60'/1'/0/0 m/44'/60'/1'/0/1
    │                │
    │                │
    ▼                ▼
Viewing Key      Spending Key
(32 bytes)       (32 bytes)
[PRIVATE]        [PRIVATE]
    │                │
    │                │
    ▼                ▼
Viewing PubKey   Spending PubKey
(33 bytes)       (33 bytes)
[PUBLIC]         [PUBLIC]
    │                │
    └────────┬───────┘
             │
             ▼
    Stealth Meta-Address
    spending_pub + viewing_pub
    (66 bytes, 0x-prefixed)
    [PUBLIC - SHARE THIS]
```

## Sender Generation Flow

```
┌─────────────────────────────────────────────────────────────┐
│         Sender Stealth Address Generation (Per Payment)     │
└─────────────────────────────────────────────────────────────┘

Input: Recipient's Stealth Meta-Address
       0x03f2e32f...037f40766... (66 bytes)
              │
              ▼
       Split into:
       ┌──────────┴──────────┐
       │                     │
       ▼                     ▼
  Spending PubKey      Viewing PubKey
  (33 bytes)           (33 bytes)
       │                     │
       │                     │
       │              Generate Random
       │              Ephemeral Keypair
       │                     │
       │              ┌──────┴──────┐
       │              │             │
       │              ▼             ▼
       │         Ephemeral      Ephemeral
       │         PrivKey        PubKey
       │         (32 bytes)     (33 bytes)
       │              │             │
       │              └──────┬──────┘
       │                     │
       │              Compute ECDH
       │              ephemeral_priv × viewing_pub
       │                     │
       │                     ▼
       │              Shared Secret
       │              (32 bytes)
       │                     │
       │                     │
       │              Hash with keccak256
       │                     │
       │                     ▼
       │              Hashed Shared Secret (s_h)
       │              (32 bytes)
       │              │
       │              ├─────> First byte = View Tag (0xa4)
       │              │
       └──────┬───────┘
              │
       Point Addition:
       stealth_pubkey = spending_pubkey + (s_h × G)
              │
              ▼
       Stealth Public Key
       (33 bytes compressed)
              │
              │
       Derive Address
              │
              ▼
       Stealth Address
       0x1234...5678
       (20 bytes, 0x-prefixed)
              │
              ▼
    ┌─────────────────────┐
    │   Announcement      │
    ├─────────────────────┤
    │ stealthAddress      │
    │ ephemeralPublicKey  │
    │ viewTag             │
    └─────────────────────┘
```

## Recipient Scanning Flow

```
┌─────────────────────────────────────────────────────────────┐
│              Recipient Scanning (Efficient with View Tags)  │
└─────────────────────────────────────────────────────────────┘

For each on-chain announcement:

    Announcement
    ├─ stealthAddress: 0x1234...
    ├─ ephemeralPublicKey: 0x02abcd...
    └─ viewTag: 0xa4
         │
         ▼
    Step 1: Compute Shared Secret
    shared = viewing_privkey × ephemeral_pubkey
         │
         ▼
    Step 2: Hash Shared Secret
    s_h = keccak256(shared)
         │
         ▼
    Step 3: CHECK VIEW TAG FIRST! ⚡
    if s_h[0] != announcement.viewTag:
      └─> SKIP THIS ANNOUNCEMENT (99% of cases)
          Return isForUser: false
         │
    else (1/256 probability):
         ▼
    Step 4: Compute Stealth Public Key
    stealth_pubkey = spending_pubkey + (s_h × G)
         │
         ▼
    Step 5: Derive Address from Public Key
    derived_address = address(stealth_pubkey)
         │
         ▼
    Step 6: Compare Addresses
    if derived_address == announcement.stealthAddress:
         │
         ▼
    ✅ FOUND A PAYMENT!
         │
         ▼
    Step 7: Compute Stealth Private Key
    stealth_privkey = (spending_privkey + s_h) mod n
         │
         ▼
    Return:
    ├─ isForUser: true
    ├─ stealthAddress: 0x1234...
    └─ stealthPrivateKey: 0xabcd... [USE THIS TO SPEND]
```

## View Tag Optimization

```
┌─────────────────────────────────────────────────────────────┐
│         Why View Tags Are Critical for Performance          │
└─────────────────────────────────────────────────────────────┘

WITHOUT View Tags (naive approach):
══════════════════════════════════════

For 10,000 announcements:
  → 10,000 × (ECDH + Hash + EC Point Add + EC Point Multiply + Address Derive)
  → ~30 seconds on standard hardware
  → Not practical for real-world use


WITH View Tags (ERC-5564):
═════════════════════════════

For 10,000 announcements:
  Step 1: Quick checks (all 10,000)
    → 10,000 × (ECDH + Hash + 1-byte compare)
    → ~5 seconds

  Step 2: Full checks (only view tag matches)
    → ~39 announcements × (EC operations + Address derive)
      (1/256 probability × 10,000)
    → ~0.5 seconds

  Total: ~5.5 seconds (6x faster!)
           └─> Practical for real-world scanning


View Tag Distribution:
═════════════════════════

  Out of 10,000 random announcements:

  View Tag     Probability    Expected Matches
  ─────────    ───────────    ────────────────
  0x00         1/256          ~39 announcements
  0x01         1/256          ~39 announcements
  0x02         1/256          ~39 announcements
  ...          ...            ...
  0xff         1/256          ~39 announcements

  Your Payments    Variable       1-10 announcements
  False Positives  1/256 × 10000  ~39 announcements

  Total Full Checks Required: ~40-50 (instead of 10,000!)
```

## Privacy Properties

```
┌─────────────────────────────────────────────────────────────┐
│                  Privacy Analysis                            │
└─────────────────────────────────────────────────────────────┘

What External Observer Sees:
════════════════════════════════

  Transaction 1:
  │ From: 0xSender1
  │ To: 0xStealth_A1  ← Unique address
  │ Amount: 1 ETH
  │ Announcement: {ephemeral_pub_1, viewTag_1}

  Transaction 2:
  │ From: 0xSender2
  │ To: 0xStealth_A2  ← Different unique address
  │ Amount: 0.5 ETH
  │ Announcement: {ephemeral_pub_2, viewTag_2}

  Transaction 3:
  │ From: 0xSender3
  │ To: 0xStealth_B1  ← Unique address (different recipient)
  │ Amount: 2 ETH
  │ Announcement: {ephemeral_pub_3, viewTag_3}

  Observer's Knowledge:
  ✓ Can see all stealth addresses
  ✓ Can see all amounts
  ✓ Can see all ephemeral public keys
  ✓ Can see all view tags

  Observer CANNOT:
  ✗ Link 0xStealth_A1 and 0xStealth_A2 to same recipient
  ✗ Determine who owns any stealth address
  ✗ Compute stealth private keys
  ✗ Identify recipient from meta-address
  ✗ Track recipient's total received amount


What Recipient Knows:
══════════════════════════

  Alice (recipient):
  ✓ Her viewing key and spending key
  ✓ Can identify which stealth addresses are hers:
    - 0xStealth_A1 ✓ (hers)
    - 0xStealth_A2 ✓ (hers)
    - 0xStealth_B1 ✗ (not hers - view tag filtered)
  ✓ Can compute private keys for her addresses
  ✓ Can spend funds from her stealth addresses
  ✓ Her total received: 1.5 ETH


What Sender Knows:
═══════════════════════

  Bob (sender of Transaction 1):
  ✓ Generated ephemeral keypair
  ✓ Knows stealth address 0xStealth_A1
  ✓ Knows his ephemeral public key
  ✓ Sent 1 ETH to that address

  Bob CANNOT:
  ✗ Determine if recipient has received other payments
  ✗ Identify recipient's other stealth addresses
  ✗ Compute stealth private key (missing spending key)
  ✗ Track recipient's activity after the payment


Unlinkability:
═══════════════

  0xStealth_A1    0xStealth_A2
       │               │
       │               │
       ▼               ▼
      ???             ???
       │               │
       └───────┬───────┘
               │
               ▼
          RECIPIENT
     (Only recipient knows
      these are connected!)
```

## Security Model

```
┌─────────────────────────────────────────────────────────────┐
│                     Security Guarantees                      │
└─────────────────────────────────────────────────────────────┘

Cryptographic Assumptions:
═══════════════════════════

  ✓ SECP256k1 elliptic curve discrete log problem is hard
  ✓ ECDH shared secrets are secure
  ✓ Keccak256 is collision-resistant
  ✓ Compressed public keys are 33 bytes
  ✓ Private keys are 32 bytes (256-bit security)


Attack Scenarios:
══════════════════

  Scenario 1: Attacker steals viewing key
  ────────────────────────────────────────
  Attacker CAN:
    ✓ Identify all stealth addresses belonging to recipient
    ✓ Track all payments to the recipient

  Attacker CANNOT:
    ✗ Spend funds (needs spending key)
    ✗ Generate valid stealth addresses for recipient


  Scenario 2: Attacker steals spending key
  ─────────────────────────────────────────
  Attacker CAN:
    ✓ Spend funds from ANY stealth address they discover

  Attacker CANNOT:
    ✗ Identify which addresses belong to recipient
    ✗ Scan for payments (needs viewing key)

  Impact: Limited - attacker must already know addresses


  Scenario 3: Attacker steals BOTH keys (full compromise)
  ────────────────────────────────────────────────────────
  Attacker CAN:
    ✓ Identify all stealth addresses
    ✓ Spend all funds

  Same as stealing recipient's mnemonic phrase!


View Tag Security:
═══════════════════

  View tags reveal 1 byte of hashed shared secret

  Security reduction:
    Without view tag: 256 bits (full hash)
    With view tag: 248 bits (255 unknown bytes)

  Impact: NEGLIGIBLE
    - 248 bits is still cryptographically secure
    - No practical attack exists
    - Privacy benefit >>> security reduction
```

## Common Patterns

### Pattern 1: Simple Payment

```
Sender                          Recipient
  │                               │
  │ 1. Get meta-address           │
  │<──────────────────────────────│
  │                               │
  │ 2. Generate stealth address   │
  │                               │
  │ 3. Send ETH + publish         │
  │──────────────────────────────>│
  │                               │
  │                               │ 4. Scan & find payment
  │                               │ 5. Compute private key
  │                               │ 6. Spend funds
```

### Pattern 2: Batch Scanning

```
Recipient

  Query blockchain events
         │
         ▼
  [Announcement 1]
  [Announcement 2]
  [Announcement 3]
  [...1000 more...]
         │
         ▼
  scanAnnouncements([...])
         │
         ├──> View tag match (1/256) ──> Full check ──> Mine!
         ├──> View tag no match ───────> Skip (99% of cases)
         ├──> View tag no match ───────> Skip
         └──> View tag match ──────────> Full check ──> Not mine

  Result: [My payments only]
```

### Pattern 3: Multi-Chain

```
Recipient generates ONE stealth meta-address
         │
         ├─────> Share on Ethereum
         ├─────> Share on Polygon
         ├─────> Share on Arbitrum
         └─────> Share on Base

Each chain has own announcements
         │
         ├─────> Scan Ethereum events
         ├─────> Scan Polygon events
         ├─────> Scan Arbitrum events
         └─────> Scan Base events

Same viewing/spending keys work on ALL chains!
```

---

## Further Reading

- [ERC-5564 Specification](https://eips.ethereum.org/EIPS/eip-5564)
- [Complete API Documentation](./ERC5564_STEALTH_ADDRESSES.md)
- [Code Examples](../examples/erc5564-stealth-demo.ts)
- [Test Suite](../test/erc5564.test.ts)
