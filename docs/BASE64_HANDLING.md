# Base64 and Base64URL Handling

## Overview

The w3pk SDK handles multiple encoding formats when working with WebAuthn and cryptographic operations:

- **Base64** - Standard encoding used for binary data
- **Base64URL** - URL-safe variant used by WebAuthn (RFC 4648)

## The Problem

WebAuthn responses (credentials, signatures, etc.) use **base64url** encoding, which differs from standard base64:

| Feature | Base64 | Base64URL |
|---------|--------|-----------|
| Characters | `+` and `/` | `-` and `_` |
| Padding | Uses `=` | Often omitted |
| URL-safe | ❌ No | ✅ Yes |

The browser's native `atob()` function **only accepts standard base64** with proper padding, causing errors when used directly with WebAuthn data:

```
Failed to execute 'atob' on 'Window': The string to be decoded is not correctly encoded
```

## Solution

The SDK provides robust utilities in `src/utils/base64.ts` that handle both formats automatically.

### Key Functions

#### `base64UrlToArrayBuffer(base64url: string): ArrayBuffer`

Safely decodes base64url strings to ArrayBuffer:

```typescript
import { base64UrlToArrayBuffer } from 'w3pk/utils/base64';

// WebAuthn credential response (base64url, no padding)
const attestation = "eyJmb3JtYXQiOi..."; // No padding, uses - and _

// Automatically handles conversion and padding
const buffer = base64UrlToArrayBuffer(attestation);
```

**Features:**
- Converts `-` → `+` and `_` → `/`
- Adds proper padding (`=`) automatically
- Returns ArrayBuffer for direct use with crypto APIs

#### `arrayBufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string`

Encodes binary data to base64url format:

```typescript
import { arrayBufferToBase64Url } from 'w3pk/utils/base64';

const challenge = new Uint8Array(32);
crypto.getRandomValues(challenge);

// Returns URL-safe base64url without padding
const encoded = arrayBufferToBase64Url(challenge);
// Result: "Ab3-xY7..." (no padding, uses - and _)
```

**Features:**
- Converts `+` → `-` and `/` → `_`
- Removes padding characters
- URL-safe output

#### `safeAtob(input: string): string`

Safe wrapper for `atob()` that handles both formats:

```typescript
import { safeAtob } from 'w3pk/utils/base64';

// Works with base64url (missing padding)
const decoded1 = safeAtob("eyJmb3JtYXQiOi");

// Works with standard base64 (has padding)
const decoded2 = safeAtob("eyJmb3JtYXQiOi==");

// Automatically detects and handles both
```

**Features:**
- Accepts base64 or base64url
- Adds padding if missing
- Converts URL-safe characters

#### `safeBtoa(input: string): string`

Safe wrapper for `btoa()` that handles Unicode:

```typescript
import { safeBtoa } from 'w3pk/utils/base64';

// Handles Unicode characters that would break btoa()
const encoded = safeBtoa("Hello 世界 🌍");
```

**Features:**
- UTF-8 encoding before base64
- Prevents "Character out of range" errors
- For text data only (not binary)

## Usage in the SDK

### Authentication Flow

```typescript
// src/auth/register.ts
import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from '../utils/base64';

// Generate challenge (base64url format for WebAuthn)
function generateChallenge(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return arrayBufferToBase64Url(array); // URL-safe, no padding
}

// Decode attestation object from WebAuthn
const attestationBuffer = base64UrlToArrayBuffer(
  credential.response.attestationObject
);
```

### Encryption

```typescript
// src/wallet/crypto.ts
import { safeAtob } from '../utils/base64';

// Decrypt with automatic format detection
const binaryString = safeAtob(encryptedData);
const combined = new Uint8Array(binaryString.length);
for (let i = 0; i < binaryString.length; i++) {
  combined[i] = binaryString.charCodeAt(i);
}
```

### Backup System

```typescript
// src/backup/encryption.ts
// For binary data, use native btoa (not safeBtoa)
function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary); // Standard base64 for binary data
}
```

## Best Practices

### ✅ DO

- Use `base64UrlToArrayBuffer()` for WebAuthn responses
- Use `arrayBufferToBase64Url()` for WebAuthn challenges
- Use `safeAtob()` when format is uncertain
- Use native `btoa()` for binary data conversion
- Use `safeBtoa()` only for text with Unicode

### ❌ DON'T

- Don't use `atob()` directly on WebAuthn data
- Don't use `safeBtoa()` for binary data (corrupts bytes)
- Don't manually add/remove padding (use utilities)
- Don't forget to convert URL-safe characters

## Common Patterns

### Pattern 1: WebAuthn Registration

```typescript
// Challenge generation
const challenge = arrayBufferToBase64Url(randomBytes);

// Attestation decoding
const attestation = base64UrlToArrayBuffer(
  credential.response.attestationObject
);
```

### Pattern 2: WebAuthn Authentication

```typescript
// Signature decoding
const signature = base64UrlToArrayBuffer(
  assertion.response.signature
);

// Client data decoding (might be base64url or JSON string)
const clientData = assertion.response.clientDataJSON;
const decoded = clientData.startsWith('eyJ')
  ? safeAtob(clientData)  // base64url
  : clientData;           // already decoded
```

### Pattern 3: Encrypted Data Storage

```typescript
// Encrypting (produces standard base64)
const iv = crypto.getRandomValues(new Uint8Array(12));
const encrypted = await crypto.subtle.encrypt(/* ... */);
const combined = new Uint8Array(iv.length + encrypted.byteLength);
combined.set(iv);
combined.set(new Uint8Array(encrypted), iv.length);

// Use standard base64 for storage
let binary = '';
for (let i = 0; i < combined.length; i++) {
  binary += String.fromCharCode(combined[i]);
}
const stored = btoa(binary);

// Decrypting (accepts base64 or base64url)
const binaryString = safeAtob(stored);
const bytes = new Uint8Array(binaryString.length);
for (let i = 0; i < binaryString.length; i++) {
  bytes[i] = binaryString.charCodeAt(i);
}
```

## Troubleshooting

### Error: "The string to be decoded is not correctly encoded"

**Cause:** Trying to use `atob()` on base64url data without padding.

**Solution:** Use `safeAtob()` or `base64UrlToArrayBuffer()` instead.

### Error: "Character out of range for btoa()"

**Cause:** Trying to encode Unicode text with native `btoa()`.

**Solution:** Use `safeBtoa()` for text data.

### Data Corruption After Encoding

**Cause:** Using `safeBtoa()` (text encoder) on binary data.

**Solution:** Use native `btoa()` for binary data:

```typescript
// ❌ Wrong (corrupts binary data)
const binary = String.fromCharCode(...bytes);
const encoded = safeBtoa(binary); // TextEncoder corrupts it

// ✅ Correct
const binary = String.fromCharCode(...bytes);
const encoded = btoa(binary);
```

## References

- [RFC 4648 - Base64 Encoding](https://datatracker.ietf.org/doc/html/rfc4648)
- [WebAuthn Spec - Base64url Encoding](https://www.w3.org/TR/webauthn-2/#base64url-encoding)
- [MDN - atob()](https://developer.mozilla.org/en-US/docs/Web/API/atob)
- [MDN - btoa()](https://developer.mozilla.org/en-US/docs/Web/API/btoa)

## Version History

- **v0.7.3** - Added comprehensive base64url utilities, fixed registration errors
- **v0.7.2** - Initial backup encryption (had encoding issues)
- **v0.7.0** - Initial release
