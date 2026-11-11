/**
 * SIWE (Sign-In with Ethereum) Utilities
 * EIP-4361 compliant message construction and validation
 *
 * Reference: https://eips.ethereum.org/EIPS/eip-4361
 */

import { keccak_256 } from '@noble/hashes/sha3.js';

export const SIWE_HEADER = ' wants you to sign in with your Ethereum account:';

/**
 * SIWE message parameters (EIP-4361)
 */
export interface SiweMessage {
  /** RFC 3986 URI scheme of the requesting origin (optional, e.g. "https") */
  scheme?: string;

  /** RFC 3986 authority (e.g., "example.com" or "localhost:3000") */
  domain: string;

  /** Ethereum address performing the signing (EIP-55 checksummed) */
  address: string;

  /** Human-readable statement (optional, no newlines allowed) */
  statement?: string;

  /** RFC 3986 URI referring to the resource subject to the signing */
  uri: string;

  /** EIP-4361 version (must be "1") */
  version: string;

  /** EIP-155 Chain ID */
  chainId: number;

  /** Randomized token for replay attack prevention (min 8 alphanumeric characters) */
  nonce: string;

  /** ISO 8601 datetime when the message was generated */
  issuedAt: string;

  /** ISO 8601 datetime when the message expires (optional) */
  expirationTime?: string;

  /** ISO 8601 datetime when the message becomes valid (optional) */
  notBefore?: string;

  /** System-specific identifier for the sign-in request (optional) */
  requestId?: string;

  /** List of RFC 3986 URIs the user wishes to have resolved (optional) */
  resources?: string[];
}

/**
 * Generate a cryptographically secure random nonce for SIWE
 *
 * @param length - Length of the nonce (default: 11 characters)
 * @returns Alphanumeric nonce string
 *
 * @example
 * const nonce = generateSiweNonce()
 * console.log(nonce) // => "YqPj9K2xL8m"
 */
export function generateSiweNonce(length: number = 11): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  // Bytes at or above 248 (4 * 62) are dropped so each character is equally likely
  const limit = 256 - (256 % chars.length);
  let nonce = '';
  while (nonce.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(Math.min(length - nonce.length, 65536)));
    for (const byte of bytes) {
      if (byte < limit) nonce += chars[byte % chars.length];
    }
  }
  return nonce;
}


const LINE_BREAK = /[\r\n]/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i;

// EIP-4361 ABNF terms, with RFC 3986 character classes
const UNRESERVED = "A-Za-z0-9\\-._~";
const SUB_DELIMS = "!$&'()*+,;=";
const PCT_ENCODED = "%[0-9A-Fa-f]{2}";
const SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*$/;
const HEADER = new RegExp(
  `^(?:([A-Za-z][A-Za-z0-9+.-]*)://)?((?:[${UNRESERVED}${SUB_DELIMS}:@[\\]]|${PCT_ENCODED})+)${SIWE_HEADER}$`
);
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const STATEMENT = new RegExp(`^[${UNRESERVED}:/?#[\\]@${SUB_DELIMS} ]*$`);
const URI = new RegExp(
  `^[A-Za-z][A-Za-z0-9+.-]*:(?:[${UNRESERVED}:/?#[\\]@${SUB_DELIMS}]|${PCT_ENCODED})*$`
);
const CHAIN_ID = /^[0-9]+$/;
const NONCE = /^[A-Za-z0-9]{8,}$/;
const REQUEST_ID = new RegExp(`^(?:[${UNRESERVED}${SUB_DELIMS}:@]|${PCT_ENCODED})*$`);

/** EIP-55: a mixed-case address must match its checksum */
function hasValidChecksum(address: string): boolean {
  const hex = address.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return true;
  const hash = keccak_256(new TextEncoder().encode(hex.toLowerCase()));
  for (let i = 0; i < 40; i++) {
    const nibble = (hash[i >> 1] >> (i % 2 === 0 ? 4 : 0)) & 0x0f;
    const expected = nibble >= 8 ? hex[i].toUpperCase() : hex[i].toLowerCase();
    if (hex[i] !== expected) return false;
  }
  return true;
}

function lineBreakFieldError(params: SiweMessage): string | undefined {
  if (params.statement && LINE_BREAK.test(params.statement)) {
    return 'Statement cannot contain line breaks';
  }
  if (LINE_BREAK.test(params.domain)) {
    return 'Domain cannot contain line breaks';
  }
  if (LINE_BREAK.test(params.uri)) {
    return 'URI cannot contain line breaks';
  }
  if (params.resources?.some((resource) => LINE_BREAK.test(resource))) {
    return 'Resources cannot contain line breaks';
  }
  return undefined;
}

function parseDate(value: string): Date | undefined {
  if (!RFC3339.test(value)) return undefined;
  const date = new Date(value);
  return isNaN(date.getTime()) ? undefined : date;
}

/**
 * Create a properly formatted SIWE message according to EIP-4361
 *
 * @param params - SIWE message parameters
 * @returns EIP-4361 compliant message string
 * @throws Error if a field is missing, or the message wouldn't pass parseSiweMessage()
 *
 * @example
 * const message = createSiweMessage({
 *   domain: 'example.com',
 *   address: '0x1234...5678',
 *   uri: 'https://example.com/login',
 *   version: '1',
 *   chainId: 1,
 *   nonce: generateSiweNonce(),
 *   issuedAt: new Date().toISOString(),
 *   statement: 'Sign in to Example App'
 * })
 *
 * // Sign with w3pk
 * const result = await w3pk.signMessage(message, { signingMethod: 'SIWE' })
 */
export function createSiweMessage(params: SiweMessage): string {
  // Validate required fields
  if (!params.domain || !params.address || !params.uri || !params.version ||
      params.chainId === undefined || !params.nonce || !params.issuedAt) {
    throw new Error('Missing required SIWE message fields');
  }

  // Validate version
  if (params.version !== '1') {
    throw new Error('SIWE version must be "1"');
  }

  // Validate nonce (minimum 8 alphanumeric characters)
  if (params.nonce.length < 8 || !/^[a-zA-Z0-9]+$/.test(params.nonce)) {
    throw new Error('Nonce must be at least 8 alphanumeric characters');
  }

  const lineBreakError = lineBreakFieldError(params);
  if (lineBreakError) {
    throw new Error(lineBreakError);
  }

  if (params.statement && !STATEMENT.test(params.statement)) {
    throw new Error('Statement must be ASCII letters, digits, spaces or RFC 3986 reserved characters');
  }

  if (params.scheme !== undefined && !SCHEME.test(params.scheme)) {
    throw new Error('Scheme must be an RFC 3986 URI scheme');
  }

  // Build message according to EIP-4361 ABNF spec
  const origin = params.scheme ? `${params.scheme}://${params.domain}` : params.domain;
  let message = `${origin}${SIWE_HEADER}\n`;
  message += `${params.address}\n`;
  message += `\n`;

  if (params.statement !== undefined) {
    message += `${params.statement}\n`;
  }
  message += `\n`;

  message += `URI: ${params.uri}\n`;
  message += `Version: ${params.version}\n`;
  message += `Chain ID: ${params.chainId}\n`;
  message += `Nonce: ${params.nonce}\n`;
  message += `Issued At: ${params.issuedAt}`;

  if (params.expirationTime) {
    message += `\nExpiration Time: ${params.expirationTime}`;
  }

  if (params.notBefore) {
    message += `\nNot Before: ${params.notBefore}`;
  }

  if (params.requestId) {
    message += `\nRequest ID: ${params.requestId}`;
  }

  if (params.resources && params.resources.length > 0) {
    message += `\nResources:`;
    for (const resource of params.resources) {
      message += `\n- ${resource}`;
    }
  }

  parseSiweMessage(message);
  return message;
}

/**
 * Parse a SIWE message string into structured data
 *
 * The message must follow the EIP-4361 ABNF exactly: fields in order, each
 * once, with no other lines and no trailing line break. Values must match
 * their ABNF terms, dates are RFC 3339, and a mixed-case address must carry
 * a valid EIP-55 checksum.
 *
 * @param message - EIP-4361 formatted SIWE message
 * @returns Parsed SIWE message object
 * @throws Error if the message doesn't follow EIP-4361
 *
 * @example
 * const parsed = parseSiweMessage(signedMessage)
 * console.log('Domain:', parsed.domain)
 * console.log('Address:', parsed.address)
 * console.log('Nonce:', parsed.nonce)
 */
export function parseSiweMessage(message: string): SiweMessage {
  const fail = (reason: string): never => {
    throw new Error(`Invalid SIWE message: ${reason}`);
  };
  const lines = message.split('\n');
  let i = 0;
  const next = (): string | undefined => lines[i++];
  const field = (prefix: string, pattern: RegExp, name: string): string => {
    const line = next();
    if (line === undefined || !line.startsWith(prefix)) fail(`expected "${prefix.trimEnd()}" on line ${i}`);
    const value = line!.slice(prefix.length);
    if (!pattern.test(value)) fail(`malformed ${name}`);
    return value;
  };
  const optional = (prefix: string, pattern: RegExp, name: string): string | undefined =>
    lines[i]?.startsWith(prefix) ? field(prefix, pattern, name) : undefined;
  const date = (value: string | undefined, name: string): string | undefined => {
    if (value !== undefined && !parseDate(value)) fail(`Invalid ${name} date: "${value}"`);
    return value;
  };

  const header = HEADER.exec(next()!);
  if (!header) fail('malformed domain line');
  const [, scheme, domain] = header!;

  const address = next();
  if (address === undefined || !ADDRESS.test(address)) fail('malformed address');
  if (!hasValidChecksum(address!)) fail('address fails its EIP-55 checksum');

  if (next() !== '') fail('expected an empty line after the address');

  let statement: string | undefined;
  if (lines[i] !== '' || lines[i + 1] === '') {
    statement = next();
    if (statement === undefined || !STATEMENT.test(statement)) fail('malformed statement');
  }
  if (next() !== '') fail('expected an empty line before the URI');

  const uri = field('URI: ', URI, 'URI');
  const version = field('Version: ', /^1$/, 'version');
  const chainIdText = field('Chain ID: ', CHAIN_ID, 'chain ID');
  const chainId = Number(chainIdText);
  if (!Number.isSafeInteger(chainId)) fail('chain ID out of range');
  const nonce = field('Nonce: ', NONCE, 'nonce');
  const issuedAt = date(field('Issued At: ', /^/, 'Issued At'), 'Issued At')!;
  const expirationTime = date(optional('Expiration Time: ', /^/, 'Expiration Time'), 'Expiration Time');
  const notBefore = date(optional('Not Before: ', /^/, 'Not Before'), 'Not Before');
  const requestId = optional('Request ID: ', REQUEST_ID, 'request ID');

  let resources: string[] | undefined;
  if (lines[i] === 'Resources:') {
    next();
    resources = [];
    while (i < lines.length) resources.push(field('- ', URI, 'resource'));
  }

  if (i < lines.length) fail(`unexpected line ${i + 1}`);

  return {
    ...(scheme !== undefined && { scheme }),
    domain,
    address: address!,
    statement,
    uri,
    version,
    chainId,
    nonce,
    issuedAt,
    expirationTime,
    notBefore,
    requestId,
    resources: resources?.length ? resources : undefined,
  };
}

/**
 * Validate a SIWE message for correctness and expiration
 *
 * `Issued At`, `Expiration Time` and `Not Before` must be valid dates, and
 * the message fails once expired or before its not-before time.
 *
 * @param message - SIWE message string or parsed object
 * @param options - Validation options
 * @returns Validation result with details
 *
 * @example
 * const validation = validateSiweMessage(message, {
 *   domain: 'example.com',
 *   chainId: 1
 * })
 *
 * if (validation.valid) {
 *   console.log('Message is valid')
 * } else {
 *   console.error('Invalid:', validation.errors)
 * }
 */
export function validateSiweMessage(
  message: string | SiweMessage,
  options?: {
    /** Expected domain (validates domain matches) */
    domain?: string;
    /** Expected scheme; a message without one is https (EIP-4361) */
    scheme?: string;
    /** Expected chain ID */
    chainId?: number;
  }
): {
  valid: boolean;
  errors: string[];
  parsed?: SiweMessage;
} {
  const errors: string[] = [];

  try {
    // Parse if string
    const parsed = typeof message === 'string' ? parseSiweMessage(message) : message;

    // Validate domain if specified
    if (options?.domain && parsed.domain !== options.domain) {
      errors.push(`Domain mismatch: expected "${options.domain}", got "${parsed.domain}"`);
    }

    const scheme = parsed.scheme ?? 'https';
    if (options?.scheme && scheme.toLowerCase() !== options.scheme.toLowerCase()) {
      errors.push(`Scheme mismatch: expected "${options.scheme}", got "${scheme}"`);
    }

    // Validate chain ID if specified
    if (options?.chainId !== undefined && parsed.chainId !== options.chainId) {
      errors.push(`Chain ID mismatch: expected ${options.chainId}, got ${parsed.chainId}`);
    }

    // Validate version
    if (parsed.version !== '1') {
      errors.push(`Invalid version: must be "1", got "${parsed.version}"`);
    }

    // Validate nonce
    if (parsed.nonce.length < 8 || !/^[a-zA-Z0-9]+$/.test(parsed.nonce)) {
      errors.push('Nonce must be at least 8 alphanumeric characters');
    }

    const lineBreakError = lineBreakFieldError(parsed);
    if (lineBreakError) {
      errors.push(lineBreakError);
    }

    const now = new Date();

    if (!parseDate(parsed.issuedAt)) {
      errors.push(`Invalid Issued At date: "${parsed.issuedAt}"`);
    }

    if (parsed.expirationTime !== undefined) {
      const expirationDate = parseDate(parsed.expirationTime);
      if (!expirationDate) {
        errors.push(`Invalid Expiration Time date: "${parsed.expirationTime}"`);
      } else if (expirationDate <= now) {
        errors.push('Message has expired');
      }
    }

    if (parsed.notBefore !== undefined) {
      const notBeforeDate = parseDate(parsed.notBefore);
      if (!notBeforeDate) {
        errors.push(`Invalid Not Before date: "${parsed.notBefore}"`);
      } else if (notBeforeDate > now) {
        errors.push('Message is not yet valid (not-before constraint)');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      parsed,
    };
  } catch (error) {
    errors.push((error as Error).message);
    return {
      valid: false,
      errors,
    };
  }
}

/**
 * Check that a SIWE message's domain matches `origin` (EIP-4361): same host
 * and port, and same scheme when the domain names one
 *
 * @throws Error if the message doesn't parse or its domain doesn't match
 */
export function assertSiweDomain(message: string, origin: string): void {
  const { scheme, domain } = parseSiweMessage(message);
  const expected = new URL(origin);
  let actual: URL;
  try {
    actual = new URL(`${scheme ? `${scheme}:` : expected.protocol}//${domain}`);
  } catch {
    throw new Error(`Invalid SIWE message domain "${domain}"`);
  }
  if (actual.protocol !== expected.protocol || actual.host !== expected.host) {
    throw new Error(
      `SIWE message domain "${domain}" does not match the current origin "${expected.host}"`
    );
  }
}

/**
 * Verify a SIWE signature
 *
 * @param message - SIWE message string
 * @param signature - Ethereum signature (hex string)
 * @param expectedAddress - Optional expected signer address
 * @returns Verification result
 *
 * @example
 * import { verifySiweSignature } from 'w3pk/siwe'
 *
 * const result = await verifySiweSignature(
 *   message,
 *   signature,
 *   '0x1234...5678'
 * )
 *
 * if (result.valid) {
 *   console.log('Signature valid, signed by:', result.address)
 * }
 */
export async function verifySiweSignature(
  message: string,
  signature: string,
  expectedAddress?: string
): Promise<{
  valid: boolean;
  address?: string;
  error?: string;
}> {
  try {
    const { verifyMessage } = await import('ethers');

    // Recover address from signature
    const recoveredAddress = verifyMessage(message, signature);

    // Parse message to get claimed address
    const parsed = parseSiweMessage(message);

    // Verify recovered address matches claimed address in message
    if (recoveredAddress.toLowerCase() !== parsed.address.toLowerCase()) {
      return {
        valid: false,
        error: 'Signature does not match address in message',
      };
    }

    // If expected address provided, verify it matches
    if (expectedAddress && recoveredAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
      return {
        valid: false,
        error: 'Signature does not match expected address',
      };
    }

    return {
      valid: true,
      address: recoveredAddress,
    };
  } catch (error) {
    return {
      valid: false,
      error: (error as Error).message,
    };
  }
}
