/**
 * SIWE (Sign-In with Ethereum) Utilities
 * EIP-4361 compliant message construction and validation
 *
 * Reference: https://docs.login.xyz/general-information/siwe-overview/eip-4361
 */

/**
 * SIWE message parameters (EIP-4361)
 */
export interface SiweMessage {
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
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);

  return Array.from(randomValues)
    .map(x => chars[x % chars.length])
    .join('');
}

/**
 * Create a properly formatted SIWE message according to EIP-4361
 *
 * @param params - SIWE message parameters
 * @returns EIP-4361 compliant message string
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

  // Validate statement (no newlines)
  if (params.statement && params.statement.includes('\n')) {
    throw new Error('Statement cannot contain newlines');
  }

  // Build message according to EIP-4361 ABNF spec
  let message = `${params.domain} wants you to sign in with your Ethereum account:\n`;
  message += `${params.address}\n`;
  message += `\n`;

  if (params.statement) {
    message += `${params.statement}\n`;
    message += `\n`;
  }

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

  return message;
}

/**
 * Parse a SIWE message string into structured data
 *
 * @param message - EIP-4361 formatted SIWE message
 * @returns Parsed SIWE message object
 * @throws Error if message format is invalid
 *
 * @example
 * const parsed = parseSiweMessage(signedMessage)
 * console.log('Domain:', parsed.domain)
 * console.log('Address:', parsed.address)
 * console.log('Nonce:', parsed.nonce)
 */
export function parseSiweMessage(message: string): SiweMessage {
  const lines = message.split('\n');

  // Parse header (domain + address)
  if (lines.length < 7) {
    throw new Error('Invalid SIWE message: too few lines');
  }

  const domainLine = lines[0];
  const domainMatch = domainLine.match(/^(.+) wants you to sign in with your Ethereum account:$/);
  if (!domainMatch) {
    throw new Error('Invalid SIWE message: malformed domain line');
  }
  const domain = domainMatch[1];

  const address = lines[1];
  if (!address.match(/^0x[a-fA-F0-9]{40}$/)) {
    throw new Error('Invalid SIWE message: malformed address');
  }

  // Line 2 should be empty
  if (lines[2] !== '') {
    throw new Error('Invalid SIWE message: expected empty line after address');
  }

  // Find required fields
  let statement: string | undefined;
  let uri = '';
  let version = '';
  let chainId = 0;
  let nonce = '';
  let issuedAt = '';
  let expirationTime: string | undefined;
  let notBefore: string | undefined;
  let requestId: string | undefined;
  const resources: string[] = [];

  let i = 3;

  // Check for optional statement
  if (lines[i] && !lines[i].startsWith('URI: ')) {
    statement = lines[i];
    i++;

    // Skip empty line after statement
    if (lines[i] === '') {
      i++;
    }
  }

  // Parse required fields
  for (; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('URI: ')) {
      uri = line.substring(5);
    } else if (line.startsWith('Version: ')) {
      version = line.substring(9);
    } else if (line.startsWith('Chain ID: ')) {
      chainId = parseInt(line.substring(10), 10);
    } else if (line.startsWith('Nonce: ')) {
      nonce = line.substring(7);
    } else if (line.startsWith('Issued At: ')) {
      issuedAt = line.substring(11);
    } else if (line.startsWith('Expiration Time: ')) {
      expirationTime = line.substring(17);
    } else if (line.startsWith('Not Before: ')) {
      notBefore = line.substring(12);
    } else if (line.startsWith('Request ID: ')) {
      requestId = line.substring(12);
    } else if (line.startsWith('Resources:')) {
      // Parse resources list
      i++;
      while (i < lines.length && lines[i].startsWith('- ')) {
        resources.push(lines[i].substring(2));
        i++;
      }
      break;
    }
  }

  // Validate required fields
  if (!uri || !version || !chainId || !nonce || !issuedAt) {
    throw new Error('Invalid SIWE message: missing required fields');
  }

  return {
    domain,
    address,
    statement,
    uri,
    version,
    chainId,
    nonce,
    issuedAt,
    expirationTime,
    notBefore,
    requestId,
    resources: resources.length > 0 ? resources : undefined,
  };
}

/**
 * Validate a SIWE message for correctness and expiration
 *
 * @param message - SIWE message string or parsed object
 * @param options - Validation options
 * @returns Validation result with details
 *
 * @example
 * const validation = validateSiweMessage(message, {
 *   domain: 'example.com',
 *   checkExpiration: true
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
    /** Check expiration time */
    checkExpiration?: boolean;
    /** Check not-before time */
    checkNotBefore?: boolean;
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

    // Check expiration
    if (options?.checkExpiration && parsed.expirationTime) {
      const expirationDate = new Date(parsed.expirationTime);
      if (expirationDate < new Date()) {
        errors.push('Message has expired');
      }
    }

    // Check not-before
    if (options?.checkNotBefore && parsed.notBefore) {
      const notBeforeDate = new Date(parsed.notBefore);
      if (notBeforeDate > new Date()) {
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
