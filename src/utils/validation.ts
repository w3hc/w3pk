/**
 * Input validation utilities
 */

export function validateEthereumAddress(address: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(address);
}

export function validateUsername(username: string): boolean {
  return username.length >= 3 && username.length <= 50;
}

export function validateMnemonic(mnemonic: string): boolean {
  const words = mnemonic.trim().split(/\s+/);
  return words.length === 12 || words.length === 24;
}

export function assertEthereumAddress(address: string): void {
  if (!validateEthereumAddress(address)) {
    throw new Error("Invalid Ethereum address format");
  }
}

export function assertUsername(username: string): void {
  if (!validateUsername(username)) {
    throw new Error("Username must be between 3 and 50 characters");
  }
}

export function assertMnemonic(mnemonic: string): void {
  if (!validateMnemonic(mnemonic)) {
    throw new Error("Invalid mnemonic: must be 12 or 24 words");
  }
}
