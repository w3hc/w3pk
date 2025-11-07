/**
 * Wallet-related types
 */

export interface WalletData {
  address: string;
  mnemonic: string;
}

export interface EncryptedWalletData {
  ethereumAddress: string;
  encryptedMnemonic: string;
  credentialId: string;
  // Challenge is NOT stored - generated fresh for each operation
  createdAt: string;
}

export interface WalletStorage {
  init(): Promise<void>;
  store(data: EncryptedWalletData): Promise<void>;
  retrieve(ethereumAddress: string): Promise<EncryptedWalletData | null>;
  delete(ethereumAddress: string): Promise<void>;
  clear(): Promise<void>;
}
