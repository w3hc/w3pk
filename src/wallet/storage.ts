/**
 * localStorage storage for encrypted wallet data, one record per passkey
 * under `w3pk_wallet_<credentialId>`: passkeys of the same wallet each keep
 * the mnemonic encrypted under their own PRF output
 *
 * Lives next to the credential metadata so browser eviction removes both or
 * neither: a credential is never left without its wallet.
 */

import { StorageError } from "../core/errors";
import type { EncryptedWalletData, WalletStorage } from "./types";

const KEY_PREFIX = "w3pk_wallet_";

export class LocalStorageWalletStorage implements WalletStorage {
  constructor(private readonly customStorage?: Storage) {}

  private get storage(): Storage {
    if (this.customStorage) return this.customStorage;
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage;
    }
    throw new StorageError("localStorage is not available");
  }

  async init(): Promise<void> {}

  async store(data: EncryptedWalletData): Promise<void> {
    try {
      this.storage.setItem(
        KEY_PREFIX + data.credentialId,
        JSON.stringify(data)
      );
    } catch (error) {
      throw new StorageError("Failed to store wallet data", error);
    }
  }

  async retrieve(credentialId: string): Promise<EncryptedWalletData | null> {
    try {
      const raw = this.storage.getItem(KEY_PREFIX + credentialId);
      return raw ? (JSON.parse(raw) as EncryptedWalletData) : null;
    } catch (error) {
      throw new StorageError("Failed to retrieve wallet data", error);
    }
  }

  async delete(credentialId: string): Promise<void> {
    try {
      this.storage.removeItem(KEY_PREFIX + credentialId);
    } catch (error) {
      throw new StorageError("Failed to delete wallet data", error);
    }
  }

  async clear(): Promise<void> {
    try {
      for (const key of this.keys()) {
        this.storage.removeItem(key);
      }
    } catch (error) {
      throw new StorageError("Failed to clear wallet data", error);
    }
  }

  private keys(): string[] {
    const keys: string[] = [];
    for (let i = 0; i < this.storage.length; i++) {
      const key = this.storage.key(i);
      if (key?.startsWith(KEY_PREFIX)) keys.push(key);
    }
    return keys;
  }
}
