/**
 * localStorage storage for encrypted wallet data
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
        KEY_PREFIX + data.ethereumAddress,
        JSON.stringify(data)
      );
    } catch (error) {
      throw new StorageError("Failed to store wallet data", error);
    }
  }

  async retrieve(ethereumAddress: string): Promise<EncryptedWalletData | null> {
    try {
      const raw = this.storage.getItem(KEY_PREFIX + ethereumAddress);
      return raw ? (JSON.parse(raw) as EncryptedWalletData) : null;
    } catch (error) {
      throw new StorageError("Failed to retrieve wallet data", error);
    }
  }

  async delete(ethereumAddress: string): Promise<void> {
    try {
      this.storage.removeItem(KEY_PREFIX + ethereumAddress);
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
