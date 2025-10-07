/**
 * IndexedDB storage for encrypted wallet data
 */

import { StorageError } from "../core/errors";
import type { EncryptedWalletData, WalletStorage } from "./types";

const DB_NAME = "Web3PasskeyWallet";
const DB_VERSION = 1;
const STORE_NAME = "wallets";

export class IndexedDBWalletStorage implements WalletStorage {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onerror = () =>
        reject(new StorageError("Failed to open database", request.error));

      request.onsuccess = () => {
        this.db = request.result;
        resolve();
      };

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "ethereumAddress" });
        }
      };
    });
  }

  async store(data: EncryptedWalletData): Promise<void> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.put(data);
      request.onerror = () =>
        reject(new StorageError("Failed to store wallet data", request.error));
      request.onsuccess = () => resolve();
    });
  }

  async retrieve(ethereumAddress: string): Promise<EncryptedWalletData | null> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readonly");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.get(ethereumAddress);
      request.onerror = () =>
        reject(
          new StorageError("Failed to retrieve wallet data", request.error)
        );
      request.onsuccess = () => resolve(request.result || null);
    });
  }

  async delete(ethereumAddress: string): Promise<void> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.delete(ethereumAddress);
      request.onerror = () =>
        reject(new StorageError("Failed to delete wallet data", request.error));
      request.onsuccess = () => resolve();
    });
  }

  async clear(): Promise<void> {
    if (!this.db) await this.init();

    return new Promise((resolve, reject) => {
      const transaction = this.db!.transaction([STORE_NAME], "readwrite");
      const store = transaction.objectStore(STORE_NAME);

      const request = store.clear();
      request.onerror = () =>
        reject(new StorageError("Failed to clear wallet data", request.error));
      request.onsuccess = () => resolve();
    });
  }
}
