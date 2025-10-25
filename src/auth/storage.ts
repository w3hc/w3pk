import { StorageError } from "../core/errors";

const STORAGE_KEY_PREFIX = "w3pk_credential_";
const STORAGE_INDEX_KEY = "w3pk_credential_index";

export interface StoredCredential {
  id: string;
  publicKey: string;
  username: string;
  ethereumAddress: string;
  userId: string;
  createdAt: number;
  lastUsed: number;
}

export class CredentialStorage {
  private storage: Storage;

  constructor(storage?: Storage) {
    if (storage) {
      this.storage = storage;
    } else if (typeof window !== "undefined" && window.localStorage) {
      this.storage = window.localStorage;
    } else {
      throw new StorageError("localStorage is not available");
    }
  }

  saveCredential(credential: StoredCredential): void {
    try {
      const key = `${STORAGE_KEY_PREFIX}${credential.id}`;
      this.storage.setItem(key, JSON.stringify(credential));
      this.addToIndex(credential.id);
    } catch (error) {
      throw new StorageError("Failed to save credential", error);
    }
  }

  getCredentialById(id: string): StoredCredential | null {
    try {
      const key = `${STORAGE_KEY_PREFIX}${id}`;
      const data = this.storage.getItem(key);
      if (!data) {
        return null;
      }
      return JSON.parse(data) as StoredCredential;
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  getCredentialByUsername(username: string): StoredCredential | null {
    try {
      const credentials = this.getAllCredentials();
      return credentials.find((c) => c.username === username) || null;
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  getCredentialByAddress(address: string): StoredCredential | null {
    try {
      const credentials = this.getAllCredentials();
      return (
        credentials.find(
          (c) => c.ethereumAddress.toLowerCase() === address.toLowerCase()
        ) || null
      );
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  getAllCredentials(): StoredCredential[] {
    try {
      const index = this.getIndex();
      return index
        .map((id) => this.getCredentialById(id))
        .filter((c): c is StoredCredential => c !== null);
    } catch (error) {
      throw new StorageError("Failed to retrieve credentials", error);
    }
  }

  userExists(username: string): boolean {
    return this.getCredentialByUsername(username) !== null;
  }

  updateLastUsed(id: string): void {
    try {
      const credential = this.getCredentialById(id);
      if (credential) {
        credential.lastUsed = Date.now();
        this.saveCredential(credential);
      }
    } catch (error) {
      throw new StorageError("Failed to update timestamp", error);
    }
  }

  deleteCredential(id: string): void {
    try {
      const key = `${STORAGE_KEY_PREFIX}${id}`;
      this.storage.removeItem(key);
      this.removeFromIndex(id);
    } catch (error) {
      throw new StorageError("Failed to delete credential", error);
    }
  }

  clearAll(): void {
    try {
      const index = this.getIndex();
      index.forEach((id) => {
        const key = `${STORAGE_KEY_PREFIX}${id}`;
        this.storage.removeItem(key);
      });
      this.storage.removeItem(STORAGE_INDEX_KEY);
    } catch (error) {
      throw new StorageError("Failed to clear credentials", error);
    }
  }

  private getIndex(): string[] {
    try {
      const data = this.storage.getItem(STORAGE_INDEX_KEY);
      return data ? JSON.parse(data) : [];
    } catch (error) {
      return [];
    }
  }

  private addToIndex(id: string): void {
    const index = this.getIndex();
    if (!index.includes(id)) {
      index.push(id);
      this.storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(index));
    }
  }

  private removeFromIndex(id: string): void {
    const index = this.getIndex();
    const filtered = index.filter((credId) => credId !== id);
    this.storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(filtered));
  }
}
