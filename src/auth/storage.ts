import { StorageError } from "../core/errors";

const STORAGE_KEY_PREFIX = "w3pk_credential_";
const STORAGE_INDEX_KEY = "w3pk_credential_index";

export interface StoredCredential {
  id: string;
  publicKey: string;
  username: string;
  ethereumAddress: string;
  createdAt: string;
  lastUsed: string;
  signCount?: number; // Signature counter for authenticator cloning detection
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

  /**
   * Saves a credential. Username and address are stored in plain text:
   * any script on the page can read them
   */
  async saveCredential(credential: StoredCredential): Promise<void> {
    try {
      this.storage.setItem(STORAGE_KEY_PREFIX + credential.id, JSON.stringify(credential));
      await this.addToIndex(credential.id);
    } catch (error) {
      throw new StorageError("Failed to save credential", error);
    }
  }

  /**
   * Retrieves a credential by ID. A record in another format is treated as
   * absent
   */
  async getCredentialById(id: string): Promise<StoredCredential | null> {
    try {
      const data = this.storage.getItem(STORAGE_KEY_PREFIX + id);
      if (!data) return null;
      const credential = JSON.parse(data) as Partial<StoredCredential> | null;
      if (
        credential?.id !== id ||
        typeof credential.publicKey !== "string" ||
        typeof credential.username !== "string" ||
        typeof credential.ethereumAddress !== "string"
      ) {
        return null;
      }
      return credential as StoredCredential;
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  /**
   * Searches for credential by username
   */
  async getCredentialByUsername(
    username: string
  ): Promise<StoredCredential | null> {
    try {
      const credentials = await this.getAllCredentials();
      return credentials.find((c) => c.username === username) || null;
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  /**
   * Searches for credential by Ethereum address
   */
  async getCredentialByAddress(
    address: string
  ): Promise<StoredCredential | null> {
    try {
      const credentials = await this.getAllCredentials();
      return (
        credentials.find(
          (c) => c.ethereumAddress.toLowerCase() === address.toLowerCase()
        ) || null
      );
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  /**
   * Retrieves all credentials
   */
  async getAllCredentials(): Promise<StoredCredential[]> {
    try {
      const index = await this.getIndex();
      const credentials = await Promise.all(
        index.map(async (id) => await this.getCredentialById(id))
      );
      return credentials.filter((c): c is StoredCredential => c !== null);
    } catch (error) {
      throw new StorageError("Failed to retrieve credentials", error);
    }
  }

  /**
   * Checks if a user exists by username
   */
  async userExists(username: string): Promise<boolean> {
    const credential = await this.getCredentialByUsername(username);
    return credential !== null;
  }

  /**
   * Updates the last used timestamp for a credential
   */
  async updateLastUsed(id: string): Promise<void> {
    try {
      const credential = await this.getCredentialById(id);
      if (credential) {
        credential.lastUsed = new Date().toISOString();
        await this.saveCredential(credential);
      }
    } catch (error) {
      throw new StorageError("Failed to update timestamp", error);
    }
  }

  /**
   * Updates the signature counter for a credential
   * Used to detect authenticator cloning attempts
   */
  async updateSignatureCounter(id: string, signCount: number): Promise<void> {
    try {
      const credential = await this.getCredentialById(id);
      if (credential) {
        credential.signCount = signCount;
        credential.lastUsed = new Date().toISOString();
        await this.saveCredential(credential);
      }
    } catch (error) {
      throw new StorageError("Failed to update signature counter", error);
    }
  }

  /**
   * Updates the Ethereum address for a credential
   * Used when restoring from backup to overwrite with new address
   */
  async updateCredentialAddress(id: string, newAddress: string): Promise<void> {
    try {
      const credential = await this.getCredentialById(id);
      if (credential) {
        credential.ethereumAddress = newAddress;
        credential.lastUsed = new Date().toISOString();
        await this.saveCredential(credential);
      }
    } catch (error) {
      throw new StorageError("Failed to update credential address", error);
    }
  }

  /**
   * Deletes a credential by ID
   */
  async deleteCredential(id: string): Promise<void> {
    try {
      this.storage.removeItem(STORAGE_KEY_PREFIX + id);
      await this.removeFromIndex(id);
    } catch (error) {
      throw new StorageError("Failed to delete credential", error);
    }
  }

  /**
   * Clears all credentials from storage
   */
  async clearAll(): Promise<void> {
    try {
      for (const id of await this.getIndex()) {
        this.storage.removeItem(STORAGE_KEY_PREFIX + id);
      }
      this.storage.removeItem(STORAGE_INDEX_KEY);
    } catch (error) {
      throw new StorageError("Failed to clear credentials", error);
    }
  }

  /**
   * Gets the credential index, the IDs of the stored credentials
   */
  private async getIndex(): Promise<string[]> {
    try {
      const data = this.storage.getItem(STORAGE_INDEX_KEY);
      return data ? JSON.parse(data) : [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Adds credential to index
   */
  private async addToIndex(id: string): Promise<void> {
    const index = await this.getIndex();
    if (!index.includes(id)) {
      index.push(id);
      this.storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(index));
    }
  }

  /**
   * Removes credential from index
   */
  private async removeFromIndex(id: string): Promise<void> {
    const index = await this.getIndex();
    const filtered = index.filter((credId) => credId !== id);
    this.storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(filtered));
  }
}
