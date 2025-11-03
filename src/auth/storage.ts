import { StorageError } from "../core/errors";
import {
  encryptMetadata,
  decryptMetadata,
  hashCredentialId,
  hashPublicKey,
} from "../wallet/crypto";

const STORAGE_KEY_PREFIX = "w3pk_credential_";
const STORAGE_INDEX_KEY = "w3pk_credential_index";

export interface StoredCredential {
  id: string;
  publicKey: string;
  username: string;
  ethereumAddress: string;
  createdAt: number;
  lastUsed: number;
}

/**
 * Encrypted credential stored in localStorage
 * Prevents XSS attacks from correlating usernames to Ethereum addresses
 */
export interface EncryptedCredential {
  id: string; // Hashed credential ID
  encryptedUsername: string; // AES-GCM encrypted
  encryptedAddress: string; // AES-GCM encrypted
  publicKey: string; // Public key (needed for encryption key derivation)
  publicKeyFingerprint: string; // SHA-256 hash for verification
  createdAt: number;
  lastUsed: number;
}

/**
 * Derives a metadata encryption key from credential ID
 * Used to encrypt username and address fields in localStorage
 */
async function deriveMetadataKey(credentialId: string): Promise<CryptoKey> {
  const keyMaterial = new TextEncoder().encode(
    `w3pk-metadata-v1:${credentialId}`
  );
  const hash = await crypto.subtle.digest("SHA-256", keyMaterial);

  const importedKey = await crypto.subtle.importKey(
    "raw",
    hash,
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode("w3pk-metadata-salt-v1"),
      iterations: 100000,
      hash: "SHA-256",
    },
    importedKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
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
   * Saves credential with encrypted metadata
   * Username and address are encrypted to prevent XSS correlation attacks
   */
  async saveCredential(credential: StoredCredential): Promise<void> {
    try {
      const metadataKey = await deriveMetadataKey(credential.id);
      const hashedId = await hashCredentialId(credential.id);

      const encryptedData: EncryptedCredential = {
        id: hashedId,
        encryptedUsername: await encryptMetadata(
          credential.username,
          metadataKey
        ),
        encryptedAddress: await encryptMetadata(
          credential.ethereumAddress,
          metadataKey
        ),
        publicKey: credential.publicKey, // Store public key (needed for key derivation)
        publicKeyFingerprint: await hashPublicKey(credential.publicKey),
        createdAt: credential.createdAt,
        lastUsed: credential.lastUsed,
      };

      const key = `${STORAGE_KEY_PREFIX}${hashedId}`;
      this.storage.setItem(key, JSON.stringify(encryptedData));
      await this.addToIndex(credential.id);
    } catch (error) {
      throw new StorageError("Failed to save credential", error);
    }
  }

  /**
   * Retrieves and decrypts credential by original ID
   */
  async getCredentialById(id: string): Promise<StoredCredential | null> {
    try {
      const hashedId = await hashCredentialId(id);
      const key = `${STORAGE_KEY_PREFIX}${hashedId}`;
      const data = this.storage.getItem(key);
      if (!data) {
        return null;
      }

      const encrypted = JSON.parse(data) as EncryptedCredential;
      const metadataKey = await deriveMetadataKey(id);

      return {
        id,
        publicKey: encrypted.publicKey, // Return the stored public key
        username: await decryptMetadata(encrypted.encryptedUsername, metadataKey),
        ethereumAddress: await decryptMetadata(
          encrypted.encryptedAddress,
          metadataKey
        ),
        createdAt: encrypted.createdAt,
        lastUsed: encrypted.lastUsed,
      };
    } catch (error) {
      throw new StorageError("Failed to retrieve credential", error);
    }
  }

  /**
   * Searches for credential by username
   * WARNING: Requires decrypting all credentials (O(n) operation)
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
   * WARNING: Requires decrypting all credentials (O(n) operation)
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
   * Retrieves and decrypts all credentials
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
        credential.lastUsed = Date.now();
        await this.saveCredential(credential);
      }
    } catch (error) {
      throw new StorageError("Failed to update timestamp", error);
    }
  }

  /**
   * Deletes a credential by original ID
   */
  async deleteCredential(id: string): Promise<void> {
    try {
      const hashedId = await hashCredentialId(id);
      const key = `${STORAGE_KEY_PREFIX}${hashedId}`;
      this.storage.removeItem(key);
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
      const index = await this.getIndex();
      const hashedIds = await Promise.all(
        index.map(async (id) => await hashCredentialId(id))
      );
      hashedIds.forEach((hashedId) => {
        const key = `${STORAGE_KEY_PREFIX}${hashedId}`;
        this.storage.removeItem(key);
      });
      this.storage.removeItem(STORAGE_INDEX_KEY);
    } catch (error) {
      throw new StorageError("Failed to clear credentials", error);
    }
  }

  /**
   * Gets the credential index (stores original IDs, not hashed)
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
