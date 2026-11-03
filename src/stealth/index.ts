/**
 * ERC-5564 Stealth Address Module for w3pk SDK
 * Provides privacy-preserving stealth address generation capabilities
 * following the ERC-5564 standard
 *
 * SECURITY NOTE:
 * - Stealth addresses use SEPARATE derivation paths from the main wallet
 * - Viewing key: m/44'/60'/1'/0/0 (for scanning announcements)
 * - Spending key: m/44'/60'/1'/0/1 (for spending stealth funds)
 * - Applications that opt-in to stealth addresses get the viewing key, never the
 *   spending key or the private key of a stealth address; w3pk signs from
 *   stealth addresses itself
 * - Stealth keys are NOT derived from the main wallet's MAIN tag
 * - Stealth keys are shared across origins: every app gets the same meta-address
 * - This module is OPT-IN only (must explicitly enable in SDK config)
 *
 * @see https://eips.ethereum.org/EIPS/eip-5564
 */

import { ethers } from "ethers";
import { Web3PasskeyError } from "../core/errors";
import {
  deriveStealthKeys,
  generateStealthAddress as generateERC5564StealthAddress,
  checkStealthAddress,
  computeStealthPrivateKey,
} from "./crypto";
import type { StealthKeys } from "./crypto";

export interface StealthAddressConfig {
  // Network-agnostic - no provider needed
}

/**
 * ERC-5564 Stealth Address Generation Result
 */
export interface StealthAddressResult {
  /** The generated stealth address where funds should be sent */
  stealthAddress: string;
  /** Ephemeral public key (to be published on-chain) */
  ephemeralPublicKey: string;
  /** View tag (1 byte) for efficient scanning */
  viewTag: string;
}

/**
 * ERC-5564 Announcement (what gets published on-chain)
 */
export interface Announcement {
  /** The stealth address that received funds */
  stealthAddress: string;
  /** Ephemeral public key used for generation */
  ephemeralPublicKey: string;
  /** View tag for efficient filtering */
  viewTag: string;
}

/**
 * Result of parsing/checking announcements
 */
export interface ParseAnnouncementResult {
  /** Whether this announcement is for the user */
  isForUser: boolean;
  /** The stealth address (only if isForUser is true) */
  stealthAddress?: string;
}

/**
 * EIP-1559 transaction to sign from a stealth address
 */
export interface StealthTransaction {
  to: string;
  value?: bigint;
  data?: string;
  chainId: number;
  nonce: number;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/**
 * ERC-5564 Stealth Address Module
 * Integrates with w3pk WebAuthn for seamless privacy-preserving stealth address generation
 *
 * SECURITY IMPLICATIONS:
 * By using this module, applications will have access to:
 * - Stealth meta-address (safe to share publicly)
 * - Viewing private key (required for scanning announcements)
 * - Transactions signed from stealth addresses with `signTransaction()`, each
 *   after a fresh passkey assertion
 *
 * The spending key and stealth private keys never leave the SDK: a stealth
 * private key plus the viewing key would give back the spending key (stealth
 * key = spending key + hash of the shared secret). The viewing key lets an app
 * see every stealth payment to the user, and an app with this module enabled
 * can ask w3pk to sign from a stealth address, which prompts for the passkey
 * every time. Stealth keys are derived from separate HD paths (not from main wallet)
 * and are the same for every origin, so any app that enables this module sees
 * the same viewing key and meta-address; scoping them per origin would change
 * the meta-address and strand funds already sent to it.
 */
export class StealthAddressModule {
  private getMnemonic: (requireAuth?: boolean) => Promise<string>;

  constructor(_config: StealthAddressConfig, getMnemonic: (requireAuth?: boolean) => Promise<string>) {
    this.getMnemonic = getMnemonic;
  }

  // ========================================
  // ERC-5564 Stealth Address Generation
  // ========================================

  /**
   * Generate a fresh ERC-5564 compliant stealth address
   * This is the sender's operation - generates a one-time address for the recipient
   *
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   * @returns Stealth address, ephemeral public key, and view tag (to be published on-chain)
   */
  async generateStealthAddress(options?: { requireAuth?: boolean }): Promise<StealthAddressResult> {
    try {
      // Get mnemonic from session (or authenticate if needed/forced)
      const mnemonic = await this.getMnemonic(options?.requireAuth);

      const stealthKeys = deriveStealthKeys(mnemonic);
      const stealthResult = generateERC5564StealthAddress(stealthKeys.stealthMetaAddress);

      return {
        stealthAddress: stealthResult.stealthAddress,
        ephemeralPublicKey: stealthResult.ephemeralPubKey,
        viewTag: stealthResult.viewTag,
      };
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to generate stealth address",
        "STEALTH_GENERATION_ERROR",
        error
      );
    }
  }

  /**
   * Parse an ERC-5564 announcement to check if it's for the user
   * Uses view tag optimization for efficient scanning (255/256 skip rate)
   *
   * @param announcement - The announcement to parse (from on-chain event)
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   * @returns ParseResult indicating if announcement is for user, plus the stealth address if true
   */
  async parseAnnouncement(announcement: Announcement, options?: { requireAuth?: boolean }): Promise<ParseAnnouncementResult> {
    try {
      // Get mnemonic from session (or authenticate if needed/forced)
      const mnemonic = await this.getMnemonic(options?.requireAuth);

      const parseResult = checkAnnouncement(deriveStealthKeys(mnemonic), announcement);

      if (!parseResult.isForUser) {
        return { isForUser: false };
      }

      return {
        isForUser: true,
        stealthAddress: parseResult.stealthAddress,
      };
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to parse announcement",
        "ANNOUNCEMENT_PARSE_ERROR",
        error
      );
    }
  }

  /**
   * Scan multiple announcements efficiently using view tags
   * Returns only the announcements that belong to the user
   *
   * @param announcements - Array of announcements to scan
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   * @returns Array of announcements that belong to the user
   */
  async scanAnnouncements(announcements: Announcement[], options?: { requireAuth?: boolean }): Promise<ParseAnnouncementResult[]> {
    const results: ParseAnnouncementResult[] = [];

    for (const announcement of announcements) {
      const result = await this.parseAnnouncement(announcement, options);
      if (result.isForUser) {
        results.push(result);
      }
    }

    return results;
  }

  /**
   * Sign an EIP-1559 transaction from a stealth address found for the user
   * The stealth private key is derived and used inside the SDK, never returned.
   * Every call runs a fresh passkey assertion, even with an active session.
   * The transaction is signed, not sent: broadcast it with your own RPC
   * (`eth_sendRawTransaction`).
   *
   * @param announcement - The announcement of the stealth address to sign from
   * @param tx - Fully populated transaction (nonce, gas limit and fees included)
   * @returns The serialized signed transaction
   */
  async signTransaction(announcement: Announcement, tx: StealthTransaction): Promise<string> {
    try {
      const mnemonic = await this.getMnemonic(true);

      const stealthKeys = deriveStealthKeys(mnemonic);

      if (!checkAnnouncement(stealthKeys, announcement).isForUser) {
        throw new Error("Announcement is not for this user");
      }

      const wallet = new ethers.Wallet(
        computeStealthPrivateKey(
          stealthKeys.viewingKey,
          stealthKeys.spendingKey,
          announcement.ephemeralPublicKey
        )
      );

      return await wallet.signTransaction({
        type: 2,
        to: tx.to,
        value: tx.value,
        data: tx.data ?? "0x",
        chainId: tx.chainId,
        nonce: tx.nonce,
        gasLimit: tx.gasLimit,
        maxFeePerGas: tx.maxFeePerGas,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
      });
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to sign stealth transaction",
        "STEALTH_SIGN_ERROR",
        error
      );
    }
  }

  // ========================================
  // Privacy & Key Management
  // ========================================

  /**
   * Get ERC-5564 stealth keys
   * Returns the stealth meta-address, both public keys and the viewing key;
   * the spending private key is never returned. The keys are the same for
   * every origin.
   *
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   */
  async getKeys(options?: { requireAuth?: boolean }): Promise<Omit<StealthKeys, "spendingKey">> {
    try {
      // Get mnemonic from session (or authenticate if needed/forced)
      const mnemonic = await this.getMnemonic(options?.requireAuth);

      const { stealthMetaAddress, spendingPubKey, viewingPubKey, viewingKey } =
        deriveStealthKeys(mnemonic);
      return { stealthMetaAddress, spendingPubKey, viewingPubKey, viewingKey };
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to get stealth keys",
        "STEALTH_KEYS_ERROR",
        error
      );
    }
  }

  /**
   * Get the stealth meta-address for receiving funds
   * This is what you share publicly for others to send you stealth payments
   *
   * @param options - Optional configuration
   * @param options.requireAuth - If true, force fresh authentication even if session is active
   * @returns The ERC-5564 stealth meta-address (66 bytes)
   */
  async getStealthMetaAddress(options?: { requireAuth?: boolean }): Promise<string> {
    try {
      const keys = await this.getKeys(options);
      return keys.stealthMetaAddress;
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to get stealth meta-address",
        "STEALTH_META_ADDRESS_ERROR",
        error
      );
    }
  }

  // ========================================
  // Status & Management
  // ========================================

  /**
   * Check if stealth addresses are available (always true if properly configured)
   */
  get isAvailable(): boolean {
    return true;
  }
}

function checkAnnouncement(stealthKeys: StealthKeys, announcement: Announcement) {
  return checkStealthAddress(
    stealthKeys.viewingKey,
    stealthKeys.spendingPubKey,
    announcement.ephemeralPublicKey,
    announcement.stealthAddress,
    announcement.viewTag
  );
}

// Export types for stealth module
export type { StealthKeys };