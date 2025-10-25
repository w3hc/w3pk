/**
 * ERC-5564 Stealth Address Module for w3pk SDK
 * Provides privacy-preserving stealth address generation capabilities
 * following the ERC-5564 standard
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
  type ParseResult
} from "./crypto";
import type { StealthKeys, StealthAddressResult as CryptoStealthResult } from "./crypto";

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
  /** @deprecated Legacy field - sender doesn't get the private key in ERC-5564 */
  stealthPrivateKey?: string;
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
  /** The stealth private key for spending (only if isForUser is true) */
  stealthPrivateKey?: string;
}

/**
 * ERC-5564 Stealth Address Module
 * Integrates with w3pk WebAuthn for seamless privacy-preserving stealth address generation
 */
export class StealthAddressModule {
  private getMnemonic: () => Promise<string>;

  constructor(config: StealthAddressConfig, getMnemonic: () => Promise<string>) {
    this.getMnemonic = getMnemonic;
  }

  // ========================================
  // ERC-5564 Stealth Address Generation
  // ========================================

  /**
   * Generate a fresh ERC-5564 compliant stealth address
   * This is the sender's operation - generates a one-time address for the recipient
   *
   * @returns Stealth address, ephemeral public key, and view tag (to be published on-chain)
   */
  async generateStealthAddress(): Promise<StealthAddressResult> {
    try {
      // Get mnemonic from session (or authenticate if needed)
      const mnemonic = await this.getMnemonic();

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
   * @returns ParseResult indicating if announcement is for user, plus stealth private key if true
   */
  async parseAnnouncement(announcement: Announcement): Promise<ParseAnnouncementResult> {
    try {
      // Get mnemonic from session (or authenticate if needed)
      const mnemonic = await this.getMnemonic();

      const stealthKeys = deriveStealthKeys(mnemonic);

      // Check if this announcement is for us (with view tag optimization)
      const parseResult = checkStealthAddress(
        stealthKeys.viewingKey,
        stealthKeys.spendingPubKey,
        announcement.ephemeralPublicKey,
        announcement.stealthAddress,
        announcement.viewTag
      );

      if (!parseResult.isForUser) {
        return { isForUser: false };
      }

      // Compute the stealth private key so user can spend the funds
      const stealthPrivateKey = computeStealthPrivateKey(
        stealthKeys.viewingKey,
        stealthKeys.spendingKey,
        announcement.ephemeralPublicKey
      );

      return {
        isForUser: true,
        stealthAddress: parseResult.stealthAddress,
        stealthPrivateKey,
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
   * @returns Array of announcements that belong to the user with their private keys
   */
  async scanAnnouncements(announcements: Announcement[]): Promise<ParseAnnouncementResult[]> {
    const results: ParseAnnouncementResult[] = [];

    for (const announcement of announcements) {
      const result = await this.parseAnnouncement(announcement);
      if (result.isForUser) {
        results.push(result);
      }
    }

    return results;
  }

  // ========================================
  // Privacy & Key Management
  // ========================================

  /**
   * Get ERC-5564 stealth keys
   * Returns the stealth meta-address and private keys
   */
  async getKeys(): Promise<StealthKeys> {
    try {
      // Get mnemonic from session (or authenticate if needed)
      const mnemonic = await this.getMnemonic();

      return deriveStealthKeys(mnemonic);
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
   * @returns The ERC-5564 stealth meta-address (66 bytes)
   */
  async getStealthMetaAddress(): Promise<string> {
    try {
      const keys = await this.getKeys();
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

// Export types for stealth module
export type { StealthKeys };