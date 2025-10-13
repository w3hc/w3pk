/**
 * Stealth Address Module for w3pk SDK
 * Provides privacy-preserving stealth address generation capabilities
 */

import { ethers } from "ethers";
import { Web3PasskeyError, AuthenticationError } from "../core/errors";
import { deriveStealthKeys } from "./crypto";
import type { StealthKeys } from "./crypto";

export interface StealthAddressConfig {
  // Network-agnostic - no provider needed
}

export interface StealthAddressResult {
  stealthAddress: string;
  stealthPrivateKey: string;
  ephemeralPublicKey: string;
}

/**
 * Main Stealth Address Module
 * Integrates with w3pk WebAuthn for seamless privacy-preserving stealth address generation
 */
export class StealthAddressModule {
  private config: StealthAddressConfig;
  private getMnemonic: () => Promise<string | null>;

  constructor(config: StealthAddressConfig, getMnemonic: () => Promise<string | null>) {
    this.config = config;
    this.getMnemonic = getMnemonic;
  }

  // ========================================
  // Stealth Address Generation
  // ========================================

  /**
   * Generate a fresh stealth address for privacy-preserving transactions
   * Returns the stealth address and private key for the user to handle transactions
   */
  async generateStealthAddress(): Promise<StealthAddressResult> {
    try {
      const mnemonic = await this.getMnemonic();
      if (!mnemonic) {
        throw new AuthenticationError("Not authenticated. Please login first.");
      }

      const stealthKeys = deriveStealthKeys(mnemonic);
      const { generateStealthAddress } = await import("./crypto");
      const stealthResult = generateStealthAddress(stealthKeys.metaAddress);

      return {
        stealthAddress: stealthResult.stealthAddress,
        stealthPrivateKey: stealthResult.stealthPrivkey,
        ephemeralPublicKey: stealthResult.ephemeralPubkey
      };
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to generate stealth address",
        "STEALTH_GENERATION_ERROR",
        error
      );
    }
  }


  // ========================================
  // Privacy & Key Management
  // ========================================

  /**
   * Get stealth keys for manual operations
   */
  async getKeys(): Promise<StealthKeys> {
    try {
      const mnemonic = await this.getMnemonic();
      if (!mnemonic) {
        throw new AuthenticationError("Not authenticated. Please login first.");
      }

      return deriveStealthKeys(mnemonic);
    } catch (error) {
      throw new Web3PasskeyError(
        "Failed to get stealth keys",
        "STEALTH_KEYS_ERROR",
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