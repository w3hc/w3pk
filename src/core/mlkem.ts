import type { SecurityMode } from "../types";
import { getOriginSpecificAddress, getCurrentOrigin, DEFAULT_TAG } from "../wallet/origin-derivation";
import { MLKEM_DEFAULT_CONTEXT, type EncryptedPayload } from "../crypto/mlkem";
import { WalletError } from "./errors";
import type { SdkContext } from "./context";

type MlkemContext = Pick<SdkContext, 'currentUser' | 'getMnemonicFromSession'>;

export async function deriveMLKemPublicKey(ctx: MlkemContext, options?: {
  context?: string;
  mode?: SecurityMode;
  tag?: string;
  requireAuth?: boolean;
}): Promise<string> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to derive ML-KEM public key");
  }

  const { deriveMLKemKeypair } = await import("../crypto/mlkem");
  const { Wallet } = await import("ethers");

  const effectiveMode = options?.mode || 'STANDARD';
  const effectiveTag = options?.tag || DEFAULT_TAG;
  const origin = getCurrentOrigin();
  const context = options?.context || MLKEM_DEFAULT_CONTEXT;
  const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

  // PRIMARY mode uses P-256 WebAuthn keys, not Ethereum keys
  // ML-KEM derivation requires an Ethereum private key
  if (effectiveMode === 'PRIMARY') {
    throw new WalletError(
      "ML-KEM encryption is not supported in PRIMARY mode. " +
      "PRIMARY mode uses P-256 WebAuthn keys which cannot derive ML-KEM keypairs. " +
      "Use STANDARD, STRICT, or YOLO mode instead."
    );
  }

  const mnemonic = await ctx.getMnemonicFromSession(requireAuth, effectiveMode);
  const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

  let privateKey: string;
  if (derived.privateKey) {
    // YOLO mode: private key is directly available
    privateKey = derived.privateKey;
  } else {
    // STANDARD/STRICT modes: derive from mnemonic
    const { deriveWalletFromMnemonic } = await import("../wallet/generate");
    const wallet = deriveWalletFromMnemonic(mnemonic, derived.index);
    privateKey = wallet.privateKey;
  }

  const keypair = await deriveMLKemKeypair(privateKey, context);

  // Convert to base64 for easy sharing
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(keypair.publicKey).toString('base64');
  } else {
    // Browser fallback
    return btoa(String.fromCharCode(...Array.from(keypair.publicKey)));
  }
}

export async function mlkemEncrypt(
  ctx: MlkemContext,
  plaintext: string,
  recipientPublicKeys: Array<string | Uint8Array>,
  options?: {
    context?: string;
    mode?: SecurityMode;
    tag?: string;
    requireAuth?: boolean;
  }
): Promise<EncryptedPayload> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to encrypt data");
  }

  const { mlkemEncryptWithKey } = await import("../crypto/mlkem");

  const effectiveMode = options?.mode || 'STANDARD';
  const effectiveTag = options?.tag || DEFAULT_TAG;
  const origin = getCurrentOrigin();
  const context = options?.context || MLKEM_DEFAULT_CONTEXT;
  const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

  if (effectiveMode === 'PRIMARY') {
    throw new WalletError(
      "ML-KEM encryption is not supported in PRIMARY mode. " +
      "Use STANDARD, STRICT, or YOLO mode instead."
    );
  }

  const mnemonic = await ctx.getMnemonicFromSession(requireAuth, effectiveMode);
  const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

  let privateKey: string;
  if (derived.privateKey) {
    // YOLO mode: private key is directly available
    privateKey = derived.privateKey;
  } else {
    // STANDARD/STRICT modes: derive from mnemonic
    const { deriveWalletFromMnemonic } = await import("../wallet/generate");
    const wallet = deriveWalletFromMnemonic(mnemonic, derived.index);
    privateKey = wallet.privateKey;
  }

  return await mlkemEncryptWithKey(
    plaintext,
    privateKey,
    recipientPublicKeys,
    context
  );
}

export async function mlkemDecrypt(
  ctx: MlkemContext,
  payload: EncryptedPayload,
  options?: {
    context?: string;
    mode?: SecurityMode;
    tag?: string;
    requireAuth?: boolean;
  }
): Promise<string> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to decrypt data");
  }

  const { mlkemDecryptWithKey } = await import("../crypto/mlkem");

  const effectiveMode = options?.mode || 'STANDARD';
  const effectiveTag = options?.tag || DEFAULT_TAG;
  const origin = getCurrentOrigin();
  const context = options?.context || MLKEM_DEFAULT_CONTEXT;
  const requireAuth = effectiveMode === 'STRICT' ? true : (options?.requireAuth || false);

  if (effectiveMode === 'PRIMARY') {
    throw new WalletError(
      "ML-KEM encryption is not supported in PRIMARY mode. " +
      "Use STANDARD, STRICT, or YOLO mode instead."
    );
  }

  const mnemonic = await ctx.getMnemonicFromSession(requireAuth, effectiveMode);
  const derived = await getOriginSpecificAddress(mnemonic, origin, effectiveMode, effectiveTag);

  let privateKey: string;
  if (derived.privateKey) {
    // YOLO mode: private key is directly available
    privateKey = derived.privateKey;
  } else {
    // STANDARD/STRICT modes: derive from mnemonic
    const { deriveWalletFromMnemonic } = await import("../wallet/generate");
    const wallet = deriveWalletFromMnemonic(mnemonic, derived.index);
    privateKey = wallet.privateKey;
  }

  return await mlkemDecryptWithKey(payload, privateKey, context);
}
