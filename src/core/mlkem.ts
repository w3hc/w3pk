import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import type { SecurityMode } from "../types";
import { getCurrentOrigin, DEFAULT_TAG } from "../wallet/origin-derivation";
import type { EncryptedPayload, MLKemDerivationOptions } from "../crypto/mlkem";
import { WalletError } from "./errors";
import type { SdkContext } from "./context";

type MlkemContext = Pick<SdkContext, 'currentUser' | 'getMnemonicFromSession'>;

interface MlkemOptions {
  context?: string;
  mode?: SecurityMode;
  tag?: string;
  requireAuth?: boolean;
}

export function bip39Seed(mnemonic: string): Uint8Array {
  return pbkdf2(sha512, mnemonic.normalize("NFKD"), "mnemonic", { c: 2048, dkLen: 64 });
}

async function withSeed<T>(
  ctx: MlkemContext,
  options: MlkemOptions | undefined,
  run: (seed: Uint8Array, derivation: MLKemDerivationOptions) => Promise<T>
): Promise<T> {
  const mode = options?.mode || 'STANDARD';

  if (mode === 'PRIMARY') {
    throw new WalletError(
      "ML-KEM encryption is not supported in PRIMARY mode. " +
      "Use STANDARD, STRICT, or YOLO mode instead."
    );
  }

  const requireAuth = mode === 'STRICT' ? true : (options?.requireAuth || false);
  const derivation: MLKemDerivationOptions = {
    origin: getCurrentOrigin(),
    mode,
    tag: options?.tag || DEFAULT_TAG,
    context: options?.context,
  };

  const mnemonic = await ctx.getMnemonicFromSession(requireAuth, mode);
  const seed = bip39Seed(mnemonic);
  try {
    return await run(seed, derivation);
  } finally {
    seed.fill(0);
  }
}

export async function deriveMLKemPublicKey(ctx: MlkemContext, options?: MlkemOptions): Promise<string> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to derive ML-KEM public key");
  }

  const { deriveMLKemKeypair } = await import("../crypto/mlkem");

  return withSeed(ctx, options, async (seed, derivation) => {
    const keypair = await deriveMLKemKeypair(seed, derivation);
    keypair.privateKey.fill(0);
    return btoa(String.fromCharCode(...Array.from(keypair.publicKey)));
  });
}

export async function mlkemEncrypt(
  ctx: MlkemContext,
  plaintext: string,
  recipientPublicKeys: Array<string | Uint8Array>,
  options?: MlkemOptions
): Promise<EncryptedPayload> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to encrypt data");
  }

  const { mlkemEncryptWithKey } = await import("../crypto/mlkem");

  return withSeed(ctx, options, (seed, derivation) =>
    mlkemEncryptWithKey(plaintext, seed, recipientPublicKeys, derivation)
  );
}

export async function mlkemDecrypt(
  ctx: MlkemContext,
  payload: EncryptedPayload,
  options?: MlkemOptions
): Promise<string> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to decrypt data");
  }

  const { mlkemDecryptWithKey } = await import("../crypto/mlkem");

  return withSeed(ctx, options, (seed, derivation) =>
    mlkemDecryptWithKey(payload, seed, derivation)
  );
}
