import { verifyAssertion, verifyAssertionSignature } from "../auth/authenticate";
import { evaluatePrf } from "../auth/prf";
import { CredentialStorage } from "../auth/storage";
import type { PasskeySelectionResult } from "../auth/sync-auth";
import type { BackupCredential, BackupFile, BackupStatus } from "../backup/types";
import type { DeviceSyncInfo } from "../sync/backup-sync";
import type { SyncCapabilities } from "../sync/types";
import { validateUsername } from "../utils/validation";
import { derivePrfSessionKey, PRF_INPUT } from "../wallet/crypto";
import { AddressChangeError, AuthenticationError, PrfUnsupportedError, SyncBootstrapError, WalletError } from "./errors";
import type { SdkContext } from "./context";

export async function getBackupStatus(ctx: SdkContext): Promise<BackupStatus> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to check backup status");
  }

  const { BackupManager } = await import("../backup/manager");
  const backupManager = new BackupManager();
  return backupManager.getBackupStatus(ctx.currentUser.ethereumAddress);
}

export async function confirmRecoveryPhraseBackup(ctx: SdkContext): Promise<void> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to confirm a backup");
  }

  const { BackupManager } = await import("../backup/manager");
  const { deriveAddressChecksum } = await import("../backup/encryption");
  const { ethereumAddress } = ctx.currentUser;
  await new BackupManager().confirmRecoveryPhraseBackup(
    ethereumAddress,
    await deriveAddressChecksum(ethereumAddress)
  );
}

export async function createBackupFile(ctx: SdkContext, password: string): Promise<{ blob: Blob; filename: string }> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to create backup");
  }
  const { assertStrongPassword } = await import("../backup/encryption");
  assertStrongPassword(password);

  const mnemonic = await ctx.getMnemonicFromSession(true);

  const { BackupFileManager } = await import("../backup/backup-file");
  const manager = new BackupFileManager();
  const { backupFile } = await manager.createPasswordBackup(
    mnemonic,
    password,
    await backupCredential(ctx),
    ctx.currentUser.username
  );

  await recordBackup(ctx, 'file');

  return manager.createDownloadableBackup(backupFile);
}

/** Store backup metadata for the backup status and security score */
export async function recordBackup(ctx: SdkContext, method: 'file' | 'prf'): Promise<void> {
  const { BackupStorage } = await import("../backup/storage");
  const { deriveAddressChecksum } = await import("../backup/encryption");
  const { ethereumAddress } = ctx.currentUser!;
  await new BackupStorage().storeBackupMetadata({
    id: crypto.randomUUID(),
    ethereumAddress,
    method,
    createdAt: new Date().toISOString(),
    addressChecksum: await deriveAddressChecksum(ethereumAddress),
  });
}

export async function backupCredential(ctx: Pick<SdkContext, 'currentUser'>): Promise<BackupCredential | undefined> {
  const credential = await new CredentialStorage().getCredentialById(
    ctx.currentUser!.credentialId
  );
  return credential
    ? { id: credential.id, publicKey: credential.publicKey }
    : undefined;
}

export async function restoreFromBackupFile(
  ctx: SdkContext,
  backupData: string | Blob,
  password?: string,
  options: { allowAddressChange?: boolean } = {}
): Promise<{ ethereumAddress: string }> {
  const { BackupFileManager } = await import("../backup/backup-file");
  const manager = new BackupFileManager();
  const allowAddressChange = options.allowAddressChange ?? false;

  const backupFile = await manager.parseBackupFile(backupData);

  if (backupFile.encryptionMethod === 'prf') {
    if (ctx.currentUser && ctx.currentUser.credentialId !== backupFile.credential!.id) {
      throw new SyncBootstrapError("CREDENTIAL_MISMATCH", ctx.currentUser.credentialId);
    }
    return restorePrfBackup(ctx, backupFile, allowAddressChange);
  }

  if (!password) {
    throw new WalletError("Password required to restore password-encrypted backup");
  }
  const { mnemonic, ethereumAddress } = await manager.restoreWithPassword(backupFile, password);

  return applyRestoredWallet(ctx, mnemonic, ethereumAddress, allowAddressChange);
}

/**
 * Put a decrypted wallet in place. Logged out, it stays in memory for
 * register(). Logged in, it replaces the stored wallet once a passkey
 * assertion releases the key it's stored under.
 */
export async function applyRestoredWallet(
  ctx: SdkContext,
  mnemonic: string,
  ethereumAddress: string,
  allowAddressChange: boolean
): Promise<{ ethereumAddress: string }> {
  const { BackupManager } = await import("../backup/manager");
  const backupManager = new BackupManager();

  const storage = new CredentialStorage();
  const credential = ctx.currentUser
    ? await storage.getCredentialById(ctx.currentUser.credentialId)
    : null;

  if (!ctx.currentUser || !credential) {
    backupManager.markBackupVerified(ethereumAddress);
    ctx.currentWallet = { address: ethereumAddress, mnemonic };
    return { ethereumAddress };
  }

  const oldAddress = ctx.currentUser.ethereumAddress;
  if (oldAddress.toLowerCase() !== ethereumAddress.toLowerCase() && !allowAddressChange) {
    throw new AddressChangeError(oldAddress, ethereumAddress);
  }

  // One assertion releases the PRF output the wallet key comes from. Until
  // it succeeds and passes login()'s checks, the stored wallet and the
  // credential stay as they were
  const { output: prfOutput, assertion, challenge } = await evaluatePrf(PRF_INPUT, credential.id);
  if (!(await verifyAssertion(assertion, credential, storage, challenge))) {
    new Uint8Array(prfOutput).fill(0);
    throw new AuthenticationError("Signature verification failed");
  }

  await bootstrapCredential(
    ctx,
    credential,
    mnemonic,
    ethereumAddress,
    prfOutput,
    allowAddressChange
  );

  backupManager.markBackupVerified(ethereumAddress);
  ctx.currentWallet = { address: ethereumAddress, mnemonic };

  return { ethereumAddress };
}

export async function syncWalletWithPasskey(
  ctx: SdkContext,
  backupData: string | Blob,
  password?: string,
  options: { allowAddressChange?: boolean } = {}
): Promise<{ ethereumAddress: string }> {
  const { BackupFileManager } = await import("../backup/backup-file");
  const { BackupManager } = await import("../backup/manager");
  const { promptPasskeySelection } = await import("../auth/sync-auth");

  const manager = new BackupFileManager();
  const backupManager = new BackupManager();

  const allowAddressChange = options.allowAddressChange ?? false;

  const backupFile = await manager.parseBackupFile(backupData);

  if (backupFile.encryptionMethod === 'prf') {
    return restorePrfBackup(ctx, backupFile, allowAddressChange);
  }

  if (!password) {
    throw new WalletError("Password required to restore password-encrypted backup");
  }

  const passkeyResult = await promptPasskeySelection();
  const credentialId = passkeyResult.credentialId;
  let publicKey: string;
  let mnemonic: string;
  let ethereumAddress: string;
  try {
    publicKey = await verifySyncAssertion(passkeyResult, backupFile);
    ({ mnemonic, ethereumAddress } = await manager.restoreWithPassword(backupFile, password));
  } catch (error) {
    if (passkeyResult.prfOutput) new Uint8Array(passkeyResult.prfOutput).fill(0);
    throw error;
  }

  await bootstrapCredential(ctx, 
    {
      id: credentialId,
      publicKey,
      username: passkeyResult.username ?? backupUsername(backupFile) ?? ethereumAddress,
    },
    mnemonic,
    ethereumAddress,
    passkeyResult.prfOutput,
    allowAddressChange
  );

  backupManager.markBackupVerified(ethereumAddress);

  return { ethereumAddress };
}

/**
 * Check the passkey selection's assertion and return the public key it
 * answers to. A known passkey's assertion passes login()'s checks against
 * its stored metadata. A fresh device has none: the public key comes from
 * the password backup that names the passkey.
 */
async function verifySyncAssertion(
  passkeyResult: PasskeySelectionResult,
  backupFile: BackupFile
): Promise<string> {
  const { credentialId, assertion, challenge } = passkeyResult;
  const storage = new CredentialStorage();
  const stored = await storage.getCredentialById(credentialId);

  if (stored) {
    if (!(await verifyAssertion(assertion, stored, storage, challenge))) {
      throw new AuthenticationError("Signature verification failed");
    }
    return stored.publicKey;
  }

  if (!backupFile.credential) {
    throw new SyncBootstrapError("NO_CREDENTIAL", credentialId);
  }
  if (backupFile.credential.id !== credentialId) {
    throw new SyncBootstrapError("CREDENTIAL_MISMATCH", credentialId);
  }
  if (!(await verifyAssertionSignature(assertion, backupFile.credential.publicKey, challenge))) {
    throw new SyncBootstrapError("PUBLIC_KEY_MISMATCH", credentialId);
  }
  return backupFile.credential.publicKey;
}

/** The backup's username, unless it isn't one register() would accept */
function backupUsername(backupFile: BackupFile): string | undefined {
  const { username } = backupFile;
  return typeof username === 'string' && validateUsername(username) ? username : undefined;
}

/**
 * Restore a PRF backup with its passkey and set this device up for it.
 * The public key is this device's when it has the passkey's metadata,
 * else the backup's, checked against the assertion's signature. The
 * backup carries no address, so a change of the passkey's stored address
 * is only known after the assertion.
 */
async function restorePrfBackup(
  ctx: SdkContext,
  backupFile: BackupFile,
  allowAddressChange: boolean
): Promise<{ ethereumAddress: string }> {
  const { DeviceSyncManager } = await import("../sync/backup-sync");
  const { BackupManager } = await import("../backup/manager");

  const credential = backupFile.credential!;
  const stored = await new CredentialStorage().getCredentialById(credential.id);
  const publicKey = stored?.publicKey ?? credential.publicKey;

  const { mnemonic, ethereumAddress, walletPrfOutput } = await new DeviceSyncManager().importFromSync(
    backupFile,
    publicKey
  );

  await bootstrapCredential(ctx, 
    {
      id: credential.id,
      publicKey,
      username: backupUsername(backupFile) ?? ethereumAddress,
    },
    mnemonic,
    ethereumAddress,
    walletPrfOutput,
    allowAddressChange
  );

  new BackupManager().markBackupVerified(ethereumAddress);

  return { ethereumAddress };
}

/**
 * Set this device up for a passkey and a synced wallet: saves the
 * passkey's metadata (or points it at the wallet), stores the wallet
 * under the key derived from `prfOutput` in the passkey's own record and
 * starts a session. Other passkeys of the wallet keep their records. If
 * pointing the passkey at the new wallet fails, its previous record is
 * put back. The previous wallet's persistent session is deleted before
 * anything else is written. Without `prfOutput`, the wallet and the
 * session stay in memory only.
 *
 * @throws AddressChangeError if the passkey has another wallet on this device and `allowAddressChange` is false
 * @throws PrfUnsupportedError if it has another wallet and there is no `prfOutput` to store the new one with
 */
export async function bootstrapCredential(
  ctx: SdkContext,
  credential: { id: string; publicKey: string; username: string },
  mnemonic: string,
  ethereumAddress: string,
  prfOutput: ArrayBuffer | undefined,
  allowAddressChange: boolean
): Promise<void> {
  const storage = new CredentialStorage();
  const stored = await storage.getCredentialById(credential.id);
  const addressChanged =
    !!stored && stored.ethereumAddress.toLowerCase() !== ethereumAddress.toLowerCase();

  if (addressChanged && (!allowAddressChange || !prfOutput)) {
    if (prfOutput) new Uint8Array(prfOutput).fill(0);
    throw allowAddressChange
      ? new PrfUnsupportedError(credential.id)
      : new AddressChangeError(stored!.ethereumAddress, ethereumAddress);
  }

  // Only a remember-me cache: deleting it first means no later failure
  // leaves the replaced mnemonic readable
  if (addressChanged) {
    await ctx.sessionManager.deletePersistentSession(stored!.ethereumAddress);
  }

  const previousWallet = addressChanged
    ? await ctx.walletStorage.retrieve(credential.id)
    : null;

  if (prfOutput) {
    await ctx.storeWallet(ethereumAddress, mnemonic, credential.id, prfOutput);
  } else if (!stored) {
    await ctx.walletStorage.delete(credential.id);
  }

  // register() refuses a username already on this device
  const username =
    !stored && (await storage.userExists(credential.username))
      ? ethereumAddress
      : credential.username;

  if (!stored) {
    const now = new Date().toISOString();
    await storage.saveCredential({
      id: credential.id,
      publicKey: credential.publicKey,
      username,
      ethereumAddress,
      createdAt: now,
      lastUsed: now,
    });
  } else if (addressChanged) {
    try {
      await storage.updateCredentialAddress(credential.id, ethereumAddress);
    } catch (error) {
      if (previousWallet) await ctx.walletStorage.store(previousWallet);
      throw error;
    }
  }

  ctx.currentUser = {
    username: stored?.username ?? username,
    ethereumAddress,
    credentialId: credential.id,
  };

  await ctx.sessionManager.startSession(
    mnemonic,
    credential.id,
    ethereumAddress,
    prfOutput
      ? await derivePrfSessionKey(prfOutput, ctx.sessionManager.storesSessionKey)
      : undefined,
    'STANDARD'
  );

  void ctx.requestPersistentStorage();
  ctx.config.onAuthStateChanged?.(true, ctx.currentUser);
}

export async function registerWithBackupFile(
  ctx: SdkContext,
  backupData: string | Blob,
  password: string,
  username: string
): Promise<{ address: string; username: string }> {
  const { BackupFileManager } = await import("../backup/backup-file");
  const { BackupManager } = await import("../backup/manager");
  const manager = new BackupFileManager();
  const backupManager = new BackupManager();

  // Parse and restore the backup
  const backupFile = await manager.parseBackupFile(backupData);

  if (backupFile.encryptionMethod !== 'password') {
    throw new WalletError(
      "Can only register with password-encrypted backups. Use syncWalletWithPasskey() or importFromSync() for PRF backups."
    );
  }

  const { mnemonic, ethereumAddress } = await manager.restoreWithPassword(
    backupFile,
    password
  );

  // Verify the mnemonic produces the expected address
  const { Wallet } = await import("ethers");
  const wallet = Wallet.fromPhrase(mnemonic);

  if (wallet.address.toLowerCase() !== ethereumAddress.toLowerCase()) {
    throw new WalletError("Backup verification failed: address mismatch");
  }

  // Mark backup as verified (successful restore proves the backup works)
  backupManager.markBackupVerified(ethereumAddress);

  // Set the current wallet
  ctx.currentWallet = {
    address: ethereumAddress,
    mnemonic,
  };

  // Now register with the restored wallet
  return ctx.register({ username });
}

export async function getSyncStatus(): Promise<DeviceSyncInfo | null> {
  const { DeviceSyncManager } = await import("../sync/backup-sync");
  const syncManager = new DeviceSyncManager();

  return syncManager.getSyncInfo();
}

export async function exportForSync(
  ctx: SdkContext,
  password?: string
): Promise<{ blob: Blob; filename: string; qrCode?: string }> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to export for sync");
  }
  if (password) {
    const { assertStrongPassword } = await import("../backup/encryption");
    assertStrongPassword(password);
  }

  // The PRF assertion below is the fresh user verification, so a cached
  // session doesn't cost a second prompt
  const mnemonic = await ctx.getMnemonicFromSession();

  const walletData = await ctx.walletStorage.retrieve(
    ctx.currentUser.credentialId
  );
  if (!walletData) {
    throw new WalletError("No wallet data found");
  }

  const storage = new CredentialStorage();
  const credential = await storage.getCredentialById(walletData.credentialId);
  if (!credential) {
    throw new WalletError("Credential not found");
  }

  const { DeviceSyncManager } = await import("../sync/backup-sync");
  const syncManager = new DeviceSyncManager();

  const { backupFile, blob } = await syncManager.exportForSync(
    mnemonic,
    { id: credential.id, publicKey: credential.publicKey },
    ctx.currentUser.username,
    password
  );

  await recordBackup(ctx, backupFile.encryptionMethod === 'prf' ? 'prf' : 'file');

  const filename = `w3pk-sync-${new Date().toISOString().split('T')[0]}.json`;

  // Optionally generate QR code
  let qrCode: string | undefined;
  try {
    qrCode = await syncManager.generateSyncQR(backupFile);
  } catch (error) {
    // QR code generation is optional
    console.warn('QR code generation failed:', error);
  }

  return { blob, filename, qrCode };
}

export async function importFromSync(
  ctx: SdkContext,
  syncData: string | Blob,
  options: { allowAddressChange?: boolean } = {}
): Promise<{ ethereumAddress: string; success: boolean }> {
  const { BackupFileManager } = await import("../backup/backup-file");

  const backupFile = await new BackupFileManager().parseBackupFile(syncData);

  if (backupFile.encryptionMethod !== 'prf') {
    throw new WalletError(
      "importFromSync() takes PRF backups from exportForSync(). Use syncWalletWithPasskey() for other backups."
    );
  }
  if (ctx.currentUser && ctx.currentUser.credentialId !== backupFile.credential!.id) {
    throw new SyncBootstrapError("CREDENTIAL_MISMATCH", ctx.currentUser.credentialId);
  }

  const { ethereumAddress } = await restorePrfBackup(
    ctx,
    backupFile,
    options.allowAddressChange ?? false
  );

  return {
    ethereumAddress,
    success: true,
  };
}

export async function detectSyncCapabilities(): Promise<SyncCapabilities> {
  const { PlatformDetector } = await import("../sync/platform-detect");
  const detector = new PlatformDetector();

  return detector.detectSyncCapabilities();
}
