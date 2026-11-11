import { CryptoError, WalletError } from "./errors";
import { applyRestoredWallet, loggedInCredential } from "./backup-sync";
import type { SdkContext } from "./context";
import type { GuardianShare } from "../recovery/backup-based-recovery";
import type { BackupFile } from "../backup/types";
import type { BackupFileManager } from "../backup/backup-file";

type SocialRecoveryContext = Pick<SdkContext, 'currentUser' | 'currentPublicKey' | 'getMnemonicFromSession'>;

export async function setupSocialRecovery(
  ctx: SocialRecoveryContext,
  guardians: { name: string; email?: string }[],
  threshold: number,
  password: string
): Promise<{
  guardianShares: GuardianShare[];
  setupComplete: boolean;
}> {
  if (!ctx.currentUser) {
    throw new WalletError("Must be authenticated to set up social recovery");
  }

  const { assertStrongPassword } = await import("../backup/encryption");
  assertStrongPassword(password);

  const mnemonic = await ctx.getMnemonicFromSession(true);

  const { BackupFileManager } = await import("../backup/backup-file");
  const { backupFile } = await new BackupFileManager().createPasswordBackup(
    mnemonic,
    password,
    await loggedInCredential(ctx),
    ctx.currentUser.username
  );

  // Split backup among guardians
  const { SocialRecovery } = await import("../recovery/backup-based-recovery");
  const recovery = new SocialRecovery();

  const setup = await recovery.splitAmongGuardians(
    backupFile,
    guardians,
    threshold,
    ctx.currentUser.ethereumAddress
  );

  return {
    guardianShares: setup.guardianShares,
    setupComplete: true,
  };
}

export async function generateGuardianInvite(
  guardianShare: GuardianShare,
  message?: string
): Promise<{
  qrCodeDataURL?: string;
  shareDocument: string;
  downloadBlob: Blob;
  filename: string;
}> {
  const { SocialRecovery } = await import("../recovery/backup-based-recovery");
  const recovery = new SocialRecovery();

  const invitation = await recovery.createGuardianInvitation(guardianShare, message);
  const download = recovery.createShareDownload(guardianShare);

  return {
    qrCodeDataURL: invitation.qrCodeDataURL,
    shareDocument: invitation.shareDocument,
    downloadBlob: download.blob,
    filename: download.filename,
  };
}

/** Most backups rebuilt from subsets of the shares that recoverFromGuardians() decrypts */
export const MAX_BACKUP_DECRYPTIONS = 8;

async function decryptGuardianBackup(
  backupFileManager: BackupFileManager,
  backupFile: BackupFile,
  password: string
): Promise<{ mnemonic: string; ethereumAddress: string }> {
  if (backupFile.encryptionMethod !== 'password') {
    throw new WalletError(
      'PRF backups are not supported for guardian recovery. Use password-protected backups.'
    );
  }
  return backupFileManager.restoreWithPassword(backupFile, password);
}

export async function recoverFromGuardians(
  ctx: SdkContext,
  shares: Array<string | GuardianShare>,
  password: string,
  options: { allowAddressChange?: boolean } = {}
): Promise<{ ethereumAddress: string }> {
  const { SocialRecovery } = await import("../recovery/backup-based-recovery");
  const { BackupFileManager } = await import("../backup/backup-file");

  const recovery = new SocialRecovery();
  const backupFileManager = new BackupFileManager();

  // Parse shares if they're strings
  const parsedShares = shares.map(share =>
    typeof share === 'string' ? recovery.parseGuardianShare(share) : share
  );

  if (!password) {
    throw new WalletError('Password required to decrypt password-protected backup');
  }

  const rebuilt = await recovery.rebuildBackups(parsedShares);
  const backups = rebuilt.backups.slice(0, MAX_BACKUP_DECRYPTIONS);
  let result: { mnemonic: string; ethereumAddress: string } | undefined;
  let firstError: unknown;
  for (const backupFile of backups) {
    try {
      result = await decryptGuardianBackup(backupFileManager, backupFile, password);
      break;
    } catch (error) {
      if (firstError === undefined) firstError = error;
    }
  }
  if (!result) {
    throw backups.length === 1
      ? firstError
      : new CryptoError(
          `None of the ${backups.length} backups rebuilt from subsets of the shares decrypts: the password is wrong, or a share was edited and its checksum recomputed`,
          firstError
        );
  }
  if (result.ethereumAddress.toLowerCase() !== rebuilt.walletAddress.toLowerCase()) {
    throw new WalletError("Recovered wallet doesn't match the guardian shares' address");
  }

  return applyRestoredWallet(
    ctx,
    result.mnemonic,
    result.ethereumAddress,
    options.allowAddressChange ?? false
  );
}
