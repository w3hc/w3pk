import { WalletError } from "./errors";
import { backupCredential } from "./backup-sync";
import type { SdkContext } from "./context";
import type { GuardianShare } from "../recovery/backup-based-recovery";

type SocialRecoveryContext = Pick<SdkContext, 'currentUser' | 'getMnemonicFromSession'>;

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

  if (!password) {
    throw new WalletError("Password required for social recovery");
  }

  const mnemonic = await ctx.getMnemonicFromSession(true);

  const { BackupFileManager } = await import("../backup/backup-file");
  const { backupFile } = await new BackupFileManager().createPasswordBackup(
    mnemonic,
    password,
    await backupCredential(ctx)
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

export async function recoverFromGuardians(
  shares: Array<string | GuardianShare>,
  password: string
): Promise<{ mnemonic: string; ethereumAddress: string }> {
  const { SocialRecovery } = await import("../recovery/backup-based-recovery");
  const { BackupFileManager } = await import("../backup/backup-file");
  const { BackupManager } = await import("../backup/manager");

  const recovery = new SocialRecovery();
  const backupFileManager = new BackupFileManager();
  const backupManager = new BackupManager();

  // Parse shares if they're strings
  const parsedShares = shares.map(share =>
    typeof share === 'string' ? recovery.parseGuardianShare(share) : share
  );

  // Combine shares to recover backup file
  const backupFile = await recovery.recoverFromShares(parsedShares);

  // Decrypt backup file
  let result;
  if (backupFile.encryptionMethod === 'password') {
    if (!password) {
      throw new WalletError('Password required to decrypt password-protected backup');
    }
    result = await backupFileManager.restoreWithPassword(backupFile, password);
  } else {
    throw new WalletError(
      'PRF backups are not supported for guardian recovery. Use password-protected backups.'
    );
  }
  if (result.ethereumAddress.toLowerCase() !== parsedShares[0].walletAddress.toLowerCase()) {
    throw new WalletError("Recovered wallet doesn't match the guardian shares' address");
  }

  // Mark backup as verified (successful guardian recovery proves the backup works)
  backupManager.markBackupVerified(result.ethereumAddress);

  return result;
}
