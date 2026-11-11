import type { LocalStorageWalletStorage } from "../wallet/storage";
import type { GeneratedWallet, RegisterResult, SecurityMode, UserInfo } from "../types";
import type { InternalConfig } from "./config";
import type { SessionManager } from "./session";

/**
 * The `Web3Passkey` internals its feature modules work on. Each module
 * takes a `Pick` of the members it needs.
 */
export interface SdkContext {
  currentUser: UserInfo | null;
  /** The logged-in passkey's public key, as checked at login */
  currentPublicKey: string | null;
  currentWallet: GeneratedWallet | null;
  readonly config: InternalConfig;
  readonly walletStorage: LocalStorageWalletStorage;
  readonly sessionManager: SessionManager;
  getMnemonicFromSession(forceAuth?: boolean, securityMode?: SecurityMode): Promise<string>;
  storeWallet(
    ethereumAddress: string,
    mnemonic: string,
    credentialId: string,
    prfOutput: BufferSource,
    createdAt?: string
  ): Promise<void>;
  requestPersistentStorage(): Promise<void>;
  register(options: { username: string }): Promise<RegisterResult>;
}
