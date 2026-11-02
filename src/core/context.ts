import type { SecurityMode, UserInfo } from "../types";

/**
 * The `Web3Passkey` internals its feature modules work on. Each module
 * takes a `Pick` of the members it needs.
 */
export interface SdkContext {
  readonly currentUser: UserInfo | null;
  getMnemonicFromSession(forceAuth?: boolean, securityMode?: SecurityMode): Promise<string>;
}
