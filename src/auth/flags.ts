/**
 * UV flag: bit 2 of the authenticator data flags byte (offset 32).
 * CTAP2 hmac-secret keeps separate secrets for verified and unverified
 * assertions, so a PRF output is only usable when this flag is set.
 */
export function isUserVerified(authData: Uint8Array): boolean {
  return authData.length > 32 && (authData[32] & 0x04) !== 0;
}
