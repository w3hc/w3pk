import { decodeCbor, decodeCborExact, type CborValue } from "./cbor";

const AT = 0x40;
const ED = 0x80;
const ATTESTED_CREDENTIAL_DATA_OFFSET = 37;
const AAGUID_LENGTH = 16;
const MAX_CREDENTIAL_ID_LENGTH = 1023;

const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_EC2_CRV = -1;
const COSE_EC2_X = -2;
const COSE_EC2_Y = -3;
const COSE_KTY_EC2 = 2;
const COSE_ALG_ES256 = -7;
const COSE_CRV_P256 = 1;

/**
 * Decodes the attestation object (WebAuthn L3 §6.5.4) and returns its
 * authenticator data.
 */
export function authDataFromAttestationObject(attestationObject: ArrayBuffer): Uint8Array {
  const value = decodeCborExact(new Uint8Array(attestationObject));
  if (
    !(value instanceof Map) ||
    typeof value.get("fmt") !== "string" ||
    !(value.get("attStmt") instanceof Map)
  ) {
    throw new Error("Invalid attestation object");
  }
  const authData = value.get("authData");
  if (!(authData instanceof Uint8Array)) throw new Error("Invalid attestation object");
  return authData;
}

/**
 * Reads the credential public key from the attested credential data
 * (WebAuthn L3 §6.5.1) and returns it as SPKI.
 * Only an ES256 key on P-256 (RFC 9053 §2.1, §7.1.1) is accepted.
 */
export async function credentialPublicKeyFromAuthData(
  authData: Uint8Array
): Promise<ArrayBuffer> {
  const flags = authData[32];
  if (authData.length < ATTESTED_CREDENTIAL_DATA_OFFSET || !(flags & AT)) {
    throw new Error("Attested credential data missing");
  }

  let offset = ATTESTED_CREDENTIAL_DATA_OFFSET + AAGUID_LENGTH;
  if (authData.length < offset + 2) throw new Error("Attested credential data truncated");
  const credIdLength = (authData[offset] << 8) | authData[offset + 1];
  offset += 2;
  if (credIdLength > MAX_CREDENTIAL_ID_LENGTH || authData.length < offset + credIdLength) {
    throw new Error("Invalid credential ID length");
  }
  offset += credIdLength;

  const { value: coseKey, end } = decodeCbor(authData, offset);
  const extensionsEnd = flags & ED ? decodeExtensions(authData, end) : end;
  if (extensionsEnd !== authData.length) {
    throw new Error("Trailing bytes after attested credential data");
  }

  return es256CoseKeyToSpki(coseKey);
}

function decodeExtensions(authData: Uint8Array, offset: number): number {
  const { value, end } = decodeCbor(authData, offset);
  if (!(value instanceof Map)) throw new Error("Invalid authenticator extensions");
  return end;
}

async function es256CoseKeyToSpki(coseKey: CborValue): Promise<ArrayBuffer> {
  if (!(coseKey instanceof Map)) throw new Error("Credential public key is not a COSE key");
  if (coseKey.get(COSE_KTY) !== COSE_KTY_EC2) throw new Error("Credential public key is not EC2");
  if (coseKey.get(COSE_ALG) !== COSE_ALG_ES256) throw new Error("Credential public key is not ES256");
  if (coseKey.get(COSE_EC2_CRV) !== COSE_CRV_P256) throw new Error("Credential public key is not on P-256");

  const x = coseKey.get(COSE_EC2_X);
  const y = coseKey.get(COSE_EC2_Y);
  if (!(x instanceof Uint8Array) || x.length !== 32 || !(y instanceof Uint8Array) || y.length !== 32) {
    throw new Error("Credential public key has invalid coordinates");
  }

  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 33);

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", point, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  } catch {
    throw new Error("Credential public key is not a point on P-256");
  }
  return crypto.subtle.exportKey("spki", key);
}
