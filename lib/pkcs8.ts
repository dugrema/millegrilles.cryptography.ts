import { AsnConvert } from "@peculiar/asn1-schema";
import { EncryptedPrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { decodeBase64 } from "./multiencoding";

/**
 * PKCS#8 encrypted private keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`).
 *
 * Supports the PBES2 envelope produced by OpenSSL
 * (`openssl genpkey -algorithm ED25519 -aes-256-cbc`) and by
 * python-cryptography (`BestAvailableEncryption`), plus the PBKDF2 PRFs that
 * older tooling wrote. Derivation and decryption run through SubtleCrypto, so
 * this works in both Node and browsers without a native dependency.
 *
 * @see RFC 8018 section 6.2 (PBES2) and section 5.2 (PBKDF2)
 */

const OID_PBES2 = "1.2.840.113549.1.5.13";
const OID_PBKDF2 = "1.2.840.113549.1.5.12";

// PBKDF2 PRF OID -> SubtleCrypto hash name. hmacWithSHA224 is deliberately absent:
// Subtle has no SHA-224 and nothing in the MilleGrilles ecosystem writes it.
const PBKDF2_PRF_HASHES: { [oid: string]: string } = {
  "1.2.840.113549.2.7": "SHA-1",
  "1.2.840.113549.2.9": "SHA-256",
  "1.2.840.113549.2.10": "SHA-384",
  "1.2.840.113549.2.11": "SHA-512",
};

// Encryption scheme OID -> AES key length in bits. DES (1.2.840.113549.3.7) and
// 3DES (1.2.840.113549.3.6 / 2.16.840.1.101.3.4.1.3) are not listed because
// SubtleCrypto cannot decrypt them; keys using those schemes are rejected.
const AES_CBC_KEY_LENGTHS: { [oid: string]: number } = {
  "2.16.840.1.101.3.4.1.2": 128,
  "2.16.840.1.101.3.4.1.22": 192,
  "2.16.840.1.101.3.4.1.42": 256,
};

const AES_BLOCK_SIZE = 16;
const MIN_SALT_LENGTH = 8;
const MIN_ITERATIONS = 1;
// PBKDF2 runs synchronously on the caller's thread, so a PEM claiming billions of
// iterations would hang a browser tab. 10M is far above any real tool's default
// (OpenSSL and python-cryptography use 2048).
const MAX_ITERATIONS = 10_000_000;
// Base64 characters of the PEM body. A PKCS#8 envelope never needs this much
// (a 4096-bit RSA key is ~4.8KB of base64); it only exists to bound the work
// done on hostile input.
const MAX_PEM_BODY_CHARS = 16384;

const ENCRYPTED_KEY_BEGIN = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const ENCRYPTED_KEY_END = "-----END ENCRYPTED PRIVATE KEY-----";

/**
 * True when the PEM holds a password-protected PKCS#8 private key.
 */
export function isEncryptedPrivateKeyPem(pem: string): boolean {
  return pem.includes(ENCRYPTED_KEY_BEGIN);
}

/**
 * Decrypt a PBES2 encrypted PKCS#8 private key.
 *
 * The password is read as UTF-8, matching OpenSSL and python-cryptography.
 * @param pem PEM content of an `ENCRYPTED PRIVATE KEY` block.
 * @param password Password protecting the key.
 * @returns The decrypted PKCS#8 DER (`-----BEGIN PRIVATE KEY-----` content).
 */
export async function decryptPrivateKeyPem(
  pem: string,
  password: string,
): Promise<Uint8Array> {
  const info = AsnConvert.parse(pemToDer(pem), EncryptedPrivateKeyInfo);

  if (info.encryptionAlgorithm.algorithm !== OID_PBES2)
    throw new Error(
      `Unsupported encrypted private key scheme: ${info.encryptionAlgorithm.algorithm} (only PBES2 is supported)`,
    );
  if (!info.encryptionAlgorithm.parameters)
    throw new Error("Missing PBES2 parameters");

  // EncryptedPrivateKeyInfo surfaces the PBES2 parameters as raw DER.
  const pbes2Der = new Uint8Array(info.encryptionAlgorithm.parameters);
  const parameters = readTlv(pbes2Der, 0, "PBES2 parameters");
  const pbes2 = readChildren(pbes2Der, parameters, "PBES2 parameters");
  if (pbes2.length !== 2)
    throw new Error("Invalid PBES2 parameters: expected 2 elements");

  const kdf = readAlgorithmIdentifier(
    pbes2Der,
    pbes2[0],
    "PBES2 key derivation function",
  );
  const scheme = readAlgorithmIdentifier(
    pbes2Der,
    pbes2[1],
    "PBES2 encryption scheme",
  );

  if (kdf.algorithm !== OID_PBKDF2)
    throw new Error(
      `Unsupported PBES2 key derivation function: ${kdf.algorithm} (only PBKDF2 is supported)`,
    );
  const keyLengthBits = AES_CBC_KEY_LENGTHS[scheme.algorithm];
  if (keyLengthBits === undefined)
    throw new Error(
      `Unsupported PBES2 encryption scheme: ${scheme.algorithm} (only AES-128/192/256-CBC are supported)`,
    );

  const { salt, iterations, hash } = readPbkdf2Parameters(kdf.parameters);

  if (salt.length < MIN_SALT_LENGTH)
    throw new Error(`Invalid PBKDF2 salt: must be at least ${MIN_SALT_LENGTH} bytes`);
  if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)
    throw new Error(
      `Invalid PBKDF2 iteration count: ${iterations} (must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS})`,
    );
  // @peculiar/asn1-pkcs8 models `encryptedData` as an OctetString instance, not an
  // ArrayBuffer, so take a plain view of it for Subtle.
  const ciphertext = new Uint8Array(
    info.encryptedData.buffer,
    info.encryptedData.byteOffset,
    info.encryptedData.byteLength,
  );
  if (ciphertext.byteLength % AES_BLOCK_SIZE !== 0)
    throw new Error("Invalid encrypted private key: ciphertext is not a multiple of the AES block size");

  const iv = readOctetString(scheme.parameters, "AES-CBC initialisation vector");

  let passwordKey: CryptoKey;
  try {
    passwordKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
  } catch (err) {
    throw new Error("Unable to read the password");
  }

  const aesKey = await crypto.subtle.deriveKey(
    // The copies give Subtle plain ArrayBuffer-backed views, which is what the
    // DOM lib types ask for; the values are tiny.
    { name: "PBKDF2", salt: new Uint8Array(salt), iterations, hash },
    passwordKey,
    { name: "AES-CBC", length: keyLengthBits },
    false,
    ["decrypt"],
  );

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: new Uint8Array(iv) },
      aesKey,
      ciphertext,
    );
    return new Uint8Array(decrypted);
  } catch (err) {
    // Subtle throws (roughly 255 times out of 256) when the password is wrong,
    // because the PKCS#7 padding of the plaintext no longer checks out.
    throw new Error("Unable to decrypt the private key (wrong password?)");
  }
}

// --- PEM and DER helpers ---------------------------------------------------

function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(ENCRYPTED_KEY_BEGIN, "")
    .replace(ENCRYPTED_KEY_END, "")
    .replace(/[\s]/g, "");
  if (body.length > MAX_PEM_BODY_CHARS)
    throw new Error("Encrypted private key is unreasonably large");
  if (body.length === 0)
    throw new Error("Missing content in the encrypted private key PEM");
  return decodeBase64(body);
}

type Tlv = {
  /** Offset of the element's tag byte. */
  start: number;
  tagClass: number;
  tagNumber: number;
  contentStart: number;
  contentEnd: number;
  next: number;
};

function readTlv(der: Uint8Array, offset: number, context: string): Tlv {
  if (der.length - offset < 2)
    throw new Error(`Invalid ${context}: truncated DER`);

  const first = der[offset];
  const tagClass = first >>> 6;
  const tagNumber = first & 0x1f;
  if (tagNumber === 0x1f)
    throw new Error(`Invalid ${context}: multi-byte DER tags are not supported`);

  let pos = offset + 1;
  const lengthByte = der[pos];

  let length: number;
  if (lengthByte === 0x80) {
    throw new Error(`Invalid ${context}: indefinite DER length`);
  } else if (lengthByte < 0x80) {
    length = lengthByte;
    pos += 1;
  } else {
    const byteCount = lengthByte & 0x7f;
    if (byteCount > 4)
      throw new Error(`Invalid ${context}: unsupported DER length size`);
    if (der.length - pos - 1 < byteCount)
      throw new Error(`Invalid ${context}: truncated DER length`);
    length = 0;
    for (let i = 0; i < byteCount; i++) length = length * 256 + der[pos + 1 + i];
    pos += 1 + byteCount;
    if (length < 0x80)
      throw new Error(`Invalid ${context}: non-minimal DER length encoding`);
  }

  const contentStart = pos;
  const contentEnd = contentStart + length;
  if (contentEnd > der.length)
    throw new Error(`Invalid ${context}: DER length exceeds the available bytes`);

  return {
    start: offset,
    tagClass,
    tagNumber,
    contentStart,
    contentEnd,
    next: contentEnd,
  };
}

function readChildren(der: Uint8Array, tlv: Tlv, context: string): Tlv[] {
  if (tlv.tagClass !== 0 || tlv.tagNumber !== 0x10)
    throw new Error(`Invalid ${context}: expected an ASN.1 SEQUENCE`);

  const children: Tlv[] = [];
  let pos = tlv.contentStart;
  while (pos < tlv.contentEnd) {
    const child = readTlv(der, pos, context);
    if (child.next > tlv.contentEnd)
      throw new Error(`Invalid ${context}: child element overruns its parent`);
    children.push(child);
    pos = child.next;
  }
  return children;
}

function readOid(der: Uint8Array, tlv: Tlv, context: string): string {
  if (tlv.tagClass !== 0 || tlv.tagNumber !== 0x06)
    throw new Error(`Invalid ${context}: expected an OBJECT IDENTIFIER`);

  const bytes = der.subarray(tlv.contentStart, tlv.contentEnd);
  if (bytes.length === 0)
    throw new Error(`Invalid ${context}: empty OBJECT IDENTIFIER`);

  const arcs: number[] = [];
  const first = bytes[0];
  if (first >= 120)
    throw new Error(`Invalid ${context}: OBJECT IDENTIFIER first arc is out of range`);
  arcs.push(Math.floor(first / 40), first % 40);

  let value = 0;
  let continuation = false;
  for (let i = 1; i < bytes.length; i++) {
    const byte = bytes[i];
    value = value * 128 + (byte & 0x7f);
    if (value > Number.MAX_SAFE_INTEGER)
      throw new Error(`Invalid ${context}: OBJECT IDENTIFIER arc is too large`);
    if (byte & 0x80) {
      continuation = true;
    } else {
      arcs.push(value);
      value = 0;
      continuation = false;
    }
  }
  if (continuation)
    throw new Error(`Invalid ${context}: truncated OBJECT IDENTIFIER arc`);

  return arcs.join(".");
}

function readAlgorithmIdentifier(
  der: Uint8Array,
  tlv: Tlv,
  context: string,
): { algorithm: string; parameters: Uint8Array | null } {
  const children = readChildren(der, tlv, context);
  if (children.length < 1 || children.length > 2)
    throw new Error(`Invalid ${context}: expected an AlgorithmIdentifier`);
  const algorithm = readOid(der, children[0], context);
  // Hand back the parameters element as a whole TLV, like @peculiar/asn1-* does
  // for its own `parameters` fields, so callers can parse it the same way.
  const parameters = children[1]
    ? der.subarray(children[1].start, children[1].contentEnd)
    : null;
  return { algorithm, parameters };
}

// PBKDF2-params ::= SEQUENCE { salt CHOICE, iterations INTEGER,
//   prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
function readPbkdf2Parameters(
  parameters: Uint8Array | null,
): { salt: Uint8Array; iterations: number; hash: string } {
  if (!parameters)
    throw new Error("Missing PBKDF2 parameters");
  const tlv = readTlv(parameters, 0, "PBKDF2 parameters");
  const children = readChildren(parameters, tlv, "PBKDF2 parameters");
  if (children.length < 2 || children.length > 3)
    throw new Error("Invalid PBKDF2 parameters: expected salt and iterations");

  const saltTlv = children[0];
  // Explicitly tagged salts ([0] printableString, [1] octetString) appear only in
  // hand-built keys; RFC 8018 recommends the OCTET STRING form used by every tool.
  if (saltTlv.tagClass !== 0 || saltTlv.tagNumber !== 0x04)
    throw new Error("Invalid PBKDF2 salt: only OCTET STRING salts are supported");
  const salt = parameters.subarray(saltTlv.contentStart, saltTlv.contentEnd);

  const iterationsTlv = children[1];
  if (iterationsTlv.tagClass !== 0 || iterationsTlv.tagNumber !== 0x02)
    throw new Error("Invalid PBKDF2 parameters: iterations is not an INTEGER");
  const iterations = readUnsignedInteger(parameters, iterationsTlv, "PBKDF2 iterations");

  let hash = "SHA-1"; // RFC 8018 default when the prf field is absent.
  if (children.length === 3) {
    const prf = readAlgorithmIdentifier(parameters, children[2], "PBKDF2 prf");
    const prfHash = PBKDF2_PRF_HASHES[prf.algorithm];
    if (!prfHash)
      throw new Error(
        `Unsupported PBKDF2 PRF: ${prf.algorithm} (only HMAC-SHA1/256/384/512 are supported)`,
      );
    hash = prfHash;
  }

  return { salt, iterations, hash };
}

function readUnsignedInteger(der: Uint8Array, tlv: Tlv, context: string): number {
  const bytes = der.subarray(tlv.contentStart, tlv.contentEnd);
  if (bytes.length === 0 || bytes.length > 5)
    throw new Error(`Invalid ${context}: unsupported INTEGER length`);
  if (bytes[0] & 0x80)
    throw new Error(`Invalid ${context}: negative INTEGER`);
  let value = 0;
  for (let i = 0; i < bytes.length; i++) value = value * 256 + bytes[i];
  return value;
}

function readOctetString(
  parameters: Uint8Array | null,
  context: string,
): Uint8Array {
  if (!parameters)
    throw new Error(`Missing ${context}`);
  const tlv = readTlv(parameters, 0, context);
  if (tlv.tagClass !== 0 || tlv.tagNumber !== 0x04)
    throw new Error(`Invalid ${context}: expected an OCTET STRING`);
  const value = parameters.subarray(tlv.contentStart, tlv.contentEnd);
  if (tlv.next !== parameters.length)
    throw new Error(`Invalid ${context}: trailing bytes after the value`);
  return value;
}
