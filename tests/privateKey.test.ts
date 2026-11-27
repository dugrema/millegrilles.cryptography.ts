import "reflect-metadata";
import {
  isEncryptedPrivateKeyPem,
  loadPrivateKeyEd25519,
  loadPrivateKeyPem,
  savePrivateKeyEd25519,
} from "../lib/certificates";
import { decodeHex, encodeHex } from "../lib/multiencoding";

// --- Fixtures ---------------------------------------------------------------

// Written by the old @dugrema/node-forge fork: PKCS#8 whose privateKey holds the
// RFC 8410 OCTET STRING *and* the public key appended to it.
const FORGE_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
ME4CAQAwBQYDK2VwBEIEILq9hBT8x+j38MQdFjx5EZUO+15+OWFfWsEVdbULOMiJ
OT/3sG07S6nyHpQD71VdQAM17uBzhQ+OMoAKWRjIP+U=
-----END PRIVATE KEY-----`;
const FORGE_PRIVATE_HEX =
  "babd8414fcc7e8f7f0c41d163c7911950efb5e7e39615f5ac11575b50b38c889";

// Same key, written by node-forge as PBES2 / PBKDF2-HMAC-SHA512 / AES-256-CBC.
const FORGE_ENCRYPTED_PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGtMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAj52joL+fVm5gICCAAw
HQYJYIZIAWUDBAEqBBBdAUqIYES+PCXKj7VkyNd/BGBvmIssujxII+fPu1f40iLl
B1rEjTsUI34K+u5xD32ne6Eweb5BPZNS479Y1optjYXTe4pmrbIvvVWw8oYkCg1C
jKvpFJjoRMzLA3jzzWW1z8rANlqqXlTDUaK1LIBGVG8=
-----END ENCRYPTED PRIVATE KEY-----`;
const FORGE_ENCRYPTED_PASSWORD = "HTGUELI3x7TevB12aQIyit/4eckiRm2kuFx/5xvpW30";
const FORGE_ENCRYPTED_HEX =
  "f5fe1a63a7abec682c3534a812e847e51e40da66c545c26e908227367936eea8";

// openssl genpkey -algorithm ED25519 -aes-256-cbc -pass 'pass:café123'
// PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC, 2048 iterations.
const OPENSSL_ENCRYPTED_PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGjMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBDbnkBMsJgF8MdpyXbP
cgQMAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQOiaFCeFrwR6chExk
BHCBegRABzW93cUfqKC2/MM7QZjoGa64FUNQpSIA3O6wBaq/lijqfyl89dDX9WZK
2KX8RT1+tE78b6/DRHKXRvXVx7GOgQ==
-----END ENCRYPTED PRIVATE KEY-----`;
const OPENSSL_ENCRYPTED_PASSWORD = "café123";
const OPENSSL_ENCRYPTED_HEX =
  "218160309e58e14f6e3448253bb4f0b1eb616f42a8aaee4a8f6b135e81004740";

// openssl pkcs8 -topk8 -v2 AES-128-CBC : no prf field, so the PBKDF2 default
// PRF (HMAC-SHA1) must be assumed.
const OPENSSL_SHA1_ENCRYPTED_PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGVMFEGCSqGSIb3DQEFDTBEMCMGCSqGSIb3DQEFDDAWBBCG+C7zhOd4Ypm21PLy
lZNfAgIIADAdBglghkgBZQMEAQIEECsF7UF1h+vvOaS2UQh0t5kEQDJUZBW/tI/N
pLtWIvjzObJFmbULdMXKyXphqX+mGsJllDSgZcq/qLzzGCd0m+g3CNgmM2sanc6Y
0QPVJeDDi6Y=
-----END ENCRYPTED PRIVATE KEY-----`;
const OPENSSL_SHA1_ENCRYPTED_PASSWORD = "pw12345678";
const OPENSSL_SHA1_ENCRYPTED_HEX =
  "0b6a2f7942407a547fe55c8cf1c7acedf9dbca45a6a6c5b1df5311d356287321";

// PBES2 / PBKDF2-HMAC-SHA256 / 3DES-CBC: SubtleCrypto cannot decrypt these.
const DES3_ENCRYPTED_PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGSMFYGCSqGSIb3DQEFDTBJMDEGCSqGSIb3DQEFDDAkBBBc8KhxS36WoTVdNMvY
8D8yAgIIADAMBggqhkiG9w0CCQUAMBQGCCqGSIb3DQMHBAhCyhNJ6IV8RAQ4MS2Q
VcftCKiZvwS6ASobeGdXCMVGmOEptGpGdlF7IUNODznG84ycZspFSkW1DQsj8ev1
alBPBJ8=
-----END ENCRYPTED PRIVATE KEY-----`;

// PKCS#5 v1.5 (pbeWithMD5AndDES-CBC), long deprecated.
const PBES1_ENCRYPTED_PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MFcwGwYJKoZIhvcNAQUDMA4ECEp4zTyt8YMXAgIIAAQ46UdsRGorApO4FL2erZ2g
wcx1HiRKVu/NgQ2kBmej1OMgbvKIS4VJwshbTOOVloRh+xNyIjmsSvw=
-----END ENCRYPTED PRIVATE KEY-----`;

const ENCRYPTED_KEY_WITHOUT_BODY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
-----END ENCRYPTED PRIVATE KEY-----`;

const RSA_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCh3p0/+IRhMkNO
kKPfQBoU9qjV0Piovow7iYMFNK24eD4Oug0VSXQxMbckEJMmI6oiwv+ljS1/89fR
Zb/RDqmqvOhHrDyZRY08eMRmY0X7gQhsip7kFxUsyiqfgthmQTSVqljnT/j97Z5T
2cgSsyIC4jlsmhI19u0A/iOe2tozoD1VXhifq61k40xomlAqFmDL04m8X7t2PDZw
gnJfF9oRXo5WPqR2GR+PMsVZwtwW/kC9RGCtWcN0aM8Q2AE4tR+sDMxfvKn82Sfb
uYSSMwYzv9ki5A8nSNxGrqChY+TQGnHz5gEbu/WOnK+Re2gXwtNnGz7hkCQ8/m4F
ayGPrPDZAgMBAAECggEAHKxLXJ6QDIuTwqH6dTxsolQDGkT3FyURwCYesFhhgXDD
RWaNlLy7OU+eKmRJPJNKuvehw1ibu7OdAjms3cJkKZtm5fNLlLbuSsz1tVFWfzOf
I2L2vF6eYJ27KSBLZumb//r53pea+pgR2LaWK0HR/4LFO0ibezWvS+K4upX32vb6
OBDWgbWHPrrp/PFrm7oIhy1C7n9p0lXNzbAemqOw9Mr0zlR/tB1ysRhY7Ipe7CZK
W2VnGRjHzROm0oBxSHvrhEbWvsdzg7C/ep1bg3Xd/IlI4SVdbv7a/Y9goOXgW/JB
cdGMAiTrdzXoC/mZ5jfp8acDfJ5SoR+dcPP7weS4kQKBgQDaxMScTn2qiia+shN1
3H5GYkfr+WXC+MCMY+RMAdLzarCXURUO9bOEdtsx+L+nFqE/4f5UwcO+lfw0Fl+S
VT5NvjByD+0CqJ0hToZHZ0djHp6vRLGIcLlXNS0Wsrb7dkunheImGuEm8g09utfz
1h1YwXY2DniHPgzWP1uXwxJ/5QKBgQC9auO+X1YUlBQxoKoUVyDindAbX9LdnU/p
CmRpYp8JLHKyyRB8/QfYebjj3uZrTb0SdfkCLzMeYtBIMT3NUPJ2+6KkgKx5dUMq
qh0eO6CbVVxRy1wUyQig/7letGGZSNB1Q4sadA4hXorUheoWyFfgAcc73FYPBCR/
hrJD62vV5QKBgCr6WxHGDcQSLfhqrY4LCjezmSOPtGEwU0uBWFliRloRzK19fWCZ
/nF4lClmD+i4dmdBc6CdDGKFvq1Q8+egnYPSaFwQKuTJ0Uy4y4J9lLWxT0VpfmMq
mg664KfD5lTScZxwnfQUdcUb6mQFL+W0W8GTCDEoeJ9BHm58tfbDmP/NAoGALPjb
6a8o+OnPgZjryLiHDkb5ygYOQp+/AU1+WacYq0zqTph+Wa6Z1kPQKgoaGw/x/BgW
bvZV5LkBSqKmUcEOUEGedAA48v1sXQzWrP7rOvYhXSozSpwQeGk+0cVyBrrLA4xt
0nILiNCxlZPV6GLYuk6xxvyhUh9hqwWH/ag/iiECgYEAw5w+ns0Ow3Toi6QisZqY
WrQY+6l9c6loGrWr3B/5G+BaVeERM9f0rgQxBwV2TRyx/GEsdzKkwjSn/AXmZK9m
NneD8AB0GFZexUvAu164UQf/UlpN30IVFJESfTHh5CZh7AV7aH+uXJWbHys2J798
fPAXVi59TPpjT313o10ERzU=
-----END PRIVATE KEY-----`;

// --- Detection --------------------------------------------------------------

test("detect encrypted private key PEMs", () => {
  expect(isEncryptedPrivateKeyPem(OPENSSL_ENCRYPTED_PEM)).toBe(true);
  expect(isEncryptedPrivateKeyPem(FORGE_PRIVATE_PEM)).toBe(false);
  expect(isEncryptedPrivateKeyPem("-----BEGIN CERTIFICATE-----\nAA==\n")).toBe(
    false,
  );
});

// --- Plain keys -------------------------------------------------------------

test("load a plain Ed25519 private key", async () => {
  const key = await loadPrivateKeyEd25519(FORGE_PRIVATE_PEM);
  expect(key).toStrictEqual(decodeHex(FORGE_PRIVATE_HEX));
  expect(key.length).toBe(32);
});

test("loadPrivateKeyPem returns the plain PKCS#8 PEM of an encrypted key", async () => {
  const pem = await loadPrivateKeyPem(
    OPENSSL_ENCRYPTED_PEM,
    OPENSSL_ENCRYPTED_PASSWORD,
  );
  expect(isEncryptedPrivateKeyPem(pem)).toBe(false);
  expect(pem.startsWith("-----BEGIN PRIVATE KEY-----")).toBe(true);
  expect(encodeHex(await loadPrivateKeyEd25519(pem))).toBe(
    OPENSSL_ENCRYPTED_HEX,
  );
});

test("ignore the password when the key is not encrypted", async () => {
  const key = await loadPrivateKeyEd25519(FORGE_PRIVATE_PEM, "whatever");
  expect(encodeHex(key)).toBe(FORGE_PRIVATE_HEX);
});

test("save then load round-trips a key", async () => {
  const seed = decodeHex(FORGE_PRIVATE_HEX);
  const pem = savePrivateKeyEd25519(seed);
  expect(await loadPrivateKeyEd25519(pem)).toStrictEqual(seed);
});

// --- Encrypted keys ---------------------------------------------------------

test("load an encrypted private key (PBKDF2-HMAC-SHA512, node-forge)", async () => {
  const key = await loadPrivateKeyEd25519(
    FORGE_ENCRYPTED_PEM,
    FORGE_ENCRYPTED_PASSWORD,
  );
  expect(encodeHex(key)).toBe(FORGE_ENCRYPTED_HEX);
});

test("load an encrypted private key (PBKDF2-HMAC-SHA256, OpenSSL, UTF-8 password)", async () => {
  const key = await loadPrivateKeyEd25519(
    OPENSSL_ENCRYPTED_PEM,
    OPENSSL_ENCRYPTED_PASSWORD,
  );
  expect(encodeHex(key)).toBe(OPENSSL_ENCRYPTED_HEX);
});

test("load an encrypted private key (AES-128-CBC, default HMAC-SHA1 PRF)", async () => {
  const key = await loadPrivateKeyEd25519(
    OPENSSL_SHA1_ENCRYPTED_PEM,
    OPENSSL_SHA1_ENCRYPTED_PASSWORD,
  );
  expect(encodeHex(key)).toBe(OPENSSL_SHA1_ENCRYPTED_HEX);
});

// --- Rejections -------------------------------------------------------------

test("reject a wrong password", async () => {
  await expect(
    loadPrivateKeyEd25519(OPENSSL_ENCRYPTED_PEM, "not-the-password"),
  ).rejects.toThrow();
});

test("require a password for an encrypted key", async () => {
  await expect(loadPrivateKeyEd25519(OPENSSL_ENCRYPTED_PEM)).rejects.toThrow(
    "The private key is encrypted, a password is required",
  );
});

test("reject a 3DES encrypted key", async () => {
  await expect(
    loadPrivateKeyEd25519(DES3_ENCRYPTED_PEM, "pw12345678"),
  ).rejects.toThrow(/Unsupported PBES2 encryption scheme/);
});

test("reject a PKCS#5 v1.5 encrypted key", async () => {
  await expect(
    loadPrivateKeyEd25519(PBES1_ENCRYPTED_PEM, "pw12345678"),
  ).rejects.toThrow(/Unsupported encrypted private key scheme/);
});

test("reject a non-Ed25519 key", async () => {
  await expect(loadPrivateKeyEd25519(RSA_PRIVATE_PEM)).rejects.toThrow(
    /Invalid algorithm OID for Ed25519 private key/,
  );
});

test("reject a truncated encrypted private key", async () => {
  // Drop the last body line: the DER is then shorter than the lengths announced
  // by its headers, which must be caught instead of reading past the end.
  const truncated = OPENSSL_ENCRYPTED_PEM.replace(
    "2KX8RT1+tE78b6/DRHKXRvXVx7GOgQ==\n",
    "",
  );
  await expect(
    loadPrivateKeyEd25519(truncated, OPENSSL_ENCRYPTED_PASSWORD),
  ).rejects.toThrow();
});

test("reject garbage where a private key is expected", async () => {
  await expect(
    loadPrivateKeyEd25519("-----BEGIN PRIVATE KEY-----\nAA=\n"),
  ).rejects.toThrow();
  await expect(
    loadPrivateKeyEd25519(ENCRYPTED_KEY_WITHOUT_BODY, "pw12345678"),
  ).rejects.toThrow("Missing content in the encrypted private key PEM");
});
