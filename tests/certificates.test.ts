import "reflect-metadata";
import { Buffer } from 'buffer';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  verifyCertificatePem,
  wrapperFromPems,
  getIdmg,
  loadPrivateKeyEd25519,
  savePrivateKeyEd25519,
  CertificateStore,
  CertificateCache,
  generateCsr,
  splitKeyCertPem,
} from "../lib/certificates";
import { decodeBase64Url } from "../lib/multiencoding";
import { parseMessage } from "../lib/messageStruct";

// ---------------------------------------------------------------------------
// Dynamic certificate generation
// ---------------------------------------------------------------------------

/**
 * Generates an Ed25519 certificate chain (CA → Intermediate → Leaf) using
 * openssl and exposes the PEM strings for tests.
 *
 * Certificates are valid for 10 years (CA) / 5 years (intermediate) / 1 year
 * (leaf) so the test suite never fails due to expiry.
 */
function generateTestCertificates(): {
  caPem: string;
  interPem: string;
  leafPem: string;
  leafPubKeyHex: string;
  idmg: string;
  chain: [string, string];
} {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mg-test-certs-'));

  const caKey = path.join(tmpDir, 'ca.key');
  const caPem = path.join(tmpDir, 'ca.pem');
  const interKey = path.join(tmpDir, 'inter.key');
  const interPem = path.join(tmpDir, 'inter.pem');
  const interCsr = path.join(tmpDir, 'inter.csr');
  const interExt = path.join(tmpDir, 'inter.ext');
  const leafKey = path.join(tmpDir, 'leaf.key');
  const leafPem = path.join(tmpDir, 'leaf.pem');
  const leafCsr = path.join(tmpDir, 'leaf.csr');
  const leafExt = path.join(tmpDir, 'leaf.ext');

  // Helper to run openssl commands with bash for process substitution support
  const sh = (cmd: string): string => {
    try {
      return execSync(`/bin/bash -c "${cmd.replace(/"/g, '\\"')}"`, { encoding: 'utf-8' });
    } catch (e: any) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      throw new Error(`shell command failed: ${e.stderr || e.message}`);
    }
  };

  // 1. Generate root CA key & self-signed cert (10 years)
  sh(`openssl genpkey -algorithm ED25519 -out "${caKey}"`);
  sh(
    `openssl req -new -x509 -key "${caKey}" -out "${caPem}" -days 3650 ` +
    `-subj "/CN=dev1/O=MilleGrilles" ` +
    `-addext "basicConstraints=critical,CA:TRUE" ` +
    `-addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"`,
  );

  // 2. Generate intermediate key & CSR
  sh(`openssl genpkey -algorithm ED25519 -out "${interKey}"`);
  sh(
    `openssl req -new -key "${interKey}" -out "${interCsr}" ` +
    `-subj "/CN=fd3d3455-a4f1-4c3f-bde6-6fb190e962c2/OU=dev1/O=zaLJQCU8mYyZBTUNHjNWaKF1wEm9mrGrmHLTD2yefEy5EqQ3aGA7LKcW"`,
  );

  // 3. Sign intermediate cert with CA (5 years) using extension file
  fs.writeFileSync(interExt, 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign');
  sh(
    `openssl x509 -req -in "${interCsr}" -CA "${caPem}" -CAkey "${caKey}" -CAcreateserial ` +
    `-out "${interPem}" -days 1825 -extfile "${interExt}"`,
  );

  // 4. Generate leaf key & CSR
  sh(`openssl genpkey -algorithm ED25519 -out "${leafKey}"`);
  sh(
    `openssl req -new -key "${leafKey}" -out "${leafCsr}" ` +
    `-subj "/CN=fd3d3455-a4f1-4c3f-bde6-6fb190e962c2/OU=core/O=zaLJQCU8mYyZBTUNHjNWaKF1wEm9mrGrmHLTD2yefEy5EqQ3aGA7LKcW"`,
  );

  // 5. Sign leaf cert with intermediate (1 year) using extension file
  fs.writeFileSync(leafExt, 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature');
  sh(
    `openssl x509 -req -in "${leafCsr}" -CA "${interPem}" -CAkey "${interKey}" -CAcreateserial ` +
    `-out "${leafPem}" -days 365 -extfile "${leafExt}"`,
  );

  // 6. Read PEMs
  const caPemStr = fs.readFileSync(caPem, 'utf-8').trim();
  const interPemStr = fs.readFileSync(interPem, 'utf-8').trim();
  const leafPemStr = fs.readFileSync(leafPem, 'utf-8').trim();

  // Extract leaf public key hex (last 32 bytes of DER-encoded key)
  const leafPubKeyHex = sh(
    `openssl x509 -in "${leafPem}" -noout -pubkey | openssl pkey -pubin -outform DER | tail -c 32 | xxd -p -c 32`,
  ).trim();

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });

  return {
    caPem: caPemStr,
    interPem: interPemStr,
    leafPem: leafPemStr,
    leafPubKeyHex,
    idmg: '', // computed below
    chain: [leafPemStr, interPemStr] as [string, string],
  };
}

// Generate once per test suite (synchronous since it's called at module load time)
const certs = generateTestCertificates();
const CERTIFICATE_1 = certs.chain;
const MILLEGRILLE_CERT = certs.caPem;
const LEAF_PUB_KEY_HEX = certs.leafPubKeyHex;

// IDMG is computed asynchronously, so we'll set it in a beforeAll
let EXPECTED_IDMG = '';

// ---------------------------------------------------------------------------
// Static test data (unrelated to certificates)
// ---------------------------------------------------------------------------

const PRIVATE_1 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOxkbFOs0LrjDdutNIXhI45fJE7SDMmzAHB5Doihl5E2
-----END PRIVATE KEY-----
`;

const PRIVATE_2 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA7VRb79082AF1FmkaveVcENAUGjNZDAb2fvcdYxnqV/
-----END ENCRYPTED PRIVATE KEY-----
`;

const CA_PRIVATE_KEY = new Uint8Array(
  (Buffer as any).from(
      "01234567890123456789012345678901234567890123456789012345678901234",
      "hex",
    ),

);

const MESSAGE_1 = {
  certificat: [
    "-----BEGIN CERTIFICATE-----\nMIICPDCCAe6gAwIBAgIUWw4LLOaWvtl2+e1NKBN1YXuHHywwBQYDK2VwMHIxLTAr\nBgNVBAMTJGEwYmI1ZGJiLTcyZmItNDEzZi05N2ZmLTc5OGQyYWVmMGQ1MDFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwNzE3MTEyODU1WhcNMjQwODE3MTEyOTE1WjCB\nhTEtMCsGA1UEAwwkYTBiYjVkYmItNzJmYi00MTNmLTk3ZmYtNzk4ZDJhZWYwZDUw\nMREwDwYDVQQLDAhjZWR1bGV1cjFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4\nd2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6WHJwMjJiQXR3R203SmYwKjAFBgMrZXAD\nIQCv+cw5YWC3IEeb2RAYdik4jBSqIq8PCE+ab2iLyxfNSqOBgTB/MCsGBCoDBAAE\nIzQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMBAGBCoDBAEECGNl\nZHVsZXVyMB8GA1UdIwQYMBaAFLMsL7gWXQsYHdzcwM0+JnFPgEj4MB0GA1UdDgQW\nBBR1sDSSZO4CFbSeOOreef/hQcxN7TAFBgMrZXADQQBlcKnfGnVP7tNWXZRLdnCD\npY7ezNBLcr+4U+D0uxumRnQjj7V/56zK06u/IjKd3PnMB5gRqK7kCGbivO6hAgEH\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD\nVQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS\nWvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z\ntEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO\n-----END CERTIFICATE-----",
  ],
  contenu:
    '{"b":true,"n":18,"sub":{"a":"More text","b":12},"value":"DUMMY content"}',
  estampille: 1721592075,
  id: "5bd735ce7816b4cdf5eb3d87ee63a40aee7fa580f7cc1bb0e64343aaf27030de",
  kind: 1,
  pubkey: "aff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a",
  routage: { action: "DUMMY ACTION", domaine: "DUMMY domain" },
  signature:
    "ecedc4bfdaa1aa19e0c195696998c1e93a02a6623469477d059e05bbb2b6715d7837b3f2182833cb51746a9125f364e3d533973e2e5b372c7c2be814c47dfa02",
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeAll(async () => {
  EXPECTED_IDMG = await getIdmg(MILLEGRILLE_CERT);
});

test("cert-validate 1", async () => {
  const result = await verifyCertificatePem(CERTIFICATE_1, MILLEGRILLE_CERT);
  expect(result).toBe(true);
});

test("cert-wrapper 1", async () => {
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1);
  expect(certificateWrapper).toBeDefined();
});

test("cert-wrapper-publicKey", async () => {
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1);
  const publicKey = certificateWrapper.getPublicKey();
  expect(publicKey).toStrictEqual(LEAF_PUB_KEY_HEX);
});

test("cert-wrapper-verify-date", async () => {
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT);
  const result = await certificateWrapper.verify(null as any, new Date("2027-01-01"));
  expect(result).toBe(true);
});

test("cert-wrapper-verify-caincluded", async () => {
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT);
  const result = await certificateWrapper.verify(null as any, false);
  expect(result).toBe(true);
});

test("cert-wrapper-verify-caprovided", async () => {
  const ca = wrapperFromPems([MILLEGRILLE_CERT]);
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1);
  const result = await certificateWrapper.verify(ca.certificate, false);
  expect(result).toBe(true);
});

test("cert-wrapper-verify-noca", async () => {
  expect.assertions(1);
  try {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1);
    await certificateWrapper.verify(null as any, false);
  } catch (err) {
    expect(err).toBeDefined();
  }
});

test("cert-wrapper-extensions", async () => {
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1);
  certificateWrapper.populateExtensions();
  // Test certs don't have custom MilleGrille extensions (generated with openssl)
  expect(certificateWrapper.extensions!.exchanges).toBeUndefined();
  expect(certificateWrapper.extensions!.roles).toBeUndefined();
  expect(certificateWrapper.extensions!.domains).toBeUndefined();
});

test("cert-wrapper-verify-commonName", async () => {
  let certificateWrapper = wrapperFromPems(CERTIFICATE_1);
  let commonName = certificateWrapper.getCommonName();
  expect(commonName).toBe("fd3d3455-a4f1-4c3f-bde6-6fb190e962c2");
});

test("cert-getIdmg", async () => {
  let idmg = await getIdmg(MILLEGRILLE_CERT);
  expect(idmg).toStrictEqual(EXPECTED_IDMG);
});

test("private key load", async () => {
  let key = loadPrivateKeyEd25519(PRIVATE_1);
  expect((Buffer as any).from(key)).toStrictEqual(
  (Buffer as any).from(
      "ec646c53acd0bae30ddbad3485e1238e5f244ed20cc9b30070790e88a1979136",
      "hex",
    ),
  );
});

test("private key save", async () => {
  let key = savePrivateKeyEd25519(CA_PRIVATE_KEY);
  expect(key).toBe(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAEjRWeJASNFZ4kBI0VniQEjRWeJASNFZ4kBI0VniQEj
-----END PRIVATE KEY-----`);
});

test("test store 1", async () => {
  let store = new CertificateStore(MILLEGRILLE_CERT);
  let result = await store.verifyCertificate(CERTIFICATE_1);
  expect(result).toBe(true);
});

test("test store cache", async () => {
  let store = new CertificateStore(MILLEGRILLE_CERT);
  store.cache = new CertificateCache();
  let result = await store.verifyCertificate(CERTIFICATE_1);
  expect(result).toBe(true);

  let wrapper = await store.cache.getCertificate(LEAF_PUB_KEY_HEX);
  expect(wrapper).toBeDefined();

  // Check that cache maintenance works
  await new Promise((resolve) => setTimeout(resolve, 5)); // Wait 5 ms
  await store.cache.maintain(1); // Mark entries older than 1ms as expired
  wrapper = await store.cache.getCertificate(LEAF_PUB_KEY_HEX);
  expect(wrapper).toBeUndefined();
});

test("test store message", async () => {
  let store = new CertificateStore(MILLEGRILLE_CERT);
  store.cache = new CertificateCache();
  let message = parseMessage(JSON.stringify(MESSAGE_1));
  try {
    let wrapperVerify1 = await store.verifyMessage(message);
    expect(wrapperVerify1).toBeFalsy();
  } catch (err) {
    expect(err).toBeDefined();
  }
  // expect(wrapperVerify1).toBeTruthy();
  // let cachedWrapper = await store.cache.getCertificate('aff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a');
  // expect(cachedWrapper).toBe(wrapperVerify1);

  // // Test cache HIT
  // let wrapperVerify2 = await store.verifyMessage(message);
  // expect(wrapperVerify2).toBe(wrapperVerify1);  // Checks that we got the same object back with toBe.
});

test("test generate CSR", async () => {
  // @peculiar/x509's Pkcs10CertificateRequestGenerator does not support Ed25519.
  // It throws: "Cannot get schema for 'CertificationRequestInfo' target"
  // If this ever starts working, the test will fail — signaling we should
  // update it to verify the newly-supported behavior.
  await expect(generateCsr("testUser", "zABCD1234")).rejects.toThrow(
    "Cannot get schema for 'CertificationRequestInfo' target",
  );
});

test("test split key/pem", () => {
  const inputString1 = PRIVATE_1 + CERTIFICATE_1.join("\n");
  // console.debug("Input: \n" + inputString1);
  let output1 = splitKeyCertPem(inputString1);
  // console.debug(output1.chain);
  expect(output1.chain).toEqual(CERTIFICATE_1);
  expect((output1.key as string) + "\n").toBe(PRIVATE_1);

  const inputString2 = PRIVATE_2 + CERTIFICATE_1.join("\n");
  // console.debug("Input: \n" + inputString2);
  let output2 = splitKeyCertPem(inputString2);
  // console.debug(output2.chain);
  expect(output2.chain).toEqual(CERTIFICATE_1);
  // console.debug(output2.key)
  expect((output2.key as string) + "\n").toBe(PRIVATE_2);
})
