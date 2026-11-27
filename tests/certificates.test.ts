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
  verifyCsr,
  splitKeyCertPem,
  splitCertificatePems,
} from "../lib/certificates";
import { generateKeypairEd5519 } from "../lib/ed25519";
import { decodeBase64Url, encodeHex } from "../lib/multiencoding";
import { parseMessage, MilleGrillesMessage } from "../lib/messageStruct";

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

// Formats a Date as OpenSSL's [CC]YYMMDDHHMMSSZ (UTC) for -not_before/-not_after.
function utcCompact(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    String(d.getUTCFullYear()) +
    p(d.getUTCMonth() + 1) +
    p(d.getUTCDate()) +
    p(d.getUTCHours()) +
    p(d.getUTCMinutes()) +
    p(d.getUTCSeconds()) +
    "Z"
  );
}

/**
 * Mints a CA (valid now) plus a leaf certificate that is already EXPIRED
 * (its whole validity window is in the past). Used to confirm expired chains
 * are rejected by default and only accepted via a trusted explicit date.
 */
function generateExpiredLeaf(): {
  caPem: string;
  leafPem: string;
  leafPubKeyHex: string;
  expiredWindow: Date;
} {
  const DAY = 86400_000;
  const now = Date.now();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mg-expired-"));
  const sh = (cmd: string): string => {
    try {
      return execSync(`/bin/bash -c "${cmd.replace(/"/g, '\\"')}"`, {
        encoding: "utf-8",
      });
    } catch (e: any) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      throw new Error(`shell command failed: ${e.stderr || e.message}`);
    }
  };

  const caKey = path.join(tmpDir, "ca.key");
  const caPem = path.join(tmpDir, "ca.pem");
  const leafKey = path.join(tmpDir, "leaf.key");
  const leafCsr = path.join(tmpDir, "leaf.csr");
  const leafPem = path.join(tmpDir, "leaf.pem");
  const leafExt = path.join(tmpDir, "leaf.ext");

  // CA valid from well before the leaf's (past) window through +10 years, so it
  // both signs the leaf and itself passes a historical date-based validation.
  sh(`openssl genpkey -algorithm ED25519 -out "${caKey}"`);
  sh(
    `openssl req -x509 -key "${caKey}" -out "${caPem}" ` +
      `-not_before "${utcCompact(new Date(now - 1000 * DAY))}" ` +
      `-not_after "${utcCompact(new Date(now + 3650 * DAY))}" ` +
      `-subj "/CN=expired-test-CA/O=MilleGrilles" ` +
      `-addext "basicConstraints=critical,CA:TRUE" ` +
      `-addext "keyUsage=critical,keyCertSign,cRLSign"`,
  );

  // Leaf valid entirely in the past: [-730d, -365d], i.e. expired ~6 months ago.
  const notBefore = new Date(now - 730 * DAY);
  const notAfter = new Date(now - 365 * DAY);
  sh(`openssl genpkey -algorithm ED25519 -out "${leafKey}"`);
  sh(
    `openssl req -new -key "${leafKey}" -out "${leafCsr}" -subj "/CN=expired-leaf/O=MilleGrilles"`,
  );
  fs.writeFileSync(
    leafExt,
    "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature",
  );
  sh(
    `openssl x509 -req -in "${leafCsr}" -CA "${caPem}" -CAkey "${caKey}" -CAcreateserial ` +
      `-out "${leafPem}" -extfile "${leafExt}" ` +
      `-not_before "${utcCompact(notBefore)}" -not_after "${utcCompact(notAfter)}"`,
  );

  const leafPubKeyHex = sh(
    `openssl x509 -in "${leafPem}" -noout -pubkey | openssl pkey -pubin -outform DER | tail -c 32 | xxd -p -c 32`,
  ).trim();

  const caPemStr = fs.readFileSync(caPem, "utf-8").trim();
  const leafPemStr = fs.readFileSync(leafPem, "utf-8").trim();
  fs.rmSync(tmpDir, { recursive: true, force: true });

  // A moment inside the leaf's (past) validity window, for the trusted-restore path.
  const expiredWindow = new Date((notBefore.getTime() + notAfter.getTime()) / 2);

  return { caPem: caPemStr, leafPem: leafPemStr, leafPubKeyHex, expiredWindow };
}

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
  let key = await loadPrivateKeyEd25519(PRIVATE_1);
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

// CSR produced by the old node-forge fork: Ed25519, CN=tata12, no extensions.
const FORGE_CSR_PEM = `-----BEGIN CERTIFICATE REQUEST-----
MIGQMEQCAQAwETEPMA0GA1UEAxMGdGF0YTEyMCowBQYDK2VwAyEAFgJht7oBV33G
U6r9f2T0dFIWBEzpFuaujOyBFMPutQCgADAFBgMrZXADQQDo03USNpkEPnx/Mp5i
GeJe88teA3NtqDVdpey6ztO+KTNJR9hMhHnXC9YupGJsaVFDAYrrrPwtW+QFEq15
ObsE
-----END CERTIFICATE REQUEST-----`;

test("test generate CSR", async () => {
  const result = await generateCsr("testUser", "zABCD1234");
  const { csr, privateKeyPem, privateKey, publicKey } = result;

  expect(csr).toContain("-----BEGIN CERTIFICATE REQUEST-----");
  expect(privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
  expect(privateKey.length).toBe(32);
  expect(publicKey.length).toBe(32);

  // The CSR must be self-consistent: its signature validates, and its public key
  // must be the one derived from the private key we handed back.
  const verified = await verifyCsr(csr);
  expect(verified.commonName).toBe("testUser");
  expect(verified.userId).toBe("zABCD1234");
  expect(verified.publicKeyHex).toBe(encodeHex(publicKey));
  expect(encodeHex((await generateKeypairEd5519(privateKey)).public)).toBe(
    verified.publicKeyHex,
  );

  // Same key material through the PEM, which is what consumers persist.
  expect(encodeHex(await loadPrivateKeyEd25519(privateKeyPem))).toBe(
    encodeHex(privateKey),
  );
});

test("test generate CSR without a userId", async () => {
  const verified = await verifyCsr((await generateCsr("soloUser")).csr);
  expect(verified.commonName).toBe("soloUser");
  expect(verified.userId).toBeUndefined();
});

test("verify a CSR written by another tool", async () => {
  const verified = await verifyCsr(FORGE_CSR_PEM);
  expect(verified.commonName).toBe("tata12");
  expect(verified.userId).toBeUndefined();
});

test("reject a tampered CSR", async () => {
  const { csr } = await generateCsr("testUser", "zABCD1234");
  const lines = csr.split("\n");
  // Flip one bit in the middle of the base64 body: this corrupts the CSR's
  // self-signature (or the structure itself), and either way must not verify.
  const bodyIndex = lines.length - 2;
  const mutated = "A" === lines[bodyIndex][10] ? "B" : "A";
  lines[bodyIndex] =
    lines[bodyIndex].substring(0, 10) + mutated + lines[bodyIndex].substring(11);
  await expect(verifyCsr(lines.join("\n"))).rejects.toThrow();
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

// ---------------------------------------------------------------------------
// Security: certificate validity handling (#20 and L1)
// ---------------------------------------------------------------------------

describe("cert validity handling (#20, L1)", () => {
  const expired = generateExpiredLeaf();

  // store.verifyMessage only validates the chain + pubkey match (no message
  // signature check), so a synthetic message with the matching pubkey is enough.
  function messageFor(pubkey: string, pems: string[], estampille: number) {
    const m = new MilleGrillesMessage(estampille, 0, "payload");
    m.pubkey = pubkey;
    m.certificat = pems;
    return m;
  }

  test("#20 expired chain rejected by default even with backdated estampille", async () => {
    const store = new CertificateStore(expired.caPem);
    // Attacker backdates estampille into the expired leaf's old validity window.
    const msg = messageFor(
      expired.leafPubKeyHex,
      [expired.leafPem],
      Math.floor(expired.expiredWindow.getTime() / 1000),
    );
    await expect(store.verifyMessage(msg)).rejects.toThrow();
  });

  test("#20 expired chain accepted only when a trusted validateAt is supplied", async () => {
    const store = new CertificateStore(expired.caPem);
    const msg = messageFor(expired.leafPubKeyHex, [expired.leafPem], 0);
    const wrapper = await store.verifyMessage(msg, {
      validateAt: expired.expiredWindow,
    });
    expect(wrapper).toBeDefined();
  });

  test("#20 validateAt still enforces the validity window", async () => {
    const store = new CertificateStore(expired.caPem);
    const msg = messageFor(expired.leafPubKeyHex, [expired.leafPem], 0);
    // Trusted caller passing an explicit date still cannot escape an out-of-
    // window date; the opt-in does not mean "skip expiry".
    await expect(
      store.verifyMessage(msg, { validateAt: new Date(0) }),
    ).rejects.toThrow();
  });

  test("#20 verifyMessage validates against the clock, not message.estampille", async () => {
    const store = new CertificateStore(MILLEGRILLE_CERT);
    // Currently-valid chain but an estampille in 1970: the old code validated
    // against estampille (and would reject); the new code validates against now.
    const msg = messageFor(LEAF_PUB_KEY_HEX, CERTIFICATE_1, 0);
    const wrapper = await store.verifyMessage(msg);
    expect(wrapper).toBeDefined();
  });

  test("L1 date:false truly skips validity checks", async () => {
    // Expired leaf: a Date at now fails, but false skips and succeeds.
    await expect(
      verifyCertificatePem([expired.leafPem], expired.caPem, new Date()),
    ).rejects.toThrow();
    const ok = await verifyCertificatePem([expired.leafPem], expired.caPem, false);
    expect(ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Security: PEM splitting preserves complete certificate blocks (#10)
// ---------------------------------------------------------------------------

describe("splitCertificatePems (#10)", () => {
  const joined = CERTIFICATE_1.join("\n");

  test("single PEM returns one intact block", () => {
    const blocks = splitCertificatePems(CERTIFICATE_1[0]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toBe(CERTIFICATE_1[0]);
  });

  test("multiple PEMs split into self-contained blocks (BEGIN preserved)", () => {
    const blocks = splitCertificatePems(joined);
    expect(blocks).toHaveLength(2);
    // Every block carries both headers, so each is parseable on its own.
    for (const block of blocks) {
      expect(block.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
      expect(block.endsWith("-----END CERTIFICATE-----")).toBe(true);
    }
    expect(blocks).toEqual(CERTIFICATE_1);
  });

  test("surrounding prose and a stray END marker do not corrupt blocks", () => {
    // Leading text (including an END marker mentioned in prose) must not turn
    // the first block into a malformed fragment.
    const messy =
      "Here is the chain (a block ends with -----END CERTIFICATE-----):\n" +
      joined +
      "\n-- end of transmission --\n";
    const blocks = splitCertificatePems(messy);
    expect(blocks).toEqual(CERTIFICATE_1);
  });

  test("split blocks are parseable by the certificate wrapper", () => {
    const blocks = splitCertificatePems(joined);
    const wrapper = wrapperFromPems(blocks);
    expect(wrapper.getPublicKey()).toBe(LEAF_PUB_KEY_HEX);
  });

  test("empty input yields an empty array", () => {
    expect(splitCertificatePems("")).toEqual([]);
    expect(splitCertificatePems("no certificates here")).toEqual([]);
  });
});
