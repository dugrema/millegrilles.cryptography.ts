import "reflect-metadata";
import { Buffer } from 'buffer';
// import * as x509 from "@peculiar/x509";
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

// Wire crytpo to work on node as in the browser
// const crypto = new Crypto();
// x509.cryptoProvider.set(crypto);

const CERTIFICATE_1 = [
  `-----BEGIN CERTIFICATE-----
MIICpDCCAlagAwIBAgIUDrIecGiOHbBFu1SyezbdqGolg28wBQYDK2VwMIGBMS0w
KwYDVQQDDCRmZDNkMzQ1NS1hNGYxLTRjM2YtYmRlNi02ZmIxOTBlOTYyYzIxDTAL
BgNVBAsMBGRldjExQTA/BgNVBAoMOHphTEpRQ1U4bVl5WkJUVU5Iak5XYUtGMXdF
bTltckdybUhMVEQyeWVmRXk1RXFRM2FHQTdMS2NXMB4XDTI2MDcxNzEwNDczMFoX
DTI2MDgxNzEwNDc1MFowgYExLTArBgNVBAMMJGZkM2QzNDU1LWE0ZjEtNGMzZi1i
ZGU2LTZmYjE5MGU5NjJjMjENMAsGA1UECwwEY29yZTFBMD8GA1UECgw4emFMSlFD
VThtWXlaQlRVTkhqTldhS0Yxd0VtOW1yR3JtSExURDJ5ZWZFeTVFcVEzYUdBN0xL
Y1cwKjAFBgMrZXADIQD1zK193whb7Hx8mj3JWAvLchGx247pxpKn+cIrNQJeVqOB
3TCB2jArBgQqAwQABCM0LnNlY3VyZSwzLnByb3RlZ2UsMi5wcml2ZSwxLnB1Ymxp
YzAMBgQqAwQBBARjb3JlMEwGBCoDBAIERENvcmVCYWNrdXAsQ29yZUNhdGFsb2d1
ZXMsQ29yZU1haXRyZURlc0NvbXB0ZXMsQ29yZVBraSxDb3JlVG9wb2xvZ2llMA8G
A1UdEQQIMAaCBGNvcmUwHwYDVR0jBBgwFoAUes4C9GF+PsOI3sjeac/FhUmhcZkw
HQYDVR0OBBYEFNdFfdZ9USEvjGlp94EPlDGE4iG+MAUGAytlcANBABcS3zOecijT
ciClLbC81e+HpwsJQtpVKSyKNFQnw7kn4N8IQanWSb4/Y/xzewQdSubINSRprFWI
+CoXWaRxcQ8=
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIIBzjCCAYCgAwIBAgIUasiODCs5UF1gEv9MUJFMXr+30e0wBQYDK2VwMCcxDTAL
BgNVBAMMBGRldjExFjAUBgNVBAoMDU1pbGxlR3JpbGxsZXMwHhcNMjYwNzE3MTA0
NzQzWhcNMjgwMTE1MTA0NzQzWjCBgTEtMCsGA1UEAwwkZmQzZDM0NTUtYTRmMS00
YzNmLWJkZTYtNmZiMTkwZTk2MmMyMQ0wCwYDVQQLDARkZXYxMUEwPwYDVQQKDDh6
YUxKUUNVOG1ZeVpCVFVOSGpOV2FLRjF3RW05bXJHcm1ITFREMnllZkV5NUVxUTNh
R0E3TEtjVzAqMAUGAytlcAMhACjEB4twcM8Juuf2n/HkriyJXgdcF/GraW/NtkhH
cPLZo2MwYTALBgNVHQ8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
FgQUes4C9GF+PsOI3sjeac/FhUmhcZkwHwYDVR0jBBgwFoAU7aDBOZ2i81ujBRrl
NJgI8npO0fowBQYDK2VwA0EAhcd7osn4wRKCI8qccj4dkQ15dVbeTSFXz6hsCxxt
aS103Trwx/Qr1YsmkgVcBlH0pTRDpKfsJpG7IFsMM4nbDA==
-----END CERTIFICATE-----`,
];

const PRIVATE_1 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOxkbFOs0LrjDdutNIXhI45fJE7SDMmzAHB5Doihl5E2
-----END PRIVATE KEY-----
`;

const PRIVATE_2 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA7VRb79082AF1FmkaveVcENAUGjNZDAb2fvcdYxnqV/
-----END ENCRYPTED PRIVATE KEY-----
`;

const MILLEGRILLE_CERT = `-----BEGIN CERTIFICATE-----
MIIBcDCCASKgAwIBAgIUNzEsSqTcgn9Ho+Ie6mhQg5uLe/kwBQYDK2VwMCcxDTAL
BgNVBAMMBGRldjExFjAUBgNVBAoMDU1pbGxlR3JpbGxsZXMwHhcNMjYwNzE3MTA0
NzQzWhcNNDYwNzEyMTA0NzQzWjAnMQ0wCwYDVQQDDARkZXYxMRYwFAYDVQQKDA1N
aWxsZUdyaWxsbGVzMCowBQYDK2VwAyEAL8ZbpltklpzCnbi7+YtWqCjIM8sXXy+a
iVp6SaEKYWejYDBeMAsGA1UdDwQEAwIC5DAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBTtoME5naLzW6MFGuU0mAjyek7R+jAfBgNVHSMEGDAWgBTtoME5naLzW6MF
GuU0mAjyek7R+jAFBgMrZXADQQAMsJnxO6Zzrj7adifPgdfJCqnCK7KhLQXclxrQ
dSbP42pSZHEXVrKsRwqkkI+g87QFgBQcCmQhyeXeKnS/MZgE
-----END CERTIFICATE-----`;

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
  expect(publicKey).toStrictEqual(
    "f5ccad7ddf085bec7c7c9a3dc9580bcb7211b1db8ee9c692a7f9c22b35025e56",
  );
});

test("cert-wrapper-verify-date", async () => {
  const certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT);
  const result = await certificateWrapper.verify(null as any, new Date("2026-07-18"));
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
  expect(certificateWrapper.extensions!.exchanges).toStrictEqual([
    "4.secure",
    "3.protege",
    "2.prive",
    "1.public",
  ]);
  expect(certificateWrapper.extensions!.roles).toStrictEqual(["core"]);
  expect(certificateWrapper.extensions!.domains).toStrictEqual([
    "CoreBackup",
    "CoreCatalogues",
    "CoreMaitreDesComptes",
    "CorePki",
    "CoreTopologie",
  ]);
});

test("cert-wrapper-verify-commonName", async () => {
  let certificateWrapper = wrapperFromPems(CERTIFICATE_1);
  let commonName = certificateWrapper.getCommonName();
  expect(commonName).toBe("fd3d3455-a4f1-4c3f-bde6-6fb190e962c2");
});

test("cert-getIdmg", async () => {
  let idmg = await getIdmg(MILLEGRILLE_CERT);
  expect(idmg).toStrictEqual(
    "zaLJQCU8mYyZBTUNHjNWaKF1wEm9mrGrmHLTD2yefEy5EqQ3aGA7LKcW",
  );
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

  let wrapper = await store.cache.getCertificate(
    "f5ccad7ddf085bec7c7c9a3dc9580bcb7211b1db8ee9c692a7f9c22b35025e56",
  );
  expect(wrapper).toBeDefined();

  // Check that cache maintenance works
  await new Promise((resolve) => setTimeout(resolve, 5)); // Wait 5 ms
  await store.cache.maintain(1); // Mark entries older than 1ms as expired
  wrapper = await store.cache.getCertificate(
    "f5ccad7ddf085bec7c7c9a3dc9580bcb7211b1db8ee9c692a7f9c22b35025e56",
  );
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
  let csrResult = await generateCsr("testUser", "zABCD1234");
  // console.debug("CSR\n%s", csrResult.csr);
  expect(typeof csrResult.csr).toBe("string");
  expect(csrResult.keys).toBeDefined();

  // Extract private key
  let privateKeyJwk = await crypto.subtle.exportKey(
    "jwk",
    csrResult.keys.privateKey,
  );
  let privateBytes = decodeBase64Url(privateKeyJwk.d as string);
  expect(privateBytes).toBeDefined();
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
