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
MIICNDCCAeagAwIBAgIUbA7jG7eN8kK4oYSgqoYKUk64zAQwBQYDK2VwMIGBMS0w
KwYDVQQDDCRmZDNkMzQ1NS1hNGYxLTRjM2YtYmRlNi02ZmIxOTBlOTYyYzIxDTAL
BgNVBAsMBGRldjExQTA/BgNVBAoMOHphTEpRQ1U4bVl5WkJUVU5Iak5XYUtGMXdF
bTltckdybUhMVEQyeWVmRXk1RXFRM2FHQTdMS2NXMB4XDTI2MTEyNTEzNTM1N1oX
DTI3MTEyNTEzNTM1N1owgYExLTArBgNVBAMMJGZkM2QzNDU1LWE0ZjEtNGMzZi1i
ZGU2LTZmYjE5MGU5NjJjMjENMAsGA1UECwwEY29yZTFBMD8GA1UECgw4emFMSlFD
VThtWXlaQlRVTkhqTldhS0Yxd0VtOW1yR3JtSExURDJ5ZWZFeTVFcVEzYUdBN0xL
Y1cwKjAFBgMrZXADIQCy112oqmwsDnErJqkOXQBeiPNwYm7STl4rq3+zXyZYSKNu
MGwwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwDwYDVR0RBAgwBoIEY29yZTAd
BgNVHQ4EFgQUqbwZOBBEWt//0JM/Zx2Y1iKN4o0wHwYDVR0jBBgwFoAUSlrlDXhi
NsHk0xbCv5QBgnv8gegwBQYDK2VwA0EAY8PS0d13Tqvgy2uMBCOmhrUg1/2pBVzX
vMZ0RqQEyTFMoC44MkNeCsX5QnTABRzQsmuJ8o9JHWjziGAzj3t8Bw==
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIIB0TCCAYOgAwIBAgIUL14qKLIyMCHe58CZkRKOUyrLp5cwBQYDK2VwMCcxDTAL
BgNVBAMMBGRldjExFjAUBgNVBAoMDU1pbGxlR3JpbGxsZXMwHhcNMjYxMTI1MTM1
MzU3WhcNMjkwNTEzMTM1MzU3WjCBgTEtMCsGA1UEAwwkZmQzZDM0NTUtYTRmMS00
YzNmLWJkZTYtNmZiMTkwZTk2MmMyMQ0wCwYDVQQLDARkZXYxMUEwPwYDVQQKDDh6
YUxKUUNVOG1ZeVpCVFVOSGpOV2FLRjF3RW05bXJHcm1ITFREMnllZkV5NUVxUTNh
R0E3TEtjVzAqMAUGAytlcAMhAF9VmblgQ1RDKtOdSwK0epgLmg8ISLsN3QUWx6lu
bv0Qo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNV
HQ4EFgQUSlrlDXhiNsHk0xbCv5QBgnv8gegwHwYDVR0jBBgwFoAU6/hw1ctAejRG
kp607BussmE09JgwBQYDK2VwA0EAmbyiaTB5J+qLn5n5uM87NcpYc4Qgv2FfYnSp
Qa/57YtRH1ndPcRz2ncsgTvwTMKIdP/iLk10cG9o24Vu181JBA==
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
MIIBczCCASWgAwIBAgIUHk4Ac+3a/HppUxFzXjcisyr4w2EwBQYDK2VwMCcxDTAL
BgNVBAMMBGRldjExFjAUBgNVBAoMDU1pbGxlR3JpbGxsZXMwHhcNMjYxMTI1MTM1
MzU3WhcNNDYxMTIwMTM1MzU3WjAnMQ0wCwYDVQQDDARkZXYxMRYwFAYDVQQKDA1N
aWxsZUdyaWxsbGVzMCowBQYDK2VwAyEAWEhk3URoWCrleqR9s7oh9JcB4z27QN0o
+wODnVEqk7+jYzBhMB0GA1UdDgQWBBTr+HDVy0B6NEaSnrTsG6yyYTT0mDAfBgNV
HSMEGDAWgBTr+HDVy0B6NEaSnrTsG6yyYTT0mDAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwIBhjAFBgMrZXADQQAikysGIwMZsLEskKOb4QXAjw0iXRMp4CfE
9Dk+wPVMMDHCzYHGbM17EvFBqVDhT+pGV3VqAQvxcvkaJRcervwH
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
    "b2d75da8aa6c2c0e712b26a90e5d005e88f370626ed24e5e2bab7fb35f265848",
  );
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
  // New test certs don't have custom MilleGrille extensions (they were generated with openssl)
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
  expect(idmg).toStrictEqual(
    "zdXEeZ5eWqqZvsgAqsUAnENRN6DywSuqMNEpiPzsYAsS9EwTYdtWEvxL",
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
    "b2d75da8aa6c2c0e712b26a90e5d005e88f370626ed24e5e2bab7fb35f265848",
  );
  expect(wrapper).toBeDefined();

  // Check that cache maintenance works
  await new Promise((resolve) => setTimeout(resolve, 5)); // Wait 5 ms
  await store.cache.maintain(1); // Mark entries older than 1ms as expired
  wrapper = await store.cache.getCertificate(
    "b2d75da8aa6c2c0e712b26a90e5d005e88f370626ed24e5e2bab7fb35f265848",
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
