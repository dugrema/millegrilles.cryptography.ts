// import * as x509 from "@peculiar/x509";
// import { Crypto } from "@peculiar/webcrypto";
import { verifyCertificatePem, wrapperFromPems, getIdmg, loadPrivateKeyEd25519, savePrivateKeyEd25519, CertificateStore, CertificateCache, generateCsr } from "../lib/certificates";
import { decodeBase64Url } from "../lib/multiencoding";
import { parseMessage } from "../lib/messageStruct";

// Wire crytpo to work on node as in the browser
// const crypto = new Crypto();
// x509.cryptoProvider.set(crypto);

const CERTIFICATE_1 = [
    `-----BEGIN CERTIFICATE-----
MIIClDCCAkagAwIBAgIUPJ9UyAgoQK6GGfOOqtPzA9X10IkwBQYDK2VwMHIxLTAr
BgNVBAMTJGM3YjAxMWVhLTU4OTEtNGYxNS04MTJmLWRlMTU3MThjZDMyODFBMD8G
A1UEChM4emJhVGVNRlhwdnVBTEdjUEx4N1VZRmpXMm9DejhmYkRweXlzZTVib1pC
MjJWWDhOdlNRZk1hU1IwHhcNMjUwOTEzMTQzMzE2WhcNMjUxMDE0MTQzMzM2WjCB
gTEtMCsGA1UEAwwkYzdiMDExZWEtNTg5MS00ZjE1LTgxMmYtZGUxNTcxOGNkMzI4
MQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6YmFUZU1GWHB2dUFMR2NQTHg3VVlG
alcyb0N6OGZiRHB5eXNlNWJvWkIyMlZYOE52U1FmTWFTUjAqMAUGAytlcAMhAA5R
N+8MvRJWMS91VPPMLhsDLYMLMd1jZO1ZLwq1WWk2o4HdMIHaMCsGBCoDBAAEIzQu
c2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw
TAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz
Q29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf
BgNVHSMEGDAWgBSkiEVOBHw4BDMATf5m8kbDtIXsNTAdBgNVHQ4EFgQUKkURQLUq
SdklMeJ4zLgLR5iDLIowBQYDK2VwA0EAXv2ditgs0bVpcYUNg/aT8IGmwoiD/407
hchly9/o2HxPMJBKf5Z2bfOynqQoQOcBJlImhkLZ1xA2NG9De2xyAA==
-----END CERTIFICATE-----`,
`-----BEGIN CERTIFICATE-----
MIIBozCCAVWgAwIBAgIKCBGDUQdmCYdJEjAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
bGVHcmlsbGUwHhcNMjUwODIwMTQzMjI3WhcNMjcwMzAxMTQzMjI3WjByMS0wKwYD
VQQDEyRjN2IwMTFlYS01ODkxLTRmMTUtODEyZi1kZTE1NzE4Y2QzMjgxQTA/BgNV
BAoTOHpiYVRlTUZYcHZ1QUxHY1BMeDdVWUZqVzJvQ3o4ZmJEcHl5c2U1Ym9aQjIy
Vlg4TnZTUWZNYVNSMCowBQYDK2VwAyEAS7ZZZYh6E3/klnr3wiSw+qKeebazldAg
rD5Et1QsQMqjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
A1UdDgQWBBSkiEVOBHw4BDMATf5m8kbDtIXsNTAfBgNVHSMEGDAWgBRga8F75mOH
5uZ1uWVsFBxVcZ8qiDAFBgMrZXADQQB6dY4hMUmonPd4KDo4u4Ps7OkMyNb3StyY
Z556Icqp1B+0/5CRxusDnjJU5zqCKRHDjqjf3DKz7ui0HeWiOt0I
-----END CERTIFICATE-----`
]

const PRIVATE_1 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA7VRb79082AF1FmkaveVcENAUGjNZDAb2fvcdYxnqV/
-----END PRIVATE KEY-----
`

const MILLEGRILLE_CERT = `-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoXGIiSN1JwgpUSMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yNDA3MTMyMDMwMDFaFw00NDA3MTMyMDMwMDFaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAsJIE69qSt+GKywKsu/3LU31FkowZ
W5OSgvDFQ34PkKGjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBRga8F75mOH5uZ1uWVsFBxVcZ8qiDAfBgNVHSMEGDAWgBRga8F75mOH
5uZ1uWVsFBxVcZ8qiDAFBgMrZXADQQAlt1NbEwEIOJi+qprkQp8GOmdvn+hQsM2R
RftTlHVzaecD36Ia4rItgfqOmJp9w925MwQibK0Z86mOXXTiyTkE
-----END CERTIFICATE-----`;

const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

const MESSAGE_1 = {"certificat":["-----BEGIN CERTIFICATE-----\nMIICPDCCAe6gAwIBAgIUWw4LLOaWvtl2+e1NKBN1YXuHHywwBQYDK2VwMHIxLTAr\nBgNVBAMTJGEwYmI1ZGJiLTcyZmItNDEzZi05N2ZmLTc5OGQyYWVmMGQ1MDFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwNzE3MTEyODU1WhcNMjQwODE3MTEyOTE1WjCB\nhTEtMCsGA1UEAwwkYTBiYjVkYmItNzJmYi00MTNmLTk3ZmYtNzk4ZDJhZWYwZDUw\nMREwDwYDVQQLDAhjZWR1bGV1cjFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4\nd2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6WHJwMjJiQXR3R203SmYwKjAFBgMrZXAD\nIQCv+cw5YWC3IEeb2RAYdik4jBSqIq8PCE+ab2iLyxfNSqOBgTB/MCsGBCoDBAAE\nIzQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMBAGBCoDBAEECGNl\nZHVsZXVyMB8GA1UdIwQYMBaAFLMsL7gWXQsYHdzcwM0+JnFPgEj4MB0GA1UdDgQW\nBBR1sDSSZO4CFbSeOOreef/hQcxN7TAFBgMrZXADQQBlcKnfGnVP7tNWXZRLdnCD\npY7ezNBLcr+4U+D0uxumRnQjj7V/56zK06u/IjKd3PnMB5gRqK7kCGbivO6hAgEH\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD\nVQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS\nWvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z\ntEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO\n-----END CERTIFICATE-----"],"contenu":"{\"b\":true,\"n\":18,\"sub\":{\"a\":\"More text\",\"b\":12},\"value\":\"DUMMY content\"}","estampille":1721592075,"id":"5bd735ce7816b4cdf5eb3d87ee63a40aee7fa580f7cc1bb0e64343aaf27030de","kind":1,"pubkey":"aff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a","routage":{"action":"DUMMY ACTION","domaine":"DUMMY domain"},"signature":"ecedc4bfdaa1aa19e0c195696998c1e93a02a6623469477d059e05bbb2b6715d7837b3f2182833cb51746a9125f364e3d533973e2e5b372c7c2be814c47dfa02"};

test('cert-validate 1', async () => {
    const result = await verifyCertificatePem(CERTIFICATE_1, MILLEGRILLE_CERT)
    expect(result).toBe(true)
});

test('cert-wrapper 1', async () => {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    expect(certificateWrapper).toBeDefined()
});

test('cert-wrapper-publicKey', async () => {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    const publicKey = certificateWrapper.getPublicKey()
    expect(publicKey).toStrictEqual('0e5137ef0cbd1256312f7554f3cc2e1b032d830b31dd6364ed592f0ab5596936')
});

test('cert-wrapper-verify-date', async () => {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT)
    const result = await certificateWrapper.verify(null, new Date('2025-10-14'))
    expect(result).toBe(true)
});

test('cert-wrapper-verify-caincluded', async () => {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT)
    const result = await certificateWrapper.verify(null, false)
    expect(result).toBe(true)
});

test('cert-wrapper-verify-caprovided', async () => {
    const ca = wrapperFromPems([MILLEGRILLE_CERT])
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    const result = await certificateWrapper.verify(ca.certificate, false)
    expect(result).toBe(true)
});

test('cert-wrapper-verify-noca', async () => {
    expect.assertions(1)
    try {
        const certificateWrapper = wrapperFromPems(CERTIFICATE_1)
        await certificateWrapper.verify(null, false)
    } catch(err) {
        expect(err).toBeDefined()
    }
});

test('cert-wrapper-extensions', async () => {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    certificateWrapper.populateExtensions()
    expect(certificateWrapper.extensions.exchanges).toStrictEqual(['4.secure', '3.protege', '2.prive', '1.public'])
    expect(certificateWrapper.extensions.roles).toStrictEqual(['core'])
    expect(certificateWrapper.extensions.domains).toStrictEqual(['CoreBackup', 'CoreCatalogues', 'CoreMaitreDesComptes', 'CorePki', 'CoreTopologie'])
});

test('cert-wrapper-verify-commonName', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let commonName = certificateWrapper.getCommonName()
    expect(commonName).toBe('c7b011ea-5891-4f15-812f-de15718cd328')
});

test('cert-getIdmg', async () => {
    let idmg = await getIdmg(MILLEGRILLE_CERT)
    expect(idmg).toStrictEqual('zbaTeMFXpvuALGcPLx7UYFjW2oCz8fbDpyyse5boZB22VX8NvSQfMaSR')
})

test('private key load', async() => {
    let key = loadPrivateKeyEd25519(PRIVATE_1);
    expect(Buffer.from(key))
        .toStrictEqual(Buffer.from('0ed545befdd3cd8017516691abde55c10d0141a33590c06f67ef71d6319ea57f', 'hex'));
})

test('private key save', async () => {
    let key = savePrivateKeyEd25519(CA_PRIVATE_KEY);
    expect(key).toBe(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAEjRWeJASNFZ4kBI0VniQEjRWeJASNFZ4kBI0VniQEj
-----END PRIVATE KEY-----`);
})


test('test store 1', async ()=>{
    let store = new CertificateStore(MILLEGRILLE_CERT);
    let result = await store.verifyCertificate(CERTIFICATE_1);
    expect(result).toBe(true);
})

test('test store cache', async ()=>{
    let store = new CertificateStore(MILLEGRILLE_CERT);
    store.cache = new CertificateCache();
    let result = await store.verifyCertificate(CERTIFICATE_1);
    expect(result).toBe(true);

    let wrapper = await store.cache.getCertificate('0e5137ef0cbd1256312f7554f3cc2e1b032d830b31dd6364ed592f0ab5596936');
    expect(wrapper).toBeDefined();

    // Check that cache maintenance works
    await new Promise(resolve=>setTimeout(resolve, 5));  // Wait 5 ms
    await store.cache.maintain(1);  // Mark entries older than 1ms as expired
    wrapper = await store.cache.getCertificate('0e5137ef0cbd1256312f7554f3cc2e1b032d830b31dd6364ed592f0ab5596936');
    expect(wrapper).toBeUndefined();
})

test('test store message', async ()=>{
    let store = new CertificateStore(MILLEGRILLE_CERT);
    store.cache = new CertificateCache();
    let message = parseMessage(JSON.stringify(MESSAGE_1));
    try {
        let wrapperVerify1 = await store.verifyMessage(message);
        expect(wrapperVerify1).toBeFalsy();
    } catch(err) {
        expect(err).toBeDefined();
    }
    // expect(wrapperVerify1).toBeTruthy();
    // let cachedWrapper = await store.cache.getCertificate('aff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a');
    // expect(cachedWrapper).toBe(wrapperVerify1);

    // // Test cache HIT
    // let wrapperVerify2 = await store.verifyMessage(message);
    // expect(wrapperVerify2).toBe(wrapperVerify1);  // Checks that we got the same object back with toBe.
})

test('test generate CSR', async ()=>{
    let csrResult = await generateCsr('testUser', 'zABCD1234');
    // console.debug("CSR\n%s", csrResult.csr);
    expect(typeof(csrResult.csr)).toBe('string');
    expect(csrResult.keys).toBeDefined();

    // Extract private key
    let privateKeyJwk = await crypto.subtle.exportKey('jwk', csrResult.keys.privateKey);
    let privateBytes = decodeBase64Url(privateKeyJwk.d);
    expect(privateBytes).toBeDefined();
})
