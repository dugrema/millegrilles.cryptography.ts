import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
import { verifyCertificatePem, wrapperFromPems, getIdmg, loadPrivateKeyEd25519, savePrivateKeyEd25519, CertificateStore, CertificateCache } from "../lib/certificates"
import { parseMessage } from "../lib/messageStruct";

// Wire crytpo to work on node as in the browser
const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const CERTIFICATE_1 = [
    `-----BEGIN CERTIFICATE-----
MIIClDCCAkagAwIBAgIUXC5AOCMbTbgN7iWKOvw+1hkamokwBQYDK2VwMHIxLTAr
BgNVBAMTJGEwYmI1ZGJiLTcyZmItNDEzZi05N2ZmLTc5OGQyYWVmMGQ1MDFBMD8G
A1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6
WHJwMjJiQXR3R203SmYwHhcNMjQwNzE3MTEyOTAwWhcNMjQwODE3MTEyOTIwWjCB
gTEtMCsGA1UEAwwkYTBiYjVkYmItNzJmYi00MTNmLTk3ZmYtNzk4ZDJhZWYwZDUw
MQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG
dUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhAEqc
7fRapdAmnekGqMtaaSZhZo7thm3juJcU9hwEqpwEo4HdMIHaMCsGBCoDBAAEIzQu
c2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw
TAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz
Q29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf
BgNVHSMEGDAWgBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAdBgNVHQ4EFgQUL6rsDhKr
NXHN8NWdaT65cl5uUjcwBQYDK2VwA0EAGnb5qFGWVnqAeUg8oteXE3m8+oYKuzlI
pjrYag3mY79CtvnWZ1H6h9JLfDRl4j5S2i8D1ywxrbg8wBULD0ucDg==
-----END CERTIFICATE-----`,
`-----BEGIN CERTIFICATE-----
MIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
bGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD
VQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV
BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS
WvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
A1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z
tEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO
-----END CERTIFICATE-----`
]

const PRIVATE_1 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA7VRb79082AF1FmkaveVcENAUGjNZDAb2fvcdYxnqV/
-----END PRIVATE KEY-----`

const MILLEGRILLE_CERT = `-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
-----END CERTIFICATE-----`;

const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

const MESSAGE_1 = {"certificate":["-----BEGIN CERTIFICATE-----\nMIICPDCCAe6gAwIBAgIUWw4LLOaWvtl2+e1NKBN1YXuHHywwBQYDK2VwMHIxLTAr\nBgNVBAMTJGEwYmI1ZGJiLTcyZmItNDEzZi05N2ZmLTc5OGQyYWVmMGQ1MDFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwNzE3MTEyODU1WhcNMjQwODE3MTEyOTE1WjCB\nhTEtMCsGA1UEAwwkYTBiYjVkYmItNzJmYi00MTNmLTk3ZmYtNzk4ZDJhZWYwZDUw\nMREwDwYDVQQLDAhjZWR1bGV1cjFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4\nd2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6WHJwMjJiQXR3R203SmYwKjAFBgMrZXAD\nIQCv+cw5YWC3IEeb2RAYdik4jBSqIq8PCE+ab2iLyxfNSqOBgTB/MCsGBCoDBAAE\nIzQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMBAGBCoDBAEECGNl\nZHVsZXVyMB8GA1UdIwQYMBaAFLMsL7gWXQsYHdzcwM0+JnFPgEj4MB0GA1UdDgQW\nBBR1sDSSZO4CFbSeOOreef/hQcxN7TAFBgMrZXADQQBlcKnfGnVP7tNWXZRLdnCD\npY7ezNBLcr+4U+D0uxumRnQjj7V/56zK06u/IjKd3PnMB5gRqK7kCGbivO6hAgEH\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD\nVQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS\nWvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z\ntEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO\n-----END CERTIFICATE-----"],"contenu":"{\"b\":true,\"n\":18,\"sub\":{\"a\":\"More text\",\"b\":12},\"value\":\"DUMMY content\"}","estampille":1721592075,"id":"5bd735ce7816b4cdf5eb3d87ee63a40aee7fa580f7cc1bb0e64343aaf27030de","kind":1,"pubkey":"aff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a","routage":{"action":"DUMMY ACTION","domaine":"DUMMY domain"},"signature":"ecedc4bfdaa1aa19e0c195696998c1e93a02a6623469477d059e05bbb2b6715d7837b3f2182833cb51746a9125f364e3d533973e2e5b372c7c2be814c47dfa02"};

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
    expect(publicKey).toStrictEqual('4a9cedf45aa5d0269de906a8cb5a692661668eed866de3b89714f61c04aa9c04')
});

test('cert-wrapper-verify-date', async () => {
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT)
    const result = await certificateWrapper.verify(null, new Date('2024-07-20'))
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
    expect(commonName).toBe('a0bb5dbb-72fb-413f-97ff-798d2aef0d50')
});

test('cert-getIdmg', async () => {
    let idmg = await getIdmg(MILLEGRILLE_CERT)
    expect(idmg).toStrictEqual('zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf')
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

    let wrapper = await store.cache.getCertificate('4a9cedf45aa5d0269de906a8cb5a692661668eed866de3b89714f61c04aa9c04');
    expect(wrapper).toBeDefined();

    // Check that cache maintenance works
    await new Promise(resolve=>setTimeout(resolve, 5));  // Wait 5 ms
    await store.cache.maintain(1);  // Mark entries older than 1ms as expired
    wrapper = await store.cache.getCertificate('4a9cedf45aa5d0269de906a8cb5a692661668eed866de3b89714f61c04aa9c04');
    expect(wrapper).toBeUndefined();
})

test('test store message', async ()=>{
    let store = new CertificateStore(MILLEGRILLE_CERT);
    store.cache = new CertificateCache();
    let message = parseMessage(JSON.stringify(MESSAGE_1));
    let result = await store.verifyMessage(message);
    expect(result).toBe(true);
    let wrapper = await store.cache.getCertificate('aff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a');
    expect(wrapper).toBeDefined();

    // No real way to check for a cache hit...
    let result2 = await store.verifyMessage(message);
    expect(result2).toBe(true);
})
