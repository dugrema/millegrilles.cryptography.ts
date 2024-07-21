import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
import { verifyCertificatePem, wrapperFromPems, getIdmg } from "../lib/certificates"

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

const MILLEGRILLE_CERT = `-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
-----END CERTIFICATE-----`

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
    expect(publicKey).toStrictEqual('9cedf45aa5d0269de906a8cb5a692661668eed866de3b89714f61c04aa9c04')
});

test('cert-wrapper-verify-date', async () => {
    const ca = wrapperFromPems([MILLEGRILLE_CERT])
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1, ca.certificate)
    const result = await certificateWrapper.verify(null, new Date('2024-07-20'))
    expect(result).toBe(true)
});

test('cert-wrapper-verify-caincluded', async () => {
    const ca = wrapperFromPems([MILLEGRILLE_CERT])
    const certificateWrapper = wrapperFromPems(CERTIFICATE_1, ca.certificate)
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
