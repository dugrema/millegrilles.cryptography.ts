import _sodium from 'libsodium-wrappers';
import { loadSigningKeyFromPems, signMessage, verifyMessageSignature, messageSigningKeyFromBytes } from '../lib/ed25519'

const DIGEST_1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

const CERTIFICATE_1 = `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
bGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD
VQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV
BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS
WvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
A1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z
tEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO
-----END CERTIFICATE-----`;

const CERTIFICATE_CHAIN = [`-----BEGIN CERTIFICATE-----
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
MIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\r
bGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD\r
VQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV
BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS
WvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
A1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z
tEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO
-----END CERTIFICATE-----`];

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

test('sign-verify 1', async () => {
    await _sodium.ready;
    const sodium = _sodium;
    
    const keyFull = sodium.crypto_sign_seed_keypair(CA_PRIVATE_KEY);

    const signatureResult = await signMessage(CA_PRIVATE_KEY, DIGEST_1);
    expect(signatureResult).toBeTruthy();
    
    const result = await verifyMessageSignature(keyFull.publicKey, DIGEST_1, signatureResult);
    expect(result).toBe(true);
});

test('signing key from pems', async() => {
    let key = await loadSigningKeyFromPems(PRIVATE_1, CERTIFICATE_1, MILLEGRILLE_CERT);
    expect(key.getChain().length).toBe(2);
    expect(key.certificate.pemMillegrille).toStrictEqual(MILLEGRILLE_CERT);
    expect(Buffer.from(key.key.private).toString('hex'))
        .toBe('0ed545befdd3cd8017516691abde55c10d0141a33590c06f67ef71d6319ea57faff9cc396160b720479bd910187629388c14aa22af0f084f9a6f688bcb17cd4a');
});

test('signing key from pems', async() => {
    let key = await messageSigningKeyFromBytes(CA_PRIVATE_KEY, CERTIFICATE_CHAIN);
    expect(key).toBeDefined();
});
