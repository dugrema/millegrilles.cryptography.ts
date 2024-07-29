import stringify from 'json-stable-stringify';
import { loadPrivateKeyEd25519, wrapperFromPems } from '../lib/certificates';
import { newMessageSigningKey } from '../lib/ed25519';
import { MessageKind, createRoutedMessage, MilleGrillesMessage, Routage, createResponse, createEncryptedResponse, parseMessage } from '../lib/messageStruct'

const PRIVATE_KEY = new Uint8Array(Buffer.from('0123456789012345678901234567890123456789012345678901234567890123', 'hex'));
const CERTIFICATE_1 = [
    `-----BEGIN CERTIFICATE-----
MIICPDCCAe6gAwIBAgIUWw4LLOaWvtl2+e1NKBN1YXuHHywwBQYDK2VwMHIxLTAr
BgNVBAMTJGEwYmI1ZGJiLTcyZmItNDEzZi05N2ZmLTc5OGQyYWVmMGQ1MDFBMD8G
A1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6
WHJwMjJiQXR3R203SmYwHhcNMjQwNzE3MTEyODU1WhcNMjQwODE3MTEyOTE1WjCB
hTEtMCsGA1UEAwwkYTBiYjVkYmItNzJmYi00MTNmLTk3ZmYtNzk4ZDJhZWYwZDUw
MREwDwYDVQQLDAhjZWR1bGV1cjFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4
d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6WHJwMjJiQXR3R203SmYwKjAFBgMrZXAD
IQCv+cw5YWC3IEeb2RAYdik4jBSqIq8PCE+ab2iLyxfNSqOBgTB/MCsGBCoDBAAE
IzQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMBAGBCoDBAEECGNl
ZHVsZXVyMB8GA1UdIwQYMBaAFLMsL7gWXQsYHdzcwM0+JnFPgEj4MB0GA1UdDgQW
BBR1sDSSZO4CFbSeOOreef/hQcxN7TAFBgMrZXADQQBlcKnfGnVP7tNWXZRLdnCD
pY7ezNBLcr+4U+D0uxumRnQjj7V/56zK06u/IjKd3PnMB5gRqK7kCGbivO6hAgEH
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
];

const PRIVATE_KEY_1 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA7VRb79082AF1FmkaveVcENAUGjNZDAb2fvcdYxnqV/
-----END PRIVATE KEY-----`;

const MILLEGRILLE_CERT = `-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
-----END CERTIFICATE-----`

test('sign-message 1', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let message = new MilleGrillesMessage(1721592075, MessageKind.Document, 'DUMMY CONTENT');
    await message.sign(signingKey);
    expect(message.pubkey).toStrictEqual('4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4');
    expect(message.id).toStrictEqual('06e7ebf2e0b83338a0eb6779d9cd0cb0c6d9fc68cf34dbe978da61291d746fdc');
    expect(message.certificat).toStrictEqual(CERTIFICATE_1);
    expect(Buffer.from(message.sig).length).toBe(128);

    let result = await message.verify();
    expect(result).toBe(true);
});

test('sign-command', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let message = new MilleGrillesMessage(1721592075, MessageKind.Command, 'DUMMY CONTENT');
    message.routage = {domaine: 'DUMMY-DOMAINE', action: 'DUMMY-ACTION'}
    await message.sign(signingKey);
    expect(message.pubkey).toStrictEqual('4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4');
    expect(message.id).toStrictEqual('d3b050d8f15a2c97f7aa3ee4d024a6211e501c89bd3413fa5fa279f16a973d9d');
    expect(message.certificat).toStrictEqual(CERTIFICATE_1);
    expect(Buffer.from(message.sig).length).toBe(128);

    let result = await message.verify();
    expect(result).toBe(true);
});

test('create routed message', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let content = {value: "DUMMY content", n: 18, b: true, sub: {b: 12, a: "More text"}};
    let routing: Routage = {domaine: "DUMMY domaine", action: "DUMMY ACTION"};
    let timestamp = new Date(1721592075000);
    let message = await createRoutedMessage(signingKey, MessageKind.Request, content, routing, timestamp);
    expect(message.pubkey).toBe("4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4");
    expect(message.contenu).toBe('{"b":true,"n":18,"sub":{"a":"More text","b":12},"value":"DUMMY content"}');
    expect(message.estampille).toBe(1721592075);
    expect(message.kind).toBe(MessageKind.Request);
    expect(message.id).toBe("bf158f1c235dea7fbb4af8cdf8641ae61e9dca8861396a5f879b6d7ed2775ec1");
    expect(message.sig).toBeTruthy();
    expect(message.certificat).toStrictEqual(CERTIFICATE_1);
    expect(await message.getContent()).toStrictEqual(content);

    let result = await message.verify();
    expect(result).toBe(true);
});

test('create response', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let content = {value: "DUMMY content", n: 18, b: true, sub: {b: 12, a: "More text"}};
    let timestamp = new Date(1721592075000);
    let message = await createResponse(signingKey, content, timestamp);
    expect(message.pubkey).toBe("4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4");
    expect(message.contenu).toBe('{"b":true,"n":18,"sub":{"a":"More text","b":12},"value":"DUMMY content"}');
    expect(message.estampille).toBe(1721592075);
    expect(message.kind).toBe(MessageKind.Document);
    expect(message.id).toBe("32491f643f2c85d86106a81217960a7122b2247406e227e024249b67ea71bed0");
    expect(message.sig).toBeTruthy();
    expect(message.certificat).toStrictEqual(CERTIFICATE_1);
    expect(await message.getContent()).toStrictEqual(content);
});

test('create encrypted response', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1, MILLEGRILLE_CERT)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let content = {value: "DUMMY content", n: 18, b: true, sub: {b: 12, a: "More text"}};
    let encryptionKeys = [signingKey.certificate]
    let timestamp = new Date(1721592075000);
    let message = await createEncryptedResponse(signingKey, encryptionKeys, content, timestamp);

    expect(message.pubkey).toBe("4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4");
    expect(message.estampille).toBe(1721592075);
    expect(message.kind).toBe(MessageKind.EncryptedResponse);
    expect(message.id).toBeTruthy();  // Encrypted content changes every time
    expect(message.dechiffrage).toBeTruthy();
    expect(message.sig).toBeTruthy();
    expect(message.contenu).toBeTruthy();
    expect(message.certificat).toStrictEqual(CERTIFICATE_1);

    // Decrypt the message
    let privateKey = loadPrivateKeyEd25519(PRIVATE_KEY_1);
    let decryptionKey = await newMessageSigningKey(privateKey, certificateWrapper);
    let cleartextContent = await message.getContent(decryptionKey);
    
    // Compare content to confirm round-trip
    expect(cleartextContent).toStrictEqual(content);
});


test('serialize-deserialize message', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let privateKey = loadPrivateKeyEd25519(PRIVATE_KEY_1);
    let signingKey = await newMessageSigningKey(privateKey, certificateWrapper);
    let content = {value: "DUMMY content", n: 18, b: true, sub: {b: 12, a: "More text"}};
    let routing: Routage = {domaine: "DUMMY domain", action: "DUMMY ACTION"};
    let timestamp = new Date(1721592075000);
    let message = await createRoutedMessage(signingKey, MessageKind.Request, content, routing, timestamp);

    let jsonMessage = stringify(message);

    let deserializedMessage = parseMessage(jsonMessage);
    let result = await deserializedMessage.verify();
    expect(result).toBe(true);

    // Compare content to confirm round-trip
    expect(await message.getContent()).toStrictEqual(content);
})

const MESSAGE_FROM_PYTHON = {
    "pubkey": "4a9cedf45aa5d0269de906a8cb5a692661668eed866de3b89714f61c04aa9c04",
    "estampille": 1722287727,
    "kind": 0,
    "contenu": "{\"texte\":\"Du texte.\",\"valeur\":1}",
    "id": "a0d8f81e3704b5e0283a674c169c7e19a2f3abd8020562fe8fbb3f65d70bd824",
    "sig": "65e2c1ce15f9c476af6f0fc8ac2b9bdc022fd6ae97c3d44014461b5c50077cfa2361557a1e592593308d9e2a336f3618e3c52055c4c81f64d7d2c4b7e2449d05",
    "certificat": [
      "-----BEGIN CERTIFICATE-----\nMIIClDCCAkagAwIBAgIUXC5AOCMbTbgN7iWKOvw+1hkamokwBQYDK2VwMHIxLTAr\nBgNVBAMTJGEwYmI1ZGJiLTcyZmItNDEzZi05N2ZmLTc5OGQyYWVmMGQ1MDFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwNzE3MTEyOTAwWhcNMjQwODE3MTEyOTIwWjCB\ngTEtMCsGA1UEAwwkYTBiYjVkYmItNzJmYi00MTNmLTk3ZmYtNzk4ZDJhZWYwZDUw\nMQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG\ndUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhAEqc\n7fRapdAmnekGqMtaaSZhZo7thm3juJcU9hwEqpwEo4HdMIHaMCsGBCoDBAAEIzQu\nc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw\nTAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz\nQ29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf\nBgNVHSMEGDAWgBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAdBgNVHQ4EFgQUL6rsDhKr\nNXHN8NWdaT65cl5uUjcwBQYDK2VwA0EAGnb5qFGWVnqAeUg8oteXE3m8+oYKuzlI\npjrYag3mY79CtvnWZ1H6h9JLfDRl4j5S2i8D1ywxrbg8wBULD0ucDg==\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\r\nMIIBozCCAVWgAwIBAgIKBoEAlpIHYAWTaDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\r\nbGVHcmlsbGUwHhcNMjQwNzE3MTEyODA4WhcNMjYwMTI2MTEyODA4WjByMS0wKwYD\r\nVQQDEyRhMGJiNWRiYi03MmZiLTQxM2YtOTdmZi03OThkMmFlZjBkNTAxQTA/BgNV\r\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\r\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAZ/cAJCrI5igFVQNa2YmgL3CPvERXhlyS\r\nWvnGAV+4OVGjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\r\nA1UdDgQWBBSzLC+4Fl0LGB3c3MDNPiZxT4BI+DAfBgNVHSMEGDAWgBTTiP/MFw4D\r\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQCmqcjq64U/cKDhGpLV4LE2WNRVloXeUK3z\r\ntEjszGAVQ+Kr04y/k3FuCVJ1aoLwaZbmPB2CzV9XyQzub2vc/+AO\n-----END CERTIFICATE-----"
    ]
};

test('deserialize message from python', async () => {
    let deserializedMessage = parseMessage(JSON.stringify(MESSAGE_FROM_PYTHON));
    let result = await deserializedMessage.verify();
    expect(result).toBe(true);
})
