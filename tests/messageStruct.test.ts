import stringify from 'json-stable-stringify';
import { loadPrivateKeyEd25519, wrapperFromPems } from '../lib/certificates';
import { newMessageSigningKey } from '../lib/ed25519';
import { MessageKind, createRoutedMessage, MilleGrillesMessage, Routage, createResponse, createEncryptedResponse, parseMessage } from '../lib/messageStruct'

const PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));
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
    expect(message.id).toStrictEqual('13981c55d168d1ae35e3e6bbe357a1bca1f4187b1e39ebf9b07cce317ca96318');
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);
    expect(Buffer.from(message.signature).length).toBe(128);

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
    expect(message.id).toStrictEqual('1b70b5cf9a7dc222aeb430864f930fc0fe448b6190b03b8739bf1387f56d3c72');
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);
    expect(Buffer.from(message.signature).length).toBe(128);

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
    expect(message.id).toBe("950d1ba9ae74fbfd161b2e6c77a4589f0e6576f2ce6d3e39e8b25d84dc2d5aae");
    expect(message.signature).toBeTruthy();
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);
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
    expect(message.id).toBe("1efc7cda1332b036d9b5f7326625ee62f15fb4fbf1c9895c98fdda787fa1dee2");
    expect(message.signature).toBeTruthy();
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);
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
    expect(message.signature).toBeTruthy();
    expect(message.contenu).toBeTruthy();
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);

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
