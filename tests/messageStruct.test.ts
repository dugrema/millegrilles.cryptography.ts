import { wrapperFromPems } from '../lib/certificates';
import { newMessageSigningKey } from '../lib/ed25519';
import { MessageKind, createRoutedMessage, MilleGrillesMessage, Routage, createResponse } from '../lib/messageStruct'

const PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));
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

test('sign-message 1', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let message = new MilleGrillesMessage(1721592075, 0, 'DUMMY CONTENT');
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
    let message = new MilleGrillesMessage(1721592075, 2, 'DUMMY CONTENT');
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
    expect(message.kind).toBe(1);
    expect(message.id).toBe("950d1ba9ae74fbfd161b2e6c77a4589f0e6576f2ce6d3e39e8b25d84dc2d5aae");
    expect(message.signature).toBeTruthy();
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);

    let result = await message.verify();
    expect(result).toBe(true);
})

test('create response', async () => {
    let certificateWrapper = wrapperFromPems(CERTIFICATE_1)
    let signingKey = await newMessageSigningKey(PRIVATE_KEY, certificateWrapper);
    let content = {value: "DUMMY content", n: 18, b: true, sub: {b: 12, a: "More text"}};
    let timestamp = new Date(1721592075000);
    let message = await createResponse(signingKey, content, timestamp);
    expect(message.pubkey).toBe("4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4");
    expect(message.contenu).toBe('{"b":true,"n":18,"sub":{"a":"More text","b":12},"value":"DUMMY content"}');
    expect(message.estampille).toBe(1721592075);
    expect(message.kind).toBe(0);
    expect(message.id).toBe("1efc7cda1332b036d9b5f7326625ee62f15fb4fbf1c9895c98fdda787fa1dee2");
    expect(message.signature).toBeTruthy();
    expect(message.certificate).toStrictEqual(CERTIFICATE_1);
})

