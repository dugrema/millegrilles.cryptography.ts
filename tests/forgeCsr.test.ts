import { createCsr, loadPrivateKey, verifyUserCsr } from '../lib/forgeCsr';
import { decodeHex } from '../lib/multiencoding';

test('test generate CSR', async ()=>{
    let { pem, privateKeyPem, privateKey, publicKey } = await createCsr('testUser', 'zABCD1234');
    // console.debug("CSR\n%s\mPrivate pem\n%s\nPrivate:%O\nPublic:%O", pem, privateKeyPem, privateKey, publicKey);
    expect(typeof(pem)).toBe('string');
    expect(typeof(privateKeyPem)).toBe('string');
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
})

const ENCRYPTED_PRIVATE_PEM = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGtMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAj52joL+fVm5gICCAAw
HQYJYIZIAWUDBAEqBBBdAUqIYES+PCXKj7VkyNd/BGBvmIssujxII+fPu1f40iLl
B1rEjTsUI34K+u5xD32ne6Eweb5BPZNS479Y1optjYXTe4pmrbIvvVWw8oYkCg1C
jKvpFJjoRMzLA3jzzWW1z8rANlqqXlTDUaK1LIBGVG8=
-----END ENCRYPTED PRIVATE KEY-----`;
const ENCRYPTED_PRIVATE_KEY_PASSWORD = 'HTGUELI3x7TevB12aQIyit/4eckiRm2kuFx/5xvpW30';
const ENCRYPTED_PRIVATE_KEY_HEX = 'f5fe1a63a7abec682c3534a812e847e51e40da66c545c26e908227367936eea8';

const PRIVATE_KEY_PEM = `
-----BEGIN PRIVATE KEY-----
ME4CAQAwBQYDK2VwBEIEILq9hBT8x+j38MQdFjx5EZUO+15+OWFfWsEVdbULOMiJ
OT/3sG07S6nyHpQD71VdQAM17uBzhQ+OMoAKWRjIP+U=
-----END PRIVATE KEY-----`;
const PRIVATE_KEY_HEX = 'babd8414fcc7e8f7f0c41d163c7911950efb5e7e39615f5ac11575b50b38c889';

const CSR_PEM = `
-----BEGIN CERTIFICATE REQUEST-----
MIGQMEQCAQAwETEPMA0GA1UEAxMGdGF0YTEyMCowBQYDK2VwAyEAFgJht7oBV33G
U6r9f2T0dFIWBEzpFuaujOyBFMPutQCgADAFBgMrZXADQQDo03USNpkEPnx/Mp5i
GeJe88teA3NtqDVdpey6ztO+KTNJR9hMhHnXC9YupGJsaVFDAYrrrPwtW+QFEq15
ObsE
-----END CERTIFICATE REQUEST-----`;

test('test load private key', () => {
    let privateKeyBytes = loadPrivateKey(PRIVATE_KEY_PEM);
    expect(privateKeyBytes).toStrictEqual(decodeHex(PRIVATE_KEY_HEX));
});

test('test load encrypted private key', () => {
    let privateKeyBytes = loadPrivateKey(ENCRYPTED_PRIVATE_PEM, ENCRYPTED_PRIVATE_KEY_PASSWORD);
    expect(privateKeyBytes).toStrictEqual(decodeHex(ENCRYPTED_PRIVATE_KEY_HEX));
});

test('verify user csr information', async () => {
    let username = verifyUserCsr(CSR_PEM);
    expect(username).toStrictEqual('tata12');
});
