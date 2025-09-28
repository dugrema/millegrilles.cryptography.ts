import { secretFromEd25519, secretFromEd25519PrivateX25519Peer, encryptEd25519, decryptEd25519, generateX25519KeyPair, sharedSecretFromX22519 } from '../lib/x25519';
import { decodeBase64Nopad } from '../lib/multiencoding'
import _sodium from 'libsodium-wrappers';

const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('0123456789012345678901234567890123456789012345678901234567890123', 'hex'));
const SECRET_KEY = new Uint8Array(Buffer.from('2345678901234567890123456789012345678901234567890123456789012345', 'hex'));

test('secretExchangeEd25519', async () => {
    await _sodium.ready;
    const sodium = _sodium;

    const caKey = sodium.crypto_sign_seed_keypair(CA_PRIVATE_KEY);
    const keyA = await secretFromEd25519(caKey.publicKey);
    expect(keyA).toBeTruthy();

    const keyB = await secretFromEd25519PrivateX25519Peer(CA_PRIVATE_KEY, keyA.peerBytes);
    expect(keyB).toBeTruthy();
    expect(keyA.secret).toStrictEqual(keyB);
});

test('encrypt-decrypt Key', async () => {
    await _sodium.ready;
    const sodium = _sodium;

    const caKey = sodium.crypto_sign_seed_keypair(CA_PRIVATE_KEY);
    const publicKey = caKey.publicKey;

    const val = await encryptEd25519(SECRET_KEY, publicKey);
    const decodedValue = decodeBase64Nopad(val);
    expect(decodedValue.length).toBe(80);

    const cleartext = await decryptEd25519(val, CA_PRIVATE_KEY);
    expect(cleartext).toStrictEqual(SECRET_KEY);
});

test('generate X25519 key pair', async () => {
    let keypair = await generateX25519KeyPair();
    expect(keypair.privateKey).toBeDefined();
    expect(keypair.publicKey).toBeDefined();
    expect(keypair.keyType).toBe('x25519');
});

test('X25519 shared key', async () => {
    let keypair1 = await generateX25519KeyPair();
    let keypair2 = await generateX25519KeyPair();
    
    let shared1 = await sharedSecretFromX22519(keypair1.privateKey, keypair2.publicKey);
    let shared2 = await sharedSecretFromX22519(keypair2.privateKey, keypair1.publicKey);
    
    expect(shared1).toEqual(shared2);
});

