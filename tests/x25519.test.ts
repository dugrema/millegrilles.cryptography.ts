import { secretFromEd25519, secretFromEd25519PrivateX25519Peer, encryptEd25519, decryptEd25519 } from '../lib/x25519';
import {baseDecode} from '../lib/multiencoding'
import _sodium from 'libsodium-wrappers';

const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));
const SECRET_KEY = new Uint8Array(Buffer.from('23456789012345678901234567890123456789012345678901234567890123456', 'hex'));

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
    const decodedValue = baseDecode(val);
    expect(decodedValue.length).toBe(80);

    const cleartext = await decryptEd25519(val, CA_PRIVATE_KEY);
    expect(cleartext).toStrictEqual(SECRET_KEY);
});
