import { secretFromEd25519, secretFromEd25519Peer } from '../lib/x25519';
import _sodium from 'libsodium-wrappers';

const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

test('secretExchangeEd25519', async () => {
    await _sodium.ready
    const sodium = _sodium

    const caKey = sodium.crypto_sign_seed_keypair(CA_PRIVATE_KEY)
    const keyA = await secretFromEd25519(caKey.publicKey);
    expect(keyA).toBeTruthy();

    const keyB = await secretFromEd25519Peer(CA_PRIVATE_KEY, keyA.publicKey);
    expect(keyB).toBeTruthy();
    expect(keyA.secret).toStrictEqual(keyB);
});
