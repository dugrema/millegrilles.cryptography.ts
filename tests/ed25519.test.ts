import _sodium from 'libsodium-wrappers';
import { signMessage, verifyMessageSignature } from '../lib/ed25519'

const DIGEST_1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

test('sign-verify 1', async () => {
    await _sodium.ready;
    const sodium = _sodium;
    
    const keyFull = sodium.crypto_sign_seed_keypair(CA_PRIVATE_KEY);

    const signatureResult = await signMessage(CA_PRIVATE_KEY, DIGEST_1);
    expect(signatureResult).toBeTruthy();
    
    const result = await verifyMessageSignature(keyFull.publicKey, DIGEST_1, signatureResult)
    expect(result).toBe(true)
});
