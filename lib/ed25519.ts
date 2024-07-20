import _sodium from 'libsodium-wrappers';
import { getRandom } from './random';
import { baseEncode, baseDecode } from './multiencoding';

type Ed25519KeyPair = {public: Uint8Array, private: Uint8Array};

export async function generateKeypairEd5519(seed?: Uint8Array): Promise<Ed25519KeyPair> {
    await _sodium.ready;
    const sodium = _sodium;

    if(seed) {
        if(seed.length != 32) throw new Error("Seed length must be 32 bytes");
    } else {
        seed = getRandom(32)
    }
    
    const newKey = sodium.crypto_sign_seed_keypair(seed);
    return {public: newKey.publicKey, private: newKey.privateKey};
}

export async function signMessage(privateKey: Uint8Array, digest: string | Uint8Array): Promise<string> {
    await _sodium.ready;
    const sodium = _sodium;

    if(typeof(digest) === 'string') {
        digest = Buffer.from(digest, 'hex');
    }

    const privateKeyFull = sodium.crypto_sign_seed_keypair(privateKey).privateKey;
    const signature = sodium.crypto_sign_detached(digest, privateKeyFull);
    return baseEncode('base64', signature);
}

export async function verifyMessageSignature(publicKey: Uint8Array, digest: string | Uint8Array, signature: string) {
    await _sodium.ready;
    const sodium = _sodium;

    if(typeof(digest) === 'string') {
        digest = Buffer.from(digest, 'hex');
    }

    const signatureBytes = baseDecode(signature);

    const result = sodium.crypto_sign_verify_detached(signatureBytes, digest, publicKey);
    if(!result) throw new Error("Signature verification failed");
    return true;
}