import _sodium from 'libsodium-wrappers';
import { getRandom } from './random';
import { baseEncode, baseDecode, decodeHex, encodeHex } from './multiencoding';
import { CertificateWrapper, loadPrivateKeyEd25519, splitCertificatePems, wrapperFromPems } from './certificates';

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
        digest = decodeHex(digest);
    }

    const privateKeyFull = sodium.crypto_sign_seed_keypair(privateKey).privateKey;
    const signature = sodium.crypto_sign_detached(digest, privateKeyFull);
    return baseEncode('base64', signature);
}

export async function verifyMessageSignature(publicKey: Uint8Array, digest: string | Uint8Array, signature: string | Uint8Array) {
    await _sodium.ready;
    const sodium = _sodium;

    if(typeof(digest) === 'string') {
        digest = decodeHex(digest);
    }

    if(typeof(signature) === 'string') {
        signature = baseDecode(signature);
    }

    const result = sodium.crypto_sign_verify_detached(signature, digest, publicKey);
    if(!result) throw new Error("Signature verification failed");
    return true;
}

export class MessageSigningKey {
    key: Ed25519KeyPair;
    publicKey: string;
    certificate: CertificateWrapper;

    constructor(key: Ed25519KeyPair, certificate: CertificateWrapper) {
        this.key = key;
        this.publicKey = encodeHex(key.public);
        this.certificate = certificate;
    }

    async sign(value: Uint8Array) {
        await _sodium.ready;
        const sodium = _sodium;
        const signature = sodium.crypto_sign_detached(value, this.key.private);
        return encodeHex(signature);
    }

    async verify(signature: Uint8Array, value: Uint8Array): Promise<boolean> {
        await _sodium.ready;
        const sodium = _sodium;
        const result = sodium.crypto_sign_verify_detached(signature, value, this.key.public);
        if(!result) throw new Error("Signature verification failed");
        return result
    }

    getChain() {
        return this.certificate.pemChain;
    }
}

export async function newMessageSigningKey(privateKey: Uint8Array, certificate: CertificateWrapper): Promise<MessageSigningKey> {
    let keypair = await generateKeypairEd5519(privateKey);
    return new MessageSigningKey(keypair, certificate)
}

export async function loadSigningKeyFromPems(privateKeyPem: string, certificateChain: string, caPem: string) {
    let certificatChainList = splitCertificatePems(certificateChain);
    let certificateWrapper = wrapperFromPems(certificatChainList, caPem);
    let privateKey = loadPrivateKeyEd25519(privateKeyPem);
    return await newMessageSigningKey(privateKey, certificateWrapper);
}
