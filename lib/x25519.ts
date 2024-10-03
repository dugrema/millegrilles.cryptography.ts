import { digest } from './digest';
import { encodeBase64Nopad, decodeBase64Nopad } from './multiencoding';
import { encryptChacha20Poly1305, decryptChacha20Poly1305 } from './encryption'
import { generateKeypairEd5519 } from './ed25519';
import _sodium, { KeyPair } from 'libsodium-wrappers';

type SecretFromEd25519Result = {
    secret: Uint8Array,     // Secret value to use
    peer: string,           // Peer to save as the encrypted key
    peerBytes: Uint8Array,  // Byte value of the peer
    publicKey: Uint8Array,  // Public ed25519 value for the key, can be used to verify a signature associated to this shared key.
    privateKey: Uint8Array, // Private ed25519 value, can be used for signing content associated to this shared key.
};

/**
 * Generate a new shared secret from a Ed25519 public key (e.g. CA or public peer)
 * @param publicKey 
 * @returns The generated secret and x25519 public peer value to save as part of the encrypted key.
 */
export async function secretFromEd25519(publicKey: Uint8Array) : Promise<SecretFromEd25519Result> {
    await _sodium.ready;
    const sodium = _sodium;

    // Convert the provided public key to curve (X25519)
    const x25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey);

    // Convert a newly generated Ed25519 keypair to curve (X25519)
    const ed25519Keypair = await generateKeypairEd5519();
    const newX25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(ed25519Keypair.public);
    const newX25519PrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(ed25519Keypair.private);

    // Prepare the shared secret based on the provided public key and newly generated private key
    const sharedSecretKey = sodium.crypto_scalarmult(newX25519PrivateKey, x25519PublicKey);
    const digestedSecret = await digest(sharedSecretKey, {digestName: 'blake2s-256', encoding: 'bytes'});
    if(!ArrayBuffer.isView(digestedSecret)) throw new Error("digest wrong response type");  // Check type
    
    // Convert the public peer value to a string. Allows to serialize it as part of a json message.
    const newPublicX25519String = encodeBase64Nopad(newX25519PublicKey);

    return {
        secret: digestedSecret,
        peer: newPublicX25519String,
        peerBytes: newX25519PublicKey,
        publicKey: ed25519Keypair.public,
        privateKey: ed25519Keypair.private,
    };
}

/**
 * Recalculates a shared secret previously generated from a public CA key. 
 * @param privateKey The Ed25519 private key used to decrypt the value.
 * @param peerPublicKey X25519 public key generated as the encrypted value of a shared secret.
 * @returns Shared secret.
 */
export async function secretFromEd25519PrivateX25519Peer(ed25519PrivateKey: Uint8Array, x25519PublicKey: Uint8Array): Promise<Uint8Array> {
    await _sodium.ready;
    const sodium = _sodium;

    // Convert the ed25519 values to x25519.
    const privateKeyFull = sodium.crypto_sign_seed_keypair(ed25519PrivateKey).privateKey;
    const x25519PrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(privateKeyFull);

    // Recalculate and digest the shared secret.
    const sharedSecretKey = sodium.crypto_scalarmult(x25519PrivateKey, x25519PublicKey);
    const digestedSecret = await digest(sharedSecretKey, {digestName: 'blake2s-256', encoding: 'bytes'});
    if(!ArrayBuffer.isView(digestedSecret)) throw new Error("wrong type");  // Check type
    
    return digestedSecret;
}

/**
 * 
 * @param pk Ed25519 public key
 * @returns X25519 public key
 */
export async function convertPublicEd25519toX25519(pk: Uint8Array) {
    await _sodium.ready;
    const sodium = _sodium;
    
    return sodium.crypto_sign_ed25519_pk_to_curve25519(pk);
}

/**
 * 
 * @param sk Ed25519 private key
 * @returns X25519 private key
 */
export async function convertPrivateEd25519ToX25519(sk: Uint8Array) {
    await _sodium.ready;
    const sodium = _sodium;

    const privateKeyFull = sodium.crypto_sign_seed_keypair(sk).privateKey;
    return sodium.crypto_sign_ed25519_sk_to_curve25519(privateKeyFull);
}

export async function encryptEd25519(secretKey: Uint8Array, publicKey: Uint8Array): Promise<string> {
    // Obtenir une nouvelle cle peer pour le chiffrage du secret
    const newKey = await secretFromEd25519(publicKey);
    const publicPeer = newKey.peerBytes;
    // Generate the nonce from the key
    const nonce = (await digest(publicPeer, {digestName: 'blake2s-256', encoding: 'bytes'})).slice(0, 12);
    if(!ArrayBuffer.isView(nonce)) throw new Error("digest - nonce format must be bytes");  // Check format
    const ciphertext = await encryptChacha20Poly1305(secretKey, nonce, newKey.secret);

    // Put key content in a buffer
    const encryptedKeyBuffer = new Uint8Array(80);
    encryptedKeyBuffer.set(newKey.peerBytes, 0); // 32 bytes x25519 public peer
    encryptedKeyBuffer.set(ciphertext, 32);      // 32 bytes encrypted secret key (chacha20-poly1305) + 16 bytes authentication tag
    const encryptedKey = encodeBase64Nopad(encryptedKeyBuffer);

    return encryptedKey;
}

export async function decryptEd25519(key: string | Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
    let keyBytes = key;
    if(typeof(keyBytes) === 'string') {
        keyBytes = decodeBase64Nopad(keyBytes);
    }

    // Get shared secret to decrypt key
    const publicPeer = keyBytes.slice(0, 32);
    const sharedSecret = await secretFromEd25519PrivateX25519Peer(privateKey, publicPeer);

    // Decrypt the key
    const ciphertextTag = keyBytes.slice(32, 80);
    const nonce = (await digest(publicPeer, {digestName: 'blake2s-256', encoding: 'bytes'})).slice(0, 12);
    if(!ArrayBuffer.isView(nonce)) throw new Error("digest - nonce format must be bytes");  // Check format

    const cleartext = await decryptChacha20Poly1305(ciphertextTag, nonce, sharedSecret);

    return cleartext;
}

export async function generateX25519KeyPair(): Promise<KeyPair> {
    await _sodium.ready;
    const sodium = _sodium;
    return sodium.crypto_kx_keypair();
}

export async function sharedSecretFromX22519(privateX25519: Uint8Array, peerPublicX25519: Uint8Array): Promise<Uint8Array> {
    await _sodium.ready;
    const sodium = _sodium;
    return sodium.crypto_scalarmult(privateX25519, peerPublicX25519);
    // return await digest(sharedSecretKey, {digestName: 'blake2s-256', encoding: 'bytes'}) as Uint8Array;
}
