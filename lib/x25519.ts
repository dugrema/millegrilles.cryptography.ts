import { getRandom } from './random';
import { digest } from './digest';
import { baseEncode } from './multiencoding';
import _sodium from 'libsodium-wrappers';

// chiffrer_asymmetrique_ed25519
// dechiffrer_asymmetrique_ed25519
// convertir_public_ed25519_to_x25519
// convertir_private_ed25519_to_x25519
// detecter_version_cle

type DeriveSecretResult = {
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
export async function secretFromEd25519(publicKey: Uint8Array) : Promise<DeriveSecretResult> {
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
    const newPublicX25519String = baseEncode('base64', newX25519PublicKey);

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
 * @param privateKey The CA or reference key to use to decrypt the value.
 * @param peerPublicKey Peer public key generated as the encrypted value of a shared secret.
 * @returns Shared secret.
 */
export async function secretFromEd25519Peer(privateKey: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array> {
    await _sodium.ready;
    const sodium = _sodium;

    // Convert the ed25519 values to x25519.
    const x25519PublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(peerPublicKey);
    const privateKeyFull = sodium.crypto_sign_seed_keypair(privateKey).privateKey;
    const x25519PrivateKey = sodium.crypto_sign_ed25519_sk_to_curve25519(privateKeyFull);

    // Recalculate and digest the shared secret.
    const sharedSecretKey = sodium.crypto_scalarmult(x25519PrivateKey, x25519PublicKey);
    const digestedSecret = await digest(sharedSecretKey, {digestName: 'blake2s-256', encoding: 'bytes'});
    if(!ArrayBuffer.isView(digestedSecret)) throw new Error("wrong type");  // Verify return type
    
    return digestedSecret;
}

function convertPublicEd25519toX25519() {

}

function convertPrivateEd25519ToX25519() {

}

function encryptEd25519() {

}

function decryptEd25519() {

}

type Ed25519KeyPair = {public: Uint8Array, private: Uint8Array}

async function generateKeypairEd5519(): Promise<Ed25519KeyPair> {
    await _sodium.ready
    const sodium = _sodium

    const privateKey = getRandom(32)
    const newKey = sodium.crypto_sign_seed_keypair(privateKey)    
    return {public: newKey.publicKey, private: newKey.privateKey}
}
