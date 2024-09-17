import _sodium from 'libsodium-wrappers';
import { MessageDecryption } from './messageStruct';

/**
 * Encrypt content using Chacha20Poly1305.
 * @param content Cleartext content to encrypt.
 * @param nonce 12 byte nonce (IV)
 * @param key 32 byte secret key
 * @returns Ciphertext content + 16 bytes authentication tag.
 */
export async function encryptChacha20Poly1305(content: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    await _sodium.ready;
    const sodium = _sodium;
    const ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(content, null, null, nonce, key);
    return new Uint8Array(ciphertext)
}

/**
 * Decrypt content using Chacha20Poly1305.
 * @param content Ciphertext content to decrypt + 16 bytes authentication tag.
 * @param nonce 12 byte nonce (IV)
 * @param key 32 byte secret key
 * @returns Cleartext content.
 */
export async function decryptChacha20Poly1305(content: Uint8Array, nonce: Uint8Array, key: Uint8Array): Promise<Uint8Array> {
    await _sodium.ready;
    const sodium = _sodium;
    const cleartext = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, content, null, nonce, key)
    return new Uint8Array(cleartext)
}

export function concatBuffers(arrays: Uint8Array[]) {
    let outputLength = arrays.reduce((acc, item)=>acc+item.length, 0)
    let buffer = new Uint8Array(outputLength);
    let position = 0;
    for(let output of arrays) {
        buffer.set(output, position);
        position += output.length;
    }
    return buffer;
}

/** Structure with information to decrypt an inline ciphertext in base64 (with padding) encoded format. */
export type EncryptedData = MessageDecryption & {
    ciphertext_base64: string
};
