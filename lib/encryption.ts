import _sodium from 'libsodium-wrappers';

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
