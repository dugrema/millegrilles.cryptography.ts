import { encryptChacha20Poly1305, decryptChacha20Poly1305 } from '../lib/encryption'
// require('./hachage.config');

const SECRET_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));
const NONCE = new Uint8Array(Buffer.from('0123456789012345678901234', 'hex'));

test('encrypt-decrypt 1', async () => {
    const message = new TextEncoder().encode("A simple message");
    
    const ciphertext = await encryptChacha20Poly1305(message, NONCE, SECRET_KEY);
    const b64text = Buffer.from(ciphertext).toString('base64')
    expect(b64text).toBe("YJjXdw1bt4hgB19Pt9Ek3pwewToOY/iTvO96Rds0pUo=");
    
    const cleartext = await decryptChacha20Poly1305(ciphertext, NONCE, SECRET_KEY);

    expect(cleartext).toStrictEqual(message);
});
