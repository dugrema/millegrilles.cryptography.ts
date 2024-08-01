import { pki, ed25519 } from '@dugrema/node-forge';
import { OIDS } from './certificates';

export async function createCsr(username: string, userId?: string): Promise<{pem: string, privateKeyPem: string, privateKey: Uint8Array, publicKey: Uint8Array }> {

    // Generate new keypair
    let keypair = ed25519.generateKeyPair();
    let publicKey = new Uint8Array(keypair.publicKey.publicKeyBytes);
    let privateKey = new Uint8Array(keypair.privateKey.privateKeyBytes).slice(0, 32);  // Keep first 32 bytes (private component)
  
    const csr = pki.createCertificationRequest();
    csr.publicKey = keypair.publicKey;
  
    var attrs = [{ name: 'commonName', value: username }];
    csr.setSubject(attrs);
  
    var extensions = [];
    if(userId) {
        // Add the userId custom extension
        extensions.push({ id: OIDS.OID_USERID, value: userId });
    }
  
    if(extensions.length > 0) {
        csr.setAttributes([
            {name: 'extensionRequest', extensions}
        ]);
    }
  
    // Sign request
    csr.sign(keypair.privateKey);
  
    // Export using PEM format
    let pem = pki.certificationRequestToPem(csr);

    let privateKeyPem = ed25519.privateKeyToPem(keypair.privateKey) as string;
  
    return {pem, privateKeyPem, privateKey, publicKey};
}

/**
 * Loads a private key.
 * @param pem Private key PEM content
 * @param password Password to decrypt the key (when the private key is encrypted)
 * @returns Private key bytes (32 bytes)
 */
export function loadPrivateKey(pem: string, password?: string): Uint8Array {
    if(password) {
        // Dechiffrer la cle privee
        let wrappedKey = pki.encryptedPrivateKeyFromPem(pem);
        let asn1Key = pki.decryptPrivateKeyInfo(wrappedKey, password);
        let privateKey = ed25519.privateKeyFromAsn1(asn1Key);
        return new Uint8Array(privateKey.privateKeyBytes);
    } else {
        let privateKey = ed25519.privateKeyFromPem(pem);
        return new Uint8Array(privateKey.privateKeyBytes);
    }
}

/**
 * Verifies a CSR and returns the username.
 * @param pem CSR string.
 * @returns username (CN subject field)
 */
export function verifyUserCsr(pem: string): string {
    const csrForge = pki.certificationRequestFromPem(pem)
    if(!csrForge.verify()) throw new Error('Invalid CSR');
    const cn = csrForge.subject.getField('CN').value
    if(!cn) throw new Error('Username missing from the CSR');
    return cn
}
