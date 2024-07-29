import { pki, ed25519 } from '@dugrema/node-forge';
import { OIDS } from './certificates';

export async function createCsr(username: string, userId?: string): Promise<{pem: string, privateKey: Uint8Array, publicKey: Uint8Array }> {

    // Generate new keypair
    let keypair = ed25519.generateKeyPair();
    let publicKey = new Uint8Array(keypair.publicKey.publicKeyBytes);       // 32 bytes
    let privateKey = new Uint8Array(keypair.privateKey.privateKeyBytes);    // 64 bytes, includes the public key
  
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
  
    return {pem, privateKey, publicKey};
}
