import { pki, ed25519 } from '@dugrema/node-forge';

export function loadEd25519PrivateKey(pem: string, opts: {password?: string, pemout?: boolean}) {
    opts = opts || {}
  
    let key
    if(opts.password) {
        // Dechiffrer la cle privee
        key = decryptPrivateKey(pem, opts.password)
        if(opts.pemout === true) {
            // Re-exporter la cle en PEM
            key.pem = ed25519.privateKeyToPem(key)
        }
    } else {
        key = ed25519.privateKeyFromPem(pem)
    }
  
    return key
}

function decryptPrivateKey(pem: string, password: string) {
    const cleWrappee = pki.encryptedPrivateKeyFromPem(pem)
    const cleAsn1 = pki.decryptPrivateKeyInfo(cleWrappee, password)
    return ed25519.privateKeyFromAsn1(cleAsn1)
}
