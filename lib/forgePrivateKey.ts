import { pki, ed25519 } from '@dugrema/node-forge';
import { getRandom } from './random';

export function loadEd25519PrivateKey(pem: string, opts: {password?: string, pemout?: boolean}) {
    opts = opts || {}
  
    let key;
    if(opts.password) {
        // Dechiffrer la cle privee
        key = decryptPrivateKey(pem, opts.password);
        if(opts.pemout === true) {
            // Re-exporter la cle en PEM
            key.pem = ed25519.privateKeyToPem(key);
        }
    } else {
        key = ed25519.privateKeyFromPem(pem);
    }
  
    return key;
}

function decryptPrivateKey(pem: string, password: string) {
    const wrappedKey = pki.encryptedPrivateKeyFromPem(pem);
    const asn1Key = pki.decryptPrivateKeyInfo(wrappedKey, password);
    return ed25519.privateKeyFromAsn1(asn1Key);
}

export function generateNewPrivateKeyPem(opts?: {password: string}): {pem: string, keyPair: {publicKey: any, privateKey: any}, encryptedPem?: string} {
    let password = opts?.password;
    let keyPair = ed25519.generateKeyPair();
    let pem = ed25519.privateKeyToPem(keyPair.privateKey).replaceAll(/\r/g, '');
    if(password) {
        let asn1Key = ed25519.privateKeyToAsn1(keyPair.privateKey);
        var encryptedPrivateKeyInfo = pki.encryptPrivateKeyInfo(
          asn1Key, 
          password, 
          { algorithm: 'aes256' }
        );
        let encryptedPem = pki.encryptedPrivateKeyToPem(encryptedPrivateKeyInfo).replaceAll(/\r/g, '');
        return {keyPair, pem, encryptedPem};
    }
    return {keyPair, pem};
}

export async function generateMilleGrilleCertificate(password: string): Promise<{cert: any, certPem: string, encryptedPem: string}> {

    let {keyPair, encryptedPem} = generateNewPrivateKeyPem({password});
 
    const cert = pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = generateRandomSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 20);
  
    var attrs = [{
        name: 'commonName',
        value: 'MilleGrille'
    }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);  // Self, generates a self-signed certificate
    cert.setExtensions([{
        name: 'basicConstraints',
        critical: true,
        cA: true,
    }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: false
    }, {
        name: 'subjectKeyIdentifier'
    }, {
        name: 'authorityKeyIdentifier',
        keyIdentifier: true,
    }])
  
    // Signer certificat
    cert.sign(keyPair.privateKey);
  
    // Exporter sous format PEM
    var pem = pki.certificateToPem(cert).replaceAll(/\r/g, '');
  
    return {cert, certPem: pem, encryptedPem};
}

function generateRandomSerialNumber() {
    let rndBuffer = getRandom(8)  // 64 bit
    let value = new BigUint64Array(rndBuffer.buffer)[0];  // Convert to view 64bit unsigned
    let serial = '' + value;
    if(serial.length < 2) {
        serial = '0' + serial
    }
    return serial
}
