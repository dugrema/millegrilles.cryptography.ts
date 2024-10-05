import { pki, ed25519 } from '@dugrema/node-forge';
import { getRandom } from './random';
import { getIdmg } from './certificates';

const CONST_EPOCH_DAY_MS = 24 * 60 * 60 * 1000;                     // Day in ms : 24h * 60min * 60secs * 1000ms
const CONST_SIGNING_CERT_DURATION = 18 * 31 * CONST_EPOCH_DAY_MS;   // 18 months

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

export async function generateIntermediateCertificate(csrPem: string, caPem: string, privateKeyBytes: Uint8Array) {
    // Lire et verifier signature du CSR
    let csr = pki.certificationRequestFromPem(csrPem);
    if(!csr.verify()) throw new Error("Invalid CSR signature");

    let idmg = await getIdmg(caPem);
    let certificatRacine = pki.certificateFromPem(caPem);
    let keyPair = ed25519.generateKeyPair({seed: privateKeyBytes});
    let privateKey = keyPair.privateKey;

    let cert = pki.createCertificate();
    cert.publicKey = csr.publicKey;
    let commonName = csr.subject.getField('CN').value;

    cert.serialNumber = generateRandomSerialNumber();
    cert.validity.notBefore = new Date();
    let expiration = cert.validity.notBefore.getTime() + CONST_SIGNING_CERT_DURATION;
    cert.validity.notAfter = new Date(expiration);

    let akid = certificatRacine.generateSubjectKeyIdentifier().getBytes();

    let attrs = [
        {name: 'commonName', value: commonName},
        {name: 'organizationName', value: idmg}
    ];
    cert.setSubject(attrs);

    cert.setIssuer(certificatRacine.subject.attributes);

    cert.setExtensions([
        {
            name: 'basicConstraints',
            critical: true,
            cA: true,
            pathLenConstraint: 0,
        }, {
            name: 'keyUsage',
            keyCertSign: true,
            cRLSign: true,
        },
        {
            name: 'subjectKeyIdentifier',
        }, 
        {
            name: 'authorityKeyIdentifier',
            keyIdentifier: akid,
        }
    ]);

    // Sign certificate
    cert.sign(privateKey);

    // Export as PEM
    let pem = pki.certificateToPem(cert).replaceAll(/\r/g, '');

    return pem;
}
