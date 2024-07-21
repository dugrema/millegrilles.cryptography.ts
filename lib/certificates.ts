import { BasicConstraintsExtension, X509Certificate, Extension } from "@peculiar/x509";
import { baseEncode, getMultihashBytes } from './multiencoding'
import { digest } from "./digest";

// Custom x509v3 OID extensions for MilleGrille certificates
const OID_EXCHANGES = "1.2.3.4.0";
const OID_ROLES = "1.2.3.4.1";
const OID_DOMAINS = "1.2.3.4.2";
const OID_USERID = "1.2.3.4.3";
const OID_ADMIN_GRANTS = "1.2.3.4.4";
const OID_DOMAIN_GRANTS = "1.2.3.4.5";

export const OIDS = {OID_EXCHANGES, OID_ROLES, OID_DOMAINS, OID_USERID, OID_ADMIN_GRANTS, OID_DOMAIN_GRANTS};

export async function verifyCertificatePem(certificatePems: string[], caCertPem: string, date?: Date | false): Promise<boolean> {
    // Load the CA certificate
    const caCert = new X509Certificate(caCertPem);

    // Map the PEMs to certificate objects
    let chain = certificatePems.map(item=>new X509Certificate(item));
    
    return await verifyCertificate(chain, caCert, date)
}

export async function verifyCertificate(chain: X509Certificate[], ca: X509Certificate, date?: Date | false): Promise<boolean> {
    // Ensure CA certificate has the CA extension flag.
    const caExtensions: BasicConstraintsExtension = ca.getExtension('2.5.29.19');
    if(caExtensions.ca !== true) throw new Error("Invalid CA certificate");

    // Determine the validation date (if any)
    let validationDate = null;  // Date is false, no check is done on the certificate dates
    if(date) {
        validationDate = date;
    } else if(date === false) {
        // Ok, no validation
    } else if(date == null) {
        validationDate = new Date();  // Use current date
    } else {
        throw new Error("Bad value for date. Must be a Date object, false or null.");
    }

    let certs = [...chain]
    // Add the CA cert (self-signed).
    certs.push(ca);

    // Reverse to verify the certificate chain in order (CA/intermediary first).
    certs.reverse();
    
    let parentKey = ca.publicKey;  // Initialise verification with the CA key (self-signed, checks itself)
    for(let cert of certs) {
        if(!parentKey) throw new Error("Invalid chain, at least one signing certificate does not have the CA flag");

        let result = await cert.verify({date: validationDate, publicKey: parentKey, signatureOnly: false});
        if(!result) throw new Error("Invalid certificate");
        
        const basicExtensions: BasicConstraintsExtension = ca.getExtension('2.5.29.19');
        if(basicExtensions && basicExtensions.ca === true) {
            // This is a CA cert (root, intermediary). Use current publicKey to check next certificate.
            parentKey = cert.publicKey;
        } else {
            // This is a leaf certificate. Ensure no other certificates are present by crashing if any.
            parentKey = null;
        }
    }

    return true
}

export type MilleGrillesCertificateExtensions = {
    exchanges?: string[],
    roles?: string[],
    domains?: string[],
    userId?: string,
    adminGrants?: string[],
    domainGrants?: string[],
};

/**
 * Wrapper for a X509 certificate. Adds MilleGrilles specific features.
 */
export class CertificateWrapper {
    readonly certificate: X509Certificate;
    readonly chain: X509Certificate[];
    readonly millegrille?: X509Certificate;
    extensions?: MilleGrillesCertificateExtensions;

    constructor(chain: X509Certificate[], millegrille?: X509Certificate) {
        this.certificate = chain[0];
        this.chain = chain;
        this.millegrille = millegrille;
    }

    populateExtensions() {
        this.extensions = extractMillegrillesExtensions(this.certificate)
    }

    async verify(ca?: X509Certificate, date?: Date | false): Promise<boolean> {
        if(!ca && !this.millegrille) throw new Error("The CA certificate must be provided");
        return await verifyCertificate(this.chain, ca || this.millegrille, date);
    }

    getPublicKey(): string {
        const publicKey = this.certificate.publicKey;
        if(publicKey.algorithm.name !== 'Ed25519') throw new Error("Unsupported algorithm");
        // Extract the EC public key from this ASN.1 structure
        const publicKeySlice = publicKey.rawData.slice(13);
        // Return in hex format
        return Buffer.from(publicKeySlice).toString('hex');
    }

    getCommonName(): string {
        let subject = this.certificate.subjectName;
        return subject.getField('CN').pop()
    }
};

/**
 * Extracts any MilleGrilles specific extensions with their meaning.
 * @param certificate 
 * @returns Extensions present in the certificate.
 */
function extractMillegrillesExtensions(certificate: X509Certificate): MilleGrillesCertificateExtensions {
    const exchanges = readExtensionListValue(certificate.getExtension(OID_EXCHANGES));
    const roles = readExtensionListValue(certificate.getExtension(OID_ROLES));
    const domains = readExtensionListValue(certificate.getExtension(OID_DOMAINS));
    const userId = readExtensionValue(certificate.getExtension(OID_USERID))
    const adminGrants = readExtensionListValue(certificate.getExtension(OID_ADMIN_GRANTS));
    const domainGrants = readExtensionListValue(certificate.getExtension(OID_DOMAIN_GRANTS));
    
    const extensions: MilleGrillesCertificateExtensions = {
        exchanges, roles, domains, userId, adminGrants, domainGrants
    };

    return extensions
}

function readExtensionListValue(extension: Extension) {
    if(!extension) return null;
    const decodedValue = new TextDecoder().decode(extension.value);
    return decodedValue.split(',');
}

function readExtensionValue(extension: Extension) {
    if(!extension) return null;
    return new TextDecoder().decode(extension.value);
}

export function wrapperFromPems(pems: string[], ca?: X509Certificate): CertificateWrapper {
    let chain = pems.map(item=>new X509Certificate(item));
    return new CertificateWrapper(chain, ca)
}

/**
 * Generate a MilleGrilles identifier (IDMG).
 * @param ca CA certificate for the MilleGrille.
 * @returns The IDMG for this certificate.
 */
export async function getIdmg(ca: X509Certificate | string) {
    if(typeof(ca) === 'string') {
        ca = new X509Certificate(ca);
    }

    // Get the public key digest using blake2s-256
    const certDigest = await digest(new Uint8Array(ca.rawData), {encoding: 'bytes', digestName: 'blake2s-256'});
    if(!ArrayBuffer.isView(certDigest)) throw new Error("wrong encoding");
    
    // Encode with multihash
    let certMhDigest = getMultihashBytes('blake2s-256', new Uint8Array(certDigest))

    // Prepare expiration date to fit in 32 bytes
    const expirationDateBuffer = _idmgExpirationTo32Uint(ca.notAfter)

    let outputBuffer = new Uint8Array(41);
    outputBuffer.set([0x2], 0);     // Version 2
    outputBuffer.set(expirationDateBuffer, 1)  // 4 bytes for the expiration date
    outputBuffer.set(certMhDigest, 5); // Multihash of the public key

    return baseEncode('base58btc', outputBuffer)
}

function _idmgExpirationTo32Uint(notAfter: Date): Uint8Array {
    const dateExpEpoch_1000 = Math.ceil(notAfter.getTime() / 1000000);
    const bufferExpiration = new ArrayBuffer(4)
    const view32Uint = new Uint32Array(bufferExpiration)
    view32Uint[0] = dateExpEpoch_1000
  
    return new Uint8Array(bufferExpiration);
}
