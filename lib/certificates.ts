import { BasicConstraintsExtension, X509Certificate, Extension } from "@peculiar/x509";
import { baseEncode, encodeHex, getMultihashBytes, decodeBase64, encodeBase64 } from './multiencoding'
import { digest } from "./digest";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "@peculiar/asn1-asym-key";
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';
import { PrivateKey as PrivateKeyPkcs8, PrivateKeyInfo as PrivateKeyInfoPkcs8 } from '@peculiar/asn1-pkcs8';
import { MilleGrillesMessage } from "./messageStruct";

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
    readonly pemChain: string[];
    readonly pemMillegrille?: string;
    extensions?: MilleGrillesCertificateExtensions;

    constructor(pemChain: string[], pemMillegrille?: string) {
        // Save PEMs for future reference (e.g. when signing)
        this.pemChain = pemChain;
        this.pemMillegrille = pemMillegrille;

        // Map the PEMs to certificate objects
        this.chain = pemChain.map(item=>new X509Certificate(item));
        if(pemMillegrille) {
            this.millegrille = new X509Certificate(pemMillegrille);
        }

        // Point to main certificate for easier reference
        this.certificate = this.chain[0];
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
        const publicKeySlice = publicKey.rawData.slice(publicKey.rawData.byteLength-32);
        // Return in hex format
        return encodeHex(publicKeySlice);
    }

    getMillegrillePublicKey(): string {
        if(!this.millegrille) throw new Error("The millegrille certificate was not provided");

        const publicKey = this.millegrille.publicKey;
        if(publicKey.algorithm.name !== 'Ed25519') throw new Error("Unsupported algorithm");
        // Extract the EC public key from this ASN.1 structure
        const publicKeySlice = publicKey.rawData.slice(publicKey.rawData.byteLength-32);

        // Return in hex format
        return encodeHex(publicKeySlice);
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

export function wrapperFromPems(pems: string[], ca?: string): CertificateWrapper {
    return new CertificateWrapper(pems, ca)
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

const CERTIFICATE_END = '-----END CERTIFICATE-----';

export function splitCertificatePems(pems: string) {
    return pems.split(CERTIFICATE_END)
        .filter(item=>item)  // Remove empty elements
        .map(item=>item+CERTIFICATE_END)  // Put the END block back
}

const KEY_BEGIN = '-----BEGIN PRIVATE KEY-----';
const KEY_END = '-----END PRIVATE KEY-----';

export function loadPrivateKeyEd25519(pem: string, password?: string): Uint8Array {
    if(password) throw new Error('not implemented');

    let keyString = pem.replace(KEY_BEGIN, '').replace(KEY_END, '').replace(/\\r\\n/g, '');
    let keyBytes = decodeBase64(keyString.trim());
    let ecParams = AsnConvert.parse(keyBytes, PrivateKeyInfo);
    let privateKey = ecParams.privateKey.slice(ecParams.privateKey.byteLength-32);
    return new Uint8Array(privateKey)
}

export function savePrivateKeyEd25519(key: Uint8Array, password?: string): string {
    if(key.length != 32) throw new Error("The private key must by 32 bytes in length");

    if(password) throw new Error('not implemented');

    // From : https://github.com/PeculiarVentures/asn1-schema/issues/82

    const algorithm = new AlgorithmIdentifier({
        algorithm: '1.3.101.112',
    });

    // CurvePrivateKey ::= OCTET STRING
    const curvePrivateKey = new OctetString(key.length);
    // copy raw
    const edPrivateKeyView = new Uint8Array(curvePrivateKey.buffer);
    edPrivateKeyView.set(key);

    const pkcs8 = new PrivateKeyInfoPkcs8({
        privateKeyAlgorithm: algorithm,
        privateKey: new PrivateKeyPkcs8(AsnConvert.serialize(curvePrivateKey)),
    });
    let keyBase64 = encodeBase64(new Uint8Array(AsnConvert.serialize(pkcs8)));
    
    let pemList = [KEY_BEGIN, keyBase64, KEY_END];
    return pemList.join('\n');
}

export class CertificateCache {
    maxSize: number;
    cacheContent: { [pubkey: string]: { wrapper: CertificateWrapper, date: Date } };

    constructor(maxSize?: number) {
        this.maxSize = maxSize | 20;
        this.cacheContent = {};
    }

    /**
     * @returns Certificate if cached
     * @param pubkey Certificate to load from the cache
     */
    async getCertificate(pubkey: string): Promise<CertificateWrapper> | null {
        let cacheValue = this.cacheContent[pubkey];
        if(cacheValue) {
            cacheValue.date = new Date();  // Touch
            return cacheValue.wrapper;
        }
    }

    /**
     * Saves a certificate in the cache.
     * @param pubkey Public key in hex of this certificate
     * @param chain X509Certificate chain
     * @returns True if saved, false if the cache is full.
     */
    async saveCertificate(chain: string[]): Promise<CertificateWrapper | boolean> {
        if(Object.keys(this.cacheContent).length >= this.maxSize) {
            return false;  // Full
        }

        // Save the wrapper with the public key as identifier.
        let wrapper = new CertificateWrapper(chain)
        wrapper.populateExtensions()
        this.cacheContent[wrapper.getPublicKey()] = {wrapper, date: new Date()};

        return wrapper;
    }

    async touch(pubkey: string) {
        let cacheValue = this.cacheContent[pubkey];
        if(cacheValue) cacheValue['date'] = new Date();
    }

    /**
     * Run regularly to expire the cache entries.
     * @param expiration Expiration of a cache entry after its last access.
     */
    async maintain(expiration?: number) {
        expiration = expiration || 300_000;  // Default is 5 minutes.
        let keys = Object.keys(this.cacheContent);
        let expirationDate = new Date().getTime() - expiration;
        for(let key of keys) {
            let value = this.cacheContent[key];
            if(value.date.getTime() <= expirationDate) {
                delete this.cacheContent[key];
            }
        }
    }

}

export class CertificateStore {
    ca: X509Certificate;
    cache: CertificateCache;

    constructor(ca: string) {
        this.ca = new X509Certificate(ca);
    }

    async verifyCertificate(pems: string[], date?: Date): Promise<boolean> {
        let chain = pems.map(item=>new X509Certificate(item));
        let result = await verifyCertificate(chain, this.ca, date)
        if(result && this.cache) {
            await this.cache.saveCertificate(pems);
        }
        return result
    }

    async verifyMessage(message: MilleGrillesMessage): Promise<CertificateWrapper> {
        let timestamp = message.estampille;
        let messageDate = new Date(timestamp * 1000);

        let publicKey = message.pubkey;
        let certificateWrapper: CertificateWrapper;
        if(this.cache) certificateWrapper = await this.cache.getCertificate(publicKey);
        let chain: X509Certificate[];
        if(certificateWrapper) {
            // We got a cache hit. Recover the chain.
            chain = certificateWrapper.chain;
            // No need to check the pubkey.
            // We got a match from the cache so we know the certificate matches this message (or the 
            // signature check will fail).
            // We still re-verify the chain to check its validity against the message date.
        } else {
            // Cache miss, extract the certificate and parse.
            chain = message.certificate.map(item=>new X509Certificate(item));
            // Ensure that the pubkey field and attached certificate match.
            let certPublickey = chain[0].publicKey;
            if(certPublickey.algorithm.name !== 'Ed25519') throw new Error("Unsupported algorithm");
            let publicKeySlice = certPublickey.rawData.slice(certPublickey.rawData.byteLength-32);
            let publicKeyCert = encodeHex(publicKeySlice);
            if(publicKey !== publicKeyCert) throw new Error('Mismatch between pubkey and attached certificate');
        }

        let verifyResult = await verifyCertificate(chain, this.ca, messageDate)
        if(verifyResult && this.cache && !certificateWrapper) {
            // Save to cache - reuse wrapper if possible.
            let saveResult = await this.cache.saveCertificate(message.certificate);
            if(typeof(saveResult) !== 'boolean') certificateWrapper = saveResult;
        }

        if(!certificateWrapper) {
            // Generate new wrapper for this certificate.
            certificateWrapper = new CertificateWrapper(message.certificate)
        }

        return certificateWrapper
    }
}
