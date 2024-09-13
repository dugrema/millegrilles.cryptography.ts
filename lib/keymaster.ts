import _sodium from 'libsodium-wrappers';
import stringify from "json-stable-stringify";
import { generateKeypairEd5519, signMessage, verifyMessageSignature } from "./ed25519";
import { digest } from "./digest";
import { baseDecode } from "./multiencoding";
import { multiencoding } from '.';

const CURRENT_VERSION = 1;

export class DomainSignature {
    domaines: string[];
    version: number;
    signature: string;  // Base64 no padding encoding of the signed domain.
    ca?: string;

    constructor(domaines: string[], version?: number, ca?: string) {
        this.domaines = domaines;
        this.version = typeof(version)==='number'?version:CURRENT_VERSION;
        this.ca = ca;
    }

    /**
     * Sign the domain list allowed to decrypt this key.
     * @param secretKey Secret key being encrypted
     */
    async sign(secretKey: Uint8Array) {
        this.signature = await signDomains(secretKey, this.domaines)
    }

    async verify(secretKey: Uint8Array): Promise<boolean> {
        return await verifyDomains(secretKey, this.domaines, this.signature);
    }

    /**
     * Reusable unique value to identify this key.
     * @returns {string} Blake2s digest of the signature as a base58btc string.
     */
    async getKeyId(): Promise<string> {
        if(!this.signature) throw new Error("Missing signature")
        let signatureBytes = multiencoding.decodeBase64Nopad(this.signature);
        let shortDigestBytes = await digest(signatureBytes, {encoding: 'bytes', digestName: 'blake2s-256'}) as Uint8Array;
        let shortDigestString =  multiencoding.encodeBase58btc(shortDigestBytes);
        // Retain the 'z' multibase marker
        return 'z' + shortDigestString;
    }
}

/**
 * Signs the domains with a secret key.
 * @param secretKey Secret key that is being saved for the domains
 * @param domains List of domains allowed to decrypt this key
 * @returns Signature
 */
async function signDomains(secretKey: Uint8Array, domains: string[]): Promise<string> {
    let domainsBytes = new TextEncoder().encode(stringify(domains));

    // Digest with blake2s-256, encode with base64 without padding
    let digestBytes = await digest(domainsBytes, {encoding: 'bytes', digestName: 'blake2s-256'});
    if(!ArrayBuffer.isView(digestBytes)) throw new Error('digest result of wrong type');
    
    let signatureBase64 = await signMessage(secretKey, digestBytes);
    signatureBase64 = signatureBase64.slice(1);  // Remove leading 'm' from multibase encoding
    
    return signatureBase64
}

async function verifyDomains(secretKey: Uint8Array, domains: string[], signature: string): Promise<boolean> {
    let key = await generateKeypairEd5519(secretKey);
    let domainsBytes = new TextEncoder().encode(stringify(domains));

    let digestBytes = await digest(domainsBytes, {encoding: 'bytes', digestName: 'blake2s-256'});
    if(!ArrayBuffer.isView(digestBytes)) throw new Error('digest result of wrong type');

    let signatureBytes = baseDecode('m'+signature);

    return await verifyMessageSignature(key.public, digestBytes, signatureBytes);
}
