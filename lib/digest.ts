import { blake2b, blake2s } from 'hash-wasm';
import { hashEncode, multihashDecode } from './multiencoding';

/** Options for digest(). */
type DigestOpts = {
    digestName?: string,   // Supported hashing algorithm, e.g. blake2b-512, blake2s-256
    encoding?: string,      // String encoding for the hash, e.g. base64, base58btc, bytes
};

/**
 * @returns Digest in multihash format.
 * @param value The value to digest.
 * @param opts Used to change the default digestName and encoding.
 */
export async function digest(value: Uint8Array, opts?: DigestOpts): Promise<string | Uint8Array> {
    opts = opts || {}
    const digestName = opts.digestName || 'blake2b-512'
    const encoding = opts.encoding || 'base58btc'

    const digestView = await digestContent(value, digestName)

    if(encoding === 'bytes') return digestView  // Return Uint8Array

    // @ts-ignore
    return hashEncode(encoding, digestName, digestView)
}

/**
 * @returns True if the digest matches.
 * @throws Error if the digest does not match.
 * @param encodedDigest The multihash encoded value to compare.
 * @param content Content to digest for the comparison.
 */
export async function verifyDigest(encodedDigest: string | Uint8Array, content: Uint8Array) : Promise<boolean> {
    if(!ArrayBuffer.isView(content)) {
        encodedDigest = Buffer.from(encodedDigest);
    }

    const {name, digest: oldDigest} = multihashDecode(encodedDigest);
    const newDigest = await digestContent(content, name);
    if(!ArrayBuffer.isView(newDigest)) { throw new Error('digest: Bad response encoding type'); }  // Narrow newDigest to View

    if(comparerArraybuffers(oldDigest, newDigest)) {
        return true;
    } else {
        throw new Error("Digest mismatch");
    }
}

/**
 * @returns Digest value using the algorithm in digestName.
 * @param value Value to hash.
 * @param digestName Name of the hash function.
 */
async function digestContent(value: Uint8Array, digestName: string): Promise<Uint8Array> {
    switch(digestName.toLocaleLowerCase()) {
        case 'blake2s-256':
        case 'blake2s256':
            return Buffer.from(await blake2s(value), 'hex');
        case 'blake2b-512':
        case 'blake2b512':
            return Buffer.from(await blake2b(value), 'hex');
        default:
            throw new Error(`Digest ${digestName} is not supported`);
    }
}

/**
 * Compares 2 Uint8Arrays.
 * https://stackoverflow.com/questions/21553528/how-to-test-for-equality-in-arraybuffer-dataview-and-typedarray
 * @param buf1 
 * @param buf2 
 * @returns True if the 2 arrays are identical in length and content.
 */
function comparerArraybuffers(buf1: Uint8Array, buf2: Uint8Array) {
    // https://stackoverflow.com/questions/21553528/how-to-test-for-equality-in-arraybuffer-dataview-and-typedarray
    if (buf1.byteLength != buf2.byteLength) return false;
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (buf1[i] != buf2[i]) return false;
    }
    return true;
}
