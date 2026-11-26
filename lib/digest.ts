import { blake2b, blake2s, createBLAKE2b, createBLAKE2s } from 'hash-wasm';
import { decodeHex, hashEncode, multihashDecode, HashMeta, nameToHashMeta } from './multiencoding';
import { IHasher } from 'hash-wasm/dist/lib/WASMInterface';
import { multiencoding } from '.';

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

    if (encoding === 'bytes') return digestView  // Return Uint8Array

    const hashMeta = nameToMeta(digestName)
    // @ts-ignore
    return hashEncode(encoding, hashMeta, digestView)
}

/**
 * @returns True if the digest matches.
 * @throws Error if the digest does not match.
 * @param encodedDigest The multihash encoded value to compare.
 * @param content Content to digest for the comparison.
 */
export async function verifyDigest(encodedDigest: string | Uint8Array, content: Uint8Array): Promise<boolean> {
    if (!ArrayBuffer.isView(content)) {
        encodedDigest = new Uint8Array(content);
    }

    const { name, digest: oldDigest } = multihashDecode(encodedDigest);
    const newDigest = await digestContent(content, name);
    if (!ArrayBuffer.isView(newDigest)) { throw new Error('digest: Bad response encoding type'); }  // Narrow newDigest to View

    if (comparerArraybuffers(oldDigest, newDigest)) {
        return true;
    } else {
        throw new Error("Digest mismatch");
    }
}

/**
 * @returns Digest value using the algorithm in digestName.
 * @param value Value to hash.
 * @param digestName Internal name (e.g. 'blake2s256').
 */
async function digestContent(value: Uint8Array, digestName: string): Promise<Uint8Array> {
    switch (digestName.toLocaleLowerCase()) {
        case 'blake2s-256':
        case 'blake2s256':
            return decodeHex(await blake2s(value));
        case 'blake2b-512':
        case 'blake2b512':
            return decodeHex(await blake2b(value));
        default:
            throw new Error(`Digest ${digestName} is not supported`);
    }
}

export class WrappedHasher {
    baseName: string
    hashMeta: HashMeta
    hasher: IHasher | null | undefined;
    digest: string | null | undefined;

    constructor(baseName: string, hashMeta: HashMeta) {
        this.baseName = baseName;
        this.hashMeta = hashMeta;
    }

    async init() {
        this.hasher = await createHasher(this.hashMeta) || null;
    }

    update(chunk: Uint8Array) {
        if (!this.hasher) throw new Error('Hasher not initialized (run obj.init())');
        this.hasher.update(chunk);
    }

    finalize(): string {
        const digestBytes = this.hasher?.digest('binary');
        if (!digestBytes) throw new Error("Hasher is not defined");
        this.digest = hashEncode(this.baseName, this.hashMeta, digestBytes);
        return this.digest;
    }
}

export async function createHasher(hashMeta: HashMeta): Promise<IHasher> {
    let hasher: IHasher;
    switch (hashMeta.code) {
        case 0xb2:  // blake2s-256
            hasher = await createBLAKE2s();
            break;
        case 0xb5:  // blake2b-512
            hasher = await createBLAKE2b();
            break;
        default:
            throw new Error(`Hash code ${hashMeta.code} is not supported`);
    }
    hasher.init();
    return hasher;
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
    for (var i = 0; i != buf1.byteLength; i++) {
        if (buf1[i] != buf2[i]) return false;
    }
    return true;
}

function nameToMeta(name: string): HashMeta {
    return nameToHashMeta(name)
}
