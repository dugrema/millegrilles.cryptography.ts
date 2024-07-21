/**
 * This is a wrapper module for multihashes and multibase.
 * Note : The multihashes and multibase libraries are deprecated and should be replaced with multiformats.
 *        The multiformats library currently has issues being imported with jest (for testing).
 */
import multihash from 'multihashes'
import multibase from 'multibase'

/**
 * @returns Encoded hash value.
 * @param encoding Name of the multibase encoding to use.
 * @param hashName Name of the hash function used to produce the hash.
 * @param value Digest produced by the hash function.
 */
export function hashEncode(encoding: multibase.BaseName, hashName: multihash.HashName, digest: Uint8Array): string {
    const encoded = multihash.encode(digest, hashName)
    return baseEncode(encoding, encoded)
}

export function getMultihashBytes(hashName: multihash.HashName, digest: Uint8Array) {
    return multihash.encode(digest, hashName)
}

/**
 * Wrapper for multibase encoding with the supported encodings.
 * @param encoding Name of the multibase encoding.
 * @param value Value to encode.
 * @returns Encoded value.
 */
export function baseEncode(encoding: multibase.BaseName, value: Uint8Array): string {
    // The character encoding list comes from multibase : 
    // https://github.com/multiformats/rust-multibase/blob/master/src/base.rs
    switch(encoding) {
        case 'base58btc':
            return String.fromCharCode.apply(null, multibase.encode('base58btc', value))
        case 'base64pad':
            return String.fromCharCode.apply(null, multibase.encode('base64pad', value))
        case 'base64':
            return String.fromCharCode.apply(null, multibase.encode('base64', value))
        default:
            throw new Error(`Encoding ${encoding} is not supported`);
    }
}

/**
 * Wrapper for multibase decoding.
 * @param value Multibase encoded value.
 * @returns Decoded bytes
 */
export function baseDecode(value: string): Uint8Array {
    return multibase.decode(value)
}

type MultihashDecodeResult = {
    name: multihash.HashName,
    digest: Uint8Array,
}

/**
 * Wrapper for the multihash decode function.
 * @param value Value to decode.
 * @returns Hashname and digest value.
 */
export function multihashDecode(value: string | Uint8Array): MultihashDecodeResult {
    let mbBytes: Uint8Array;
    if(typeof(value) === 'string') {
        mbBytes = multibase.decode(value)
    } else {
        mbBytes = value
    }
    const mh = multihash.decode(mbBytes)
  
    const algo = mh.name
    const digest = mh.digest
  
    return { name: algo, digest }
}
