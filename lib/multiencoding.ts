/**
 * Wrapper module for multihash and multibase encoding / decoding.
 *
 * Replaces the deprecated `multihashes` and `multibase` packages.
 * All functions are implemented natively — no external dependencies needed.
 *
 * Dual-mode hash encoding:
 * - `legacy` (default): uses multihashes v4 custom codes for backward
 *   compatibility (e.g. blake2b-512 → 0xb240, blake2s-256 → 0xb260).
 * - `modern`: uses standard multiformats codes (0xb5 for blake2b, 0xb2 for blake2s).
 *
 * Call `setHashEncodingMode('modern')` to generate new-format hashes.
 * Decoding always accepts both legacy and modern codes.
 */

// ---------------------------------------------------------------------------
// Varint encoding / decoding (protobuf-style, matches varint v5.0.2)
// ---------------------------------------------------------------------------

function encodeVarint(num: number): number[] {
    const INT = Math.pow(2, 31)
    const MSB = 0x80
    const REST = 0x7f
    const MSBALL = ~REST
    const out: number[] = []

    while (num >= INT) {
        out.push((num & 0xff) | MSB)
        num /= 128
    }
    while (num & MSBALL) {
        out.push((num & 0xff) | MSB)
        num >>>= 7
    }
    out.push(num | 0)
    return out
}

function decodeVarint(buf: Uint8Array, offset: number): { value: number; bytes: number } {
    let res = 0
    let shift = 0
    let counter = offset
    const MSB = 0x80
    const REST = 0x7f

    while (counter < buf.length) {
        const b = buf[counter++]
        res += shift < 28
            ? (b & REST) << shift
            : (b & REST) * Math.pow(2, shift)
        shift += 7
        if (b < MSB) break
    }

    return { value: res, bytes: counter - offset }
}

// ---------------------------------------------------------------------------
// Base58 (Bitcoin) encoding / decoding
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE58_ALPHABET_MAP: Record<string, number> = {}
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    BASE58_ALPHABET_MAP[BASE58_ALPHABET[i]] = i
}

function base58Encode(input: Uint8Array): string {
    if (input.length === 0) return ''

    let zeroes = 0
    while (zeroes < input.length && input[zeroes] === 0) zeroes++

    const result: number[] = [0]
    for (const byte of input) {
        let carry = byte
        for (let i = 0; i < result.length; i++) {
            carry += result[i] << 8
            result[i] = carry % 58
            carry = (carry / 58) | 0
        }
        while (carry > 0) {
            result.push(carry % 58)
            carry = (carry / 58) | 0
        }
    }

    for (let i = 0; i < zeroes; i++) result.push(0)
    result.reverse()

    return result.map((n) => BASE58_ALPHABET[n]).join('')
}

function base58Decode(input: string): Uint8Array {
    if (input.length === 0) return new Uint8Array(0)

    let zeroes = 0
    while (zeroes < input.length && input[zeroes] === '1') zeroes++

    const result: number[] = [0]
    for (const char of input) {
        const digit = BASE58_ALPHABET_MAP[char]
        if (digit === undefined) throw new Error(`Invalid base58 character: ${char}`)
        let carry = digit
        for (let i = 0; i < result.length; i++) {
            carry += result[i] * 58
            result[i] = carry & 0xff
            carry = carry >>> 8
        }
        while (carry > 0) {
            result.push(carry & 0xff)
            carry >>>= 8
        }
    }

    for (let i = 0; i < zeroes; i++) result.push(0)
    result.reverse()

    let firstNonZero = 0
    while (firstNonZero < result.length && result[firstNonZero] === 0) firstNonZero++
    return new Uint8Array(result.slice(firstNonZero))
}

// ---------------------------------------------------------------------------
// Base64 encoding / decoding
// ---------------------------------------------------------------------------

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const BASE64_URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

function base64Encode(input: Uint8Array, alphabet: string, pad: boolean): string {
    let result = ''
    const len = input.length
    for (let i = 0; i < len; i += 3) {
        const a = input[i]
        const b = i + 1 < len ? input[i + 1] : 0
        const c = i + 2 < len ? input[i + 2] : 0
        const triple = (a << 16) | (b << 8) | c
        result += alphabet[(triple >> 18) & 0x3f]
        result += alphabet[(triple >> 12) & 0x3f]
        result += alphabet[(triple >> 6) & 0x3f]
        result += alphabet[triple & 0x3f]
    }
    if (pad) {
        const mod = len % 3
        if (mod === 1) result = result.slice(0, -2) + '=='
        else if (mod === 2) result = result.slice(0, -1) + '='
    } else {
        const mod = len % 3
        if (mod === 1) result = result.slice(0, -2)
        else if (mod === 2) result = result.slice(0, -1)
    }
    return result
}

function base64Decode(input: string, alphabet: string): Uint8Array {
    const padCount = input.match(/=+$/)?.[0].length ?? 0
    const clean = input.replace(/=+$/, '')

    const charToVal = new Map<string, number>()
    for (let i = 0; i < alphabet.length; i++) {
        charToVal.set(alphabet[i], i)
    }
    charToVal.set('=', 61)

    let resultLen = Math.floor(clean.length * 3 / 4)
    const result = new Uint8Array(resultLen)
    let pos = 0

    for (let i = 0; i < clean.length; i += 4) {
        const a = charToVal.get(clean[i]) ?? 0
        const b = charToVal.get(clean[i + 1]) ?? 0
        const c = charToVal.get(clean[i + 2]) ?? 0
        const d = charToVal.get(clean[i + 3]) ?? 0
        const triple = (a << 18) | (b << 12) | (c << 6) | d
        result[pos++] = (triple >> 16) & 0xff
        if (pos < resultLen) result[pos++] = (triple >> 8) & 0xff
        if (pos < resultLen) result[pos++] = triple & 0xff
    }

    return result
}

// ---------------------------------------------------------------------------
// Hash encoding mode (legacy vs modern)
// ---------------------------------------------------------------------------

type HashEncodingMode = 'legacy' | 'modern'
let currentMode: HashEncodingMode = 'legacy'

/**
 * Set the hash encoding mode.
 * - `legacy`: uses multihashes v4 custom codes (backward compatible).
 *   blake2b-512 → 0xb240, blake2s-256 → 0xb260, sha2-256 → 0x12, sha2-512 → 0x13.
 * - `modern`: uses standard multiformats codes.
 *   blake2b-512 → 0xb5, blake2s-256 → 0xb2, sha2-256 → 0x12, sha2-512 → 0x13.
 *
 * Decoding always accepts both legacy and modern codes.
 * Use this to switch between generating old-format or new-format hashes.
 */
export function setHashEncodingMode(mode: HashEncodingMode): void {
    currentMode = mode
}

/** Get the current hash encoding mode. */
export function getHashEncodingMode(): HashEncodingMode {
    return currentMode
}

// ---------------------------------------------------------------------------
// Multihash helpers — dual-mode support
// ---------------------------------------------------------------------------

/** Standard multiformats code → name mapping. */
const STANDARD_CODE_TO_NAME: Record<number, string> = {
    0xb2: 'blake2s256',
    0xb5: 'blake2b512',
    0x12: 'sha2256',
    0x13: 'sha2512',
}

/** Legacy multihashes v4 code → name mapping. */
const LEGACY_CODE_TO_NAME: Record<number, string> = {
    0xb260: 'blake2s256',
    0xb240: 'blake2b512',
    0x12: 'sha2256',
    0x13: 'sha2512',
}

/** Standard name → { code, length } mapping. */
const MODERN_NAME_TO_META: Record<string, { code: number; length: number }> = {
    'blake2s-256': { code: 0xb2, length: 32 },
    'blake2s256': { code: 0xb2, length: 32 },
    'blake2b-512': { code: 0xb5, length: 64 },
    'blake2b512': { code: 0xb5, length: 64 },
    'sha2-256': { code: 0x12, length: 32 },
    'sha256': { code: 0x12, length: 32 },
    'sha2-512': { code: 0x13, length: 64 },
    'sha512': { code: 0x13, length: 64 },
}

/** Legacy multihashes v4 name → { code, length } mapping. */
const LEGACY_NAME_TO_META: Record<string, { code: number; length: number }> = {
    'blake2s-256': { code: 0xb260, length: 32 },
    'blake2s256': { code: 0xb260, length: 32 },
    'blake2b-512': { code: 0xb240, length: 64 },
    'blake2b512': { code: 0xb240, length: 64 },
    'sha2-256': { code: 0x12, length: 32 },
    'sha256': { code: 0x12, length: 32 },
    'sha2-512': { code: 0x13, length: 64 },
    'sha512': { code: 0x13, length: 64 },
}

/** Multihash digest code / length pair. */
export type HashMeta = { code: number; length: number }

/** Result of decoding a multihash-encoded value. */
type MultihashDecodeResult = {
    name: string,  // Internal name (e.g. 'blake2s256')
    digest: Uint8Array,
}

/**
 * Encode raw digest bytes into a multihash buffer.
 */
function encodeMultihash(hashMeta: HashMeta, digest: Uint8Array): Uint8Array {
    const codeBytes = encodeVarint(hashMeta.code)
    const lenBytes = encodeVarint(hashMeta.length)
    const mh = new Uint8Array(codeBytes.length + lenBytes.length + digest.length)
    mh.set(codeBytes, 0)
    mh.set(lenBytes, codeBytes.length)
    mh.set(digest, codeBytes.length + lenBytes.length)
    return mh
}

/**
 * @returns Multibase-encoded multihash string.
 * @param encoding Multibase encoding name.
 * @param hashMeta Hash code and length.
 * @param digest Raw digest bytes.
 */
export function hashEncode(encoding: string, hashMeta: HashMeta, digest: Uint8Array): string {
    const mhBytes = encodeMultihash(hashMeta, digest)
    return baseEncode(encoding, mhBytes)
}

/**
 * @returns Raw multihash bytes (varint code + length + digest).
 */
export function getMultihashBytes(hashMeta: HashMeta, digest: Uint8Array): Uint8Array {
    return encodeMultihash(hashMeta, digest)
}

/**
 * Resolve a name string to a HashMeta object based on the current mode.
 */
export function nameToHashMeta(name: string): HashMeta {
    const map = currentMode === 'legacy' ? LEGACY_NAME_TO_META : MODERN_NAME_TO_META
    const meta = map[name]
    if (!meta) throw new Error(`Unknown hash name: ${name} in mode '${currentMode}'`)
    return meta
}

// ---------------------------------------------------------------------------
// Base encoding / decoding
// ---------------------------------------------------------------------------

/**
 * Multibase encoding.
 * @param encoding Base name ('base58btc', 'base64', 'base64pad').
 * @param value Bytes to encode.
 * @returns Encoded string (including multibase prefix).
 */
export function baseEncode(encoding: string, value: Uint8Array): string {
    switch (encoding) {
        case 'base58btc':
            return 'z' + base58Encode(value)
        case 'base64pad':
            return 'M' + base64Encode(value, BASE64_CHARS, true)
        case 'base64':
            return 'm' + base64Encode(value, BASE64_CHARS, false)
        default:
            throw new Error(`Encoding ${encoding} is not supported`)
    }
}

/**
 * Multibase decoding (expects prefix character included).
 * @param value Multibase-encoded string.
 * @returns Decoded bytes.
 */
export function baseDecode(value: string): Uint8Array {
    const prefix = value[0]
    const payload = value.slice(1)
    switch (prefix) {
        case 'z':
            return base58Decode(payload)
        case 'M':
            return base64Decode(payload, BASE64_CHARS)
        case 'm':
            return base64Decode(payload, BASE64_CHARS)
        case 'u':
            return base64Decode(payload, BASE64_URL_CHARS)
        default:
            throw new Error(`Unknown multibase prefix: ${prefix}`)
    }
}

/**
 * @returns Base64 encoded value with no '=' padding (no prefix).
 */
export function encodeBase64Nopad(value: Uint8Array): string {
    return base64Encode(value, BASE64_CHARS, false)
}

export function decodeBase64Nopad(value: string): Uint8Array {
    return base64Decode(value, BASE64_CHARS)
}

export function encodeBase64Url(value: Uint8Array): string {
    return base64Encode(value, BASE64_URL_CHARS, false)
}

export function decodeBase64Url(value: string): Uint8Array {
    return base64Decode(value, BASE64_URL_CHARS)
}

export function encodeBase64(value: Uint8Array): string {
    return base64Encode(value, BASE64_CHARS, true)
}

export function decodeBase64(value: string): Uint8Array {
    return base64Decode(value, BASE64_CHARS)
}

export function encodeBase58btc(value: Uint8Array): string {
    return base58Encode(value)
}

export function decodeBase58btc(value: string): Uint8Array {
    return base58Decode(value)
}

export function encodeHex(value: Uint8Array | ArrayBuffer): string {
    const view: Uint8Array = ArrayBuffer.isView(value) ? value : new Uint8Array(value)
    return Array.from(view).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function decodeHex(value: string): Uint8Array {
    const result = new Uint8Array(value.length / 2)
    for (let i = 0; i < value.length; i += 2) {
        result.set([parseInt(value.slice(i, i + 2), 16)], i / 2)
    }
    return result
}

/**
 * Decode a multibase-encoded multihash.
 * Accepts both legacy (multihashes v4) and modern (multiformats) hash codes.
 * @param value Multibase-encoded string or raw multihash bytes.
 * @returns Hash name and digest value.
 */
export function multihashDecode(value: string | Uint8Array): MultihashDecodeResult {
    let mbBytes: Uint8Array
    if (typeof value === 'string') {
        mbBytes = baseDecode(value)
    } else {
        mbBytes = value
    }

    const { value: code, bytes: codeLen } = decodeVarint(mbBytes, 0)
    const { value: length, bytes: lenLen } = decodeVarint(mbBytes, codeLen)

    const digestOffset = codeLen + lenLen
    const digest = mbBytes.slice(digestOffset, digestOffset + length)

    // Accept both legacy and standard codes
    const name = LEGACY_CODE_TO_NAME[code]
        ?? STANDARD_CODE_TO_NAME[code]
        ?? `code:${code.toString(16)}`
    return { name, digest }
}
