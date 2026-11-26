import { digest, verifyDigest } from '../lib/digest'
import { setHashEncodingMode, getHashEncodingMode } from '../lib/multiencoding'

// Default (legacy) hash for "A simple message" using blake2b-512
// with multihashes v4 code 0xb240.
const LEGACY_HASH = "zSEfXUDE8fEDqjh8DJp5d4e7izp6vmCfHMCFgnbKtfLoHttXnEs3UNeAywD4LFmBAWrL91dvHHSLbecqZ7FmADfBRiqfQa"

// Modern hash for "A simple message" using blake2b-512
// with multiformats code 0xb5.
const MODERN_HASH = "z6NBK7Z1Dey1SNRXNi85K4AnVpHkLKJuCvLbiKwZUnHrvhFhb6dCbMa2EDRHuiZk8WBY46pywUjgVzZcsiHi58x7qAeMU"

test('digest legacy mode', async () => {
    const message = new TextEncoder().encode("A simple message");

    // Verify default mode is legacy
    expect(getHashEncodingMode()).toBe('legacy');

    const digestResult = await digest(message);
    expect(digestResult).toBe(LEGACY_HASH);

    expect(await verifyDigest(digestResult, message)).toBe(true);
});

test('digest modern mode', async () => {
    const message = new TextEncoder().encode("A simple message");

    // Switch to modern mode
    setHashEncodingMode('modern');
    try {
        const digestResult = await digest(message);
        // Modern hash uses code 0xb5 instead of 0xb240, producing a different output
        expect(digestResult).not.toBe(LEGACY_HASH);

        // Verify modern hash works
        expect(await verifyDigest(digestResult, message)).toBe(true);

        // Verify legacy hash still works in modern mode (backward compat decode)
        expect(await verifyDigest(LEGACY_HASH, message)).toBe(true);
    } finally {
        // Restore legacy mode
        setHashEncodingMode('legacy');
    }
});

test('verifyDigest accepts both legacy and modern hashes', async () => {
    const message = new TextEncoder().encode("A simple message");

    // Verify legacy hash
    expect(await verifyDigest(LEGACY_HASH, message)).toBe(true);

    // Verify modern hash (generate one and check it works too)
    setHashEncodingMode('modern');
    try {
        const modernResult = await digest(message);
        expect(await verifyDigest(modernResult, message)).toBe(true);
    } finally {
        setHashEncodingMode('legacy');
    }
});
