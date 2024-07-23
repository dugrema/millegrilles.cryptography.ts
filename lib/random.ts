/**
 * @returns Array of random bytes.
 * @param byteLen Length of the array to generate.
 */
export function getRandom(byteLen: number): Uint8Array {
    let abView: Uint8Array;
    let crypto: any;
    if( typeof(window) !== 'undefined' && window.crypto) {
        // Browser
        crypto = window.crypto;
        const randomAB = new ArrayBuffer(byteLen);
        abView = new Uint8Array(randomAB);
        crypto.getRandomValues(abView);
    } else if( typeof(self) !== 'undefined' && self.crypto ) {
        // Browser web worker
        crypto = self.crypto;
        const randomAB = new ArrayBuffer(byteLen);
        abView = new Uint8Array(randomAB);
        crypto.getRandomValues(abView);
    } else {
        throw new Error('random generator not available');
    }

    return abView;
}
