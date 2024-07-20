/**
 * @returns Array of random bytes.
 * @param byteLen Length of the array to generate.
 */
export function getRandom(byteLen: number) {
    let abView: Uint8Array;
    if( typeof(window) !== 'undefined' && window.crypto) {
        // Browser
        const crypto = window.crypto;
        const randomAB = new ArrayBuffer(byteLen);
        abView = new Uint8Array(randomAB);
        crypto.getRandomValues(abView);
    } else if( typeof(self) !== 'undefined' && self.crypto ) {
        // Browser web worker
        crypto = self.crypto;
        const randomAB = new ArrayBuffer(byteLen);
        abView = new Uint8Array(randomAB);
        crypto.getRandomValues(abView);
    } else if( typeof(crypto) !== 'undefined' ) {
        // Nodejs
        abView = new Uint8Array(byteLen);
        abView = crypto.getRandomValues(abView);
    } else {
        throw new Error('random generator not available');
    }

    return abView;
}
