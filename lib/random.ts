/**
 * @returns Array of random bytes.
 * @param byteLen Length of the array to generate.
 */
export function getRandom(byteLen: number): Uint8Array {
    let abView: Uint8Array;
    let cryptoHandle: any;
    if( typeof(window) !== 'undefined' && window.crypto) {
        // Browser
        cryptoHandle = window.crypto;
        const randomAB = new ArrayBuffer(byteLen);
        abView = new Uint8Array(randomAB);
        cryptoHandle.getRandomValues(abView);
    } else if( typeof(self) !== 'undefined' && self.crypto ) {
        // Browser web worker
        cryptoHandle = self.crypto;
        const randomAB = new ArrayBuffer(byteLen);
        abView = new Uint8Array(randomAB);
        cryptoHandle.getRandomValues(abView);
    } else if( typeof(crypto) !== 'undefined' ) {
        // Nodejs
        abView = new Uint8Array(byteLen);
        abView = crypto.getRandomValues(abView);
    } else {
        throw new Error('random generator not available');
    }

    return abView;
}
