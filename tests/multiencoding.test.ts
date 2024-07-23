import { encodeHex, decodeHex } from '../lib/multiencoding'
// require('./hachage.config');

test('hex 1', async () => {
    const BUF = new Uint8Array([0x1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    const VAL1 = "0123456789abcdef";
    const VAL2 = "0123456789ABCDEF";

    let output1 = decodeHex(VAL1);
    let output2 = decodeHex(VAL2);
    expect(output1).toStrictEqual(BUF);
    expect(output1).toStrictEqual(output2);

    let output3 = encodeHex(BUF);
    expect(output3).toStrictEqual(VAL1);
});

