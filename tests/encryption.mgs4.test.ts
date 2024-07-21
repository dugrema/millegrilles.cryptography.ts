import { getMgs4Cipher, getMgs4Decipher } from '../lib/encryption.mgs4'

const BUFFER_1 = new Uint8Array(100);

test('encrypt-decrypt 1', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_1);
    let finalOutput = await cipher.finalize();
    expect(output).toBeNull()
    expect(finalOutput.length).toBe(117)

    let {header, key, digest} = cipher;
    expect(header).toBeTruthy()
    expect(key).toBeTruthy()
    expect(digest.length).toBe(64)

    let decipher = await getMgs4Decipher(key, header);
    let clear1 = await decipher.update(finalOutput);
    let clear2 = await decipher.finalize();
    expect(clear1).toBeNull()
    expect(clear2).toStrictEqual(BUFFER_1);
});
