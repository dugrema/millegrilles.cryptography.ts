import { getMgs4Cipher, getMgs4Decipher } from '../lib/encryption.mgs4'

const BUFFER_1 = new Uint8Array(100);
const BUFFER_2 = new Uint8Array(100_000);
const BUFFER_3 = new Uint8Array(300_000);
const BUFFER_4 = new Uint8Array(65519);

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

test('encrypt-decrypt 2', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_2);
    let finalOutput = await cipher.finalize();
    expect(output.length).toBe(65536)
    expect(finalOutput.length).toBe(34498)

    let {header, key, digest} = cipher;
    expect(header).toBeTruthy()
    expect(key).toBeTruthy()
    expect(digest.length).toBe(64)

    let decipher = await getMgs4Decipher(key, header);
    let clear1 = await decipher.update(output);
    console.debug("Clear 1 ", clear1)
    let clear2 = await decipher.update(finalOutput);
    console.debug("Clear 2 ", clear2)
    let clear3 = await decipher.finalize();
    console.debug("Clear 3 ", clear3)
    expect(clear1.length).toBe(65519)
    expect(clear2).toBeNull()
    expect(clear3.length).toBe(34481)
    expect(Buffer.concat([clear1, clear3])).toStrictEqual(Buffer.from(BUFFER_2));
});

test('encrypt-decrypt 3', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_3);
    let finalOutput = await cipher.finalize();
    expect(output.length).toBe(262144)
    expect(finalOutput.length).toBe(37941)

    let {header, key, digest} = cipher;
    expect(header).toBeTruthy()
    expect(key).toBeTruthy()
    expect(digest.length).toBe(64)

    let decipher = await getMgs4Decipher(key, header);
    let clear1 = await decipher.update(output);
    console.debug("Clear 1 ", clear1)
    let clear2 = await decipher.update(finalOutput);
    console.debug("Clear 2 ", clear2)
    let clear3 = await decipher.finalize();
    console.debug("Clear 3 ", clear3)
    expect(clear1.length).toBe(262076)
    expect(clear2).toBeNull()
    expect(clear3.length).toBe(37924)
    expect(Buffer.concat([clear1, clear3])).toStrictEqual(Buffer.from(BUFFER_3));
});

test('encrypt-decrypt 4', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_4);
    let finalOutput = await cipher.finalize();
    expect(output.length).toBe(65536)
    expect(finalOutput.length).toBe(17)

    let {header, key, digest} = cipher;
    expect(header).toBeTruthy()
    expect(key).toBeTruthy()
    expect(digest.length).toBe(64)

    let decipher = await getMgs4Decipher(key, header);
    let clear1 = await decipher.update(output);
    let clear2 = await decipher.update(finalOutput);
    let clear3 = await decipher.finalize();
    expect(clear1).toStrictEqual(BUFFER_4);
    expect(clear2).toBeNull();
    expect(clear3).toBeNull();
});