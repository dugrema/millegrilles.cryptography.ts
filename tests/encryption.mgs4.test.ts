import { getMgs4Cipher, getMgs4Decipher } from '../lib/encryption.mgs4'

const BUFFER_100b = new Uint8Array(100);
const BUFFER_100k = new Uint8Array(100_000);
const BUFFER_EXACT = new Uint8Array(65519);

test('encrypt-decrypt 100b', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_100b);
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
    expect(clear2).toStrictEqual(BUFFER_100b);
});

test('encrypt-decrypt 100k', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_100k);
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
    expect(Buffer.concat([clear1, clear3])).toStrictEqual(Buffer.from(BUFFER_100k));
});

test('encrypt-decrypt 1MB', async () => {
    let cipher = await getMgs4Cipher();
    let output: Uint8Array[] = []
    for(let i=0; i<10; i++) {
        let out = await cipher.update(BUFFER_100k);
        output.push(out)
    }
    let finalOutput = await cipher.finalize();
    let outputBuffer = Buffer.concat(output)
    expect(outputBuffer.length).toBe(983040)
    expect(finalOutput.length).toBe(17232)

    let {header, key, digest} = cipher;
    expect(header).toBeTruthy()
    expect(key).toBeTruthy()
    expect(digest.length).toBe(64)

    let decipher = await getMgs4Decipher(key, header);
    let clear1 = await decipher.update(outputBuffer);
    let clear2 = await decipher.update(finalOutput);
    let clear3 = await decipher.finalize();
    expect(clear1.length).toBe(982785);
    expect(clear2).toBeNull();
    expect(clear3.length).toBe(17215);
    // Check only first part (BUFFER_2 is repeated)
    expect(Buffer.from(clear1).subarray(0,BUFFER_100k.length)).toStrictEqual(Buffer.from(BUFFER_100k));
});

test('encrypt-decrypt 100MB', async () => {
    let cipher = await getMgs4Cipher();
    let output: Uint8Array[] = []
    for(let i=0; i<1000; i++) {
        let out = await cipher.update(BUFFER_100k);
        output.push(out)
    }
    let finalOutput = await cipher.finalize();
    let outputBuffer = Buffer.concat(output)
    expect(outputBuffer.length).toBe(100007936)
    expect(finalOutput.length).toBe(18023)

    let {header, key, digest} = cipher;
    expect(header).toBeTruthy()
    expect(key).toBeTruthy()
    expect(digest.length).toBe(64)

    let decipher = await getMgs4Decipher(key, header);
    let clear1 = await decipher.update(outputBuffer);
    let clear2 = await decipher.update(finalOutput);
    let clear3 = await decipher.finalize();
    expect(clear1.length).toBe(99981994);
    expect(clear2).toBeNull();
    expect(clear3.length).toBe(18006);
    // Check only first part (BUFFER_2 is repeated)
    expect(Buffer.from(clear1).subarray(0,BUFFER_100k.length)).toStrictEqual(Buffer.from(BUFFER_100k));
});

test('encrypt-decrypt exact blocksize', async () => {
    let cipher = await getMgs4Cipher();
    let output = await cipher.update(BUFFER_EXACT);
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
    expect(clear1).toStrictEqual(BUFFER_EXACT);
    expect(clear2).toBeNull();
    expect(clear3).toBeNull();
});
