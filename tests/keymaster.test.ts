import "reflect-metadata";
import { DomainSignature, decryptKey } from "../lib/keymaster";

const CA_PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

test('sign domains 1', async () => {
    let ds = new DomainSignature(['DomainA', 'DomainB']);
    await ds.sign(CA_PRIVATE_KEY);
    expect(ds.signature).toBeTruthy();

    let result = await ds.verify(CA_PRIVATE_KEY);
    expect(result).toBe(true);
});

test('sign domains err', async () => {
    expect.assertions(2)

    let ds = new DomainSignature(['DomainA', 'DomainB']);
    await ds.sign(CA_PRIVATE_KEY);
    expect(ds.signature).toBeTruthy();

    // Corrupt the domains
    ds.domaines = ['DomainA', 'DomainC']
    
    // Ensure failure at verify
    try {
        await ds.verify(CA_PRIVATE_KEY);
    } catch(err) {
        expect(err).toBeTruthy()
    }
    
});

test('decryptKey rejects unexpected key length (L4)', async () => {
    // 16 bytes is neither 32 (direct) nor 80 (indirect); must throw rather than
    // silently return undefined.
    const badKey = new Uint8Array(16);
    await expect(decryptKey(badKey, CA_PRIVATE_KEY)).rejects.toThrow(
        "Invalid encrypted key length",
    );
});
