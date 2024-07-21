import { DomainSignature } from "../lib/keymaster";

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
