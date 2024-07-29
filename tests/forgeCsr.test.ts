import { createCsr } from '../lib/forgeCsr';

test('test generate CSR', async ()=>{
    let { pem, privateKey, publicKey } = await createCsr('testUser', 'zABCD1234');
    console.debug("CSR\n%s\nPrivate:%O\nPublic:%O", pem, privateKey, publicKey);
    expect(typeof(pem)).toBe('string');
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
})
