import { createCsr } from '../lib/forgeCsr';

test('test generate CSR', async ()=>{
    let { pem, privateKeyPem, privateKey, publicKey } = await createCsr('testUser', 'zABCD1234');
    console.debug("CSR\n%s\mPrivate pem\n%s\nPrivate:%O\nPublic:%O", pem, privateKeyPem, privateKey, publicKey);
    expect(typeof(pem)).toBe('string');
    expect(typeof(privateKeyPem)).toBe('string');
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
})
