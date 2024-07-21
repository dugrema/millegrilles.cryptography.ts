import { newMessageSigningKey } from '../lib/ed25519';
import {MilleGrillesMessage} from '../lib/messageStruct'

const PRIVATE_KEY = new Uint8Array(Buffer.from('01234567890123456789012345678901234567890123456789012345678901234', 'hex'));

test('sign-message 1', async () => {
    let signingKey = await newMessageSigningKey(PRIVATE_KEY);
    let message = new MilleGrillesMessage(1721592075, 0, 'DUMMY CONTENT');
    await message.sign(signingKey);
    console.debug("Message ", message);
    expect(message.pubkey).toStrictEqual('4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4');
    expect(message.id).toStrictEqual('13981c55d168d1ae35e3e6bbe357a1bca1f4187b1e39ebf9b07cce317ca96318');
    expect(Buffer.from(message.signature).length).toBe(128);

    let result = await message.verify();
    expect(result).toBe(true);
});

test('sign-command', async () => {
    let signingKey = await newMessageSigningKey(PRIVATE_KEY);
    let message = new MilleGrillesMessage(1721592075, 2, 'DUMMY CONTENT');
    message.routage = {domaine: 'DUMMY-DOMAINE', action: 'DUMMY-ACTION'}
    await message.sign(signingKey);
    console.debug("Message ", message);
    expect(message.pubkey).toStrictEqual('4ff87c18844b0575b77946fb84a469b58d931622672b3c2614439bc9b609cdc4');
    expect(message.id).toStrictEqual('1b70b5cf9a7dc222aeb430864f930fc0fe448b6190b03b8739bf1387f56d3c72');
    expect(Buffer.from(message.signature).length).toBe(128);

    let result = await message.verify();
    expect(result).toBe(true);
});
