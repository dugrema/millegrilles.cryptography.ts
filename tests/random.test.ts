import { getRandom } from "../lib/random";

test('random 16', async () => {
    const random16 = getRandom(16);
    expect(random16.length).toBe(16);
});

test('random 32', async () => {
    const random32 = getRandom(32);
    expect(random32.length).toBe(32);
});

test('random 128', async () => {
    const random128 = getRandom(128);
    expect(random128.length).toBe(128);
});
