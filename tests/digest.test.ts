import { digest, verifyDigest } from '../lib/digest'
// require('./hachage.config');

test('digest 1', async () => {
    const message = new TextEncoder().encode("A simple message");
    
    const digestResult = await digest(message);
    expect(digestResult).toBe("zSEfXUDE8fEDqjh8DJp5d4e7izp6vmCfHMCFgnbKtfLoHttXnEs3UNeAywD4LFmBAWrL91dvHHSLbecqZ7FmADfBRiqfQa");
    
    expect(await verifyDigest(digestResult, message)).toBe(true);
});
