import _sodium from 'libsodium-wrappers';
import { getRandom } from './random';
import { createBLAKE2b } from 'hash-wasm';
import { IHasher } from 'hash-wasm/dist/lib/WASMInterface';

export async function getMgs4Cipher() {
    await _sodium.ready;
    const sodium = _sodium;

    // Generate new key
    let key = getRandom(32);
    let {state, header} = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    let hasher = await createBLAKE2b();
    hasher.init();
    return new Mgs4Cipher(key, state, header, hasher);
}

const MGS4_ENCRYPT_BLOCK_SIZE = 1024 * 64 - 17;
const MGS4_DECRYPT_BLOCK_SIZE = 1024 * 64;

class Mgs4Cipher {
    readonly key: Uint8Array;
    state: _sodium.StateAddress;
    header: Uint8Array;
    hasher: IHasher;
    excessBuffer: Uint8Array | null;
    digest?: Uint8Array;

    constructor(key: Uint8Array, state: _sodium.StateAddress, header: Uint8Array, hasher: IHasher) {
        this.key = key;
        this.state = state;
        this.header = header;
        this.hasher = hasher;
    }

    async update(chunk: Uint8Array): Promise<Uint8Array | null> {
        await _sodium.ready;
        const sodium = _sodium;

        if(!chunk || chunk.byteLength === 0) return;

        let encryptedOutputs: Uint8Array[] = [];

        // Concatenate excess buffer with new chunk
        let bufferInputs = [];
        if(this.excessBuffer) bufferInputs.push(this.excessBuffer);
        bufferInputs.push(chunk);
        let filledBuffer = Buffer.concat(bufferInputs);
        
        // Encrypt while there is enough data to fill blocks.
        let position = 0;
        while(filledBuffer.length >= MGS4_ENCRYPT_BLOCK_SIZE + position) {
            let currentSlice = filledBuffer.subarray(position, position+MGS4_ENCRYPT_BLOCK_SIZE)
            
            let encryptedChunk = sodium.crypto_secretstream_xchacha20poly1305_push(
                this.state, currentSlice, null, 
                _sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

            encryptedOutputs.push(encryptedChunk);
            
            // Apply encrypted chunk to hash function
            this.hasher.update(encryptedChunk);

            position += MGS4_ENCRYPT_BLOCK_SIZE;
        }

        // Save excess data
        if(position > 0) {
            this.excessBuffer = filledBuffer.subarray(position);
        } else {
            this.excessBuffer = filledBuffer;
        }

        // Convert outputs to Uint8Array if applicable.
        if(encryptedOutputs.length === 1) return encryptedOutputs[0];
        else if(encryptedOutputs.length > 0) {
            let buffer = Buffer.concat(encryptedOutputs);
            return buffer.subarray(0)
        }
        else {
            // Chunk too small to produce output.
            return null;
        }
    }

    async finalize(): Promise<Uint8Array | null> {
        await _sodium.ready;
        const sodium = _sodium;

        let finalBuffer = null;
        if(this.excessBuffer) finalBuffer = this.excessBuffer;
        let encryptedOutput = sodium.crypto_secretstream_xchacha20poly1305_push(
            this.state, finalBuffer, null, 
            _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        
        if(encryptedOutput) {
            // Apply encrypted chunk to hash function
            this.hasher.update(encryptedOutput);
        }

        this.digest = this.hasher.digest('binary');
        
        // Extract authentication tag from last 16 bytes
        return encryptedOutput;
    }
}

export async function getMgs4Decipher(key: Uint8Array, header: Uint8Array) {
    await _sodium.ready;
    const sodium = _sodium;


    let state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
    return new Mgs4Decipher(key, state, header)
}

class Mgs4Decipher {
    readonly key: Uint8Array;
    state: _sodium.StateAddress;
    header: Uint8Array;
    hasher: IHasher;
    excessBuffer: Uint8Array | null;

    constructor(key: Uint8Array, state: _sodium.StateAddress, header: Uint8Array) {
        this.key = key;
        this.state = state;
        this.header = header;
    }

    async update(chunk: Uint8Array): Promise<Uint8Array | null> {
        await _sodium.ready;
        const sodium = _sodium;

        if(!chunk || chunk.byteLength === 0) return;

        let encryptedOutputs: Uint8Array[] = [];

        // Concatenate excess buffer with new chunk
        let bufferInputs = [];
        if(this.excessBuffer) bufferInputs.push(this.excessBuffer);
        bufferInputs.push(chunk);
        let filledBuffer = Buffer.concat(bufferInputs);
        
        // Encrypt while there is enough data to fill blocks.
        let position = 0;
        while(filledBuffer.length >= MGS4_DECRYPT_BLOCK_SIZE + position) {
            let currentSlice = filledBuffer.subarray(position, position+MGS4_DECRYPT_BLOCK_SIZE);
            let {message: decryptedChunk, tag} = sodium.crypto_secretstream_xchacha20poly1305_pull(
                this.state, currentSlice, null);

            encryptedOutputs.push(decryptedChunk);
    
            if(tag === _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
                throw new Error("MGS4 TODO Final tag on update");
            }
            if(tag !== _sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) {
                throw new Error("MGS4 Decryption error, out of sync");
            }

            position += MGS4_DECRYPT_BLOCK_SIZE;
        }

        // Save excess data
        if(position > 0) {
            this.excessBuffer = filledBuffer.subarray(position);
        } else {
            this.excessBuffer = filledBuffer;
        }

        // Convert outputs to Uint8Array if applicable.
        if(encryptedOutputs.length === 1) return encryptedOutputs[0];
        else if(encryptedOutputs.length > 0) {
            let buffer = Buffer.concat(encryptedOutputs);
            return new Uint8Array(buffer);
        }
        else {
            // Chunk too small to produce output.
            return null;
        }        
    }
    
    async finalize(): Promise<Uint8Array | null> {
        await _sodium.ready;
        const sodium = _sodium;

        if(this.excessBuffer == null) return

        let finalBuffer = new Uint8Array(this.excessBuffer);
        let {message: decryptedChunk, tag} = sodium.crypto_secretstream_xchacha20poly1305_pull(
            this.state, finalBuffer, null);
        
        if(tag !== _sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            throw new Error("MGS4 Decryption error, out of sync");
        }
        
        if(decryptedChunk.length === 0) return null;
        return decryptedChunk;
    }    
}
