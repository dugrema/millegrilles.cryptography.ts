# MilleGrilles Cryptographie Library (TypeScript)

The **millegrilles.cryptographie.ts** package is a full‑featured reference implementation of the cryptographic primitives and certificate handling used by the MilleGrilles project.  
It is written in TypeScript, builds to ES2020 modules, and is designed to run both in Node.js and in modern browsers.

---

## Table of Contents

- [Installation & Build](#installation--build)
- [Project Structure](#project-structure)
- [Core Modules](#core-modules)
  - [Certificates & X.509](#certificates--x509)
  - [Digest](#digest)
  - [Ed25519](#ed25519)
  - [Encryption](#encryption)
  - [Keymaster](#keymaster)
  - [Message Structure](#message-structure)
  - [Multiencoding](#multiencoding)
  - [Random](#random)
  - [X25519](#x25519)
  - [CSR / PrivateKey Generation](#csr--privatekey-generation)
- [Examples](#examples)
- [Testing](#testing)
- [License](#license)
- [Contributing](#contributing)

---

## Installation & Build

```bash
# Install dependencies
npm install

# Build the library
npm run build

# Run unit tests
npm test
```

The output is placed in the `dist/` directory and is ready to be imported:

```ts
import * as crypto from 'millegrilles.cryptographie';
```

---

## Project Structure

```
millegrilles.cryptographie.ts/
├─ lib/                # Source TS modules
├─ dist/               # Build output (ESM)
├─ tests/              # Jest unit tests
├─ AGENTS.md           # This documentation
├─ README.md
├─ package.json
├─ tsconfig.json
└─ rollup.config.mjs
```

---

## Core Modules

### Certificates & X.509

Handles parsing, verification, and extraction of custom MilleGrilles extensions.

- **verifyCertificatePem** – Verify a chain of PEM certificates against a CA.
- **CertificateWrapper** – Object representation with helper methods (`getPublicKey`, `populateExtensions`, etc.).
- **OID definitions** – Custom OIDs for MilleGrilles (`exchanges`, `roles`, `domains`, etc.).

*See `lib/certificates.ts` for full API.*

### Digest

Provides multihash digests using Blake2 variants.

- `digest(value: Uint8Array, opts?)`: returns a multihash string or raw bytes.
- `verifyDigest(encodedDigest, content)`: verifies content against a multihash.
- `WrappedHasher`: streaming hasher.

*See `lib/digest.ts`.*

### Ed25519

Key generation, signing, and verification.

- `generateKeypairEd5519(secret)`: deterministic keypair from a 32‑byte seed.
- `signMessage`, `verifyMessageSignature`.
- `signDomains` / `verifyDomains` (used by `keymaster`).

*See `lib/ed25519.ts`.*

### Encryption

Chacha20-Poly1305 helpers.

- `encryptChacha20Poly1305(content, nonce, key)`.
- `decryptChacha20Poly1305(ciphertext, nonce, key)`.
- `concatBuffers`: concatenate multiple Uint8Arrays.

*See `lib/encryption.ts`.*

### Keymaster

Manages domain‑restricted key encryption and decryption.

- `DomainSignature`: sign/verify allowed domains.
- `decryptKey(encryptedKey, privateKey)`: returns decrypted secret.
- `encryptionResultToBase64`: convert raw result to Base64.

*See `lib/keymaster.ts`.*

### Message Structure

Defines the JSON schema for MilleGrilles messages, including encryption metadata, signatures, and optional compression.

```ts
export type MessageStruct = {
  // ... fields defined in lib/messageStruct.ts
};
```

*See `lib/messageStruct.ts`.*

### Multiencoding

Convenient helpers for multibase / multihash encoding/decoding.

- `hashEncode`, `hashDecode`.
- `encodeBase64`, `decodeBase64`.
- `baseEncode`, `baseDecode`.
- `encodeHex`, `decodeHex`.

*See `lib/multiencoding.ts`.*

### Random

Secure random byte generation using `crypto.getRandomValues` / `libsodium`.

```ts
export function randomBytes(length: number): Uint8Array;
```

*See `lib/random.ts`.*

### X25519

Ephemeral key exchange helpers (X25519 + Ed25519 integration).

- `secretFromEd25519PrivateX25519Peer`.
- `decryptEd25519`.

*See `lib/x25519.ts`.*

### CSR / PrivateKey Generation

- `forgeCsr`: generate a CSR from a keypair.
- `forgePrivateKey`: generate a new Ed25519 private key.

*See `lib/forgeCsr.ts` & `lib/forgePrivateKey.ts`.*

---

## Examples

```ts
import { randomBytes } from 'millegrilles.cryptographie/random';
import { generateKeypairEd5519, signMessage, verifyMessageSignature } from 'millegrilles.cryptographie/ed25519';
import { encryptChacha20Poly1305, decryptChacha20Poly1305 } from 'millegrilles.cryptographie/encryption';

// 1. Key generation
const seed = randomBytes(32);
const { private, public } = await generateKeypairEd5519(seed);

// 2. Sign a message
const payload = new TextEncoder().encode('Hello world');
const signature = await signMessage(private, payload);

// 3. Verify signature
const valid = await verifyMessageSignature(public, payload, signature);
console.log('Signature valid', valid);

// 4. Encrypt
const nonce = randomBytes(12);
const plaintext = new TextEncoder().encode('Secret data');
const ciphertext = await encryptChacha20Poly1305(plaintext, nonce, public);

// 5. Decrypt
const decrypted = await decryptChacha20Poly1305(ciphertext, nonce, public);
console.log('Decrypted', new TextDecoder().decode(decrypted));
```

---

## Testing

All unit tests are in `tests/`. Run:

```bash
npm test
```

The test suite covers:

- Digest hashing and verification
- Ed25519 key generation and signing
- X25519 key exchange
- Certificate chain validation
- Encryption/decryption round‑trips

---

## License

MIT © 2024 MilleGrilles

---

## Contributing

Feel free to open issues or pull requests.  
Ensure that tests pass and that the library remains fully typed.

---

*For more details, refer to the source files under `lib/` and the inline documentation within each module.*