# Project Overview

The **millegrilles.cryptographie.ts** repository implements the cryptographic primitives, certificate handling, and related utilities used by the MilleGrilles project.  
It is a TypeScript library that can be built and used in Node.js or browser environments.

## Key Features

- **X.509 Certificate Management** – parse, verify, and extract custom MilleGrilles extensions.  
- **Digest** – Blake2 multihash support with streaming API.  
- **Ed25519** – deterministic key generation, signing, and verification.  
- **Encryption** – Chacha20-Poly1305 helpers for authenticated encryption.  
- **Keymaster** – domain‑restricted key encryption/decryption.  
- **CSR & PrivateKey Generation** – helpers for creating CSRs and new Ed25519 keys.  
- **Multiencoding** – convenient multibase / multihash conversion utilities.  
- **Random** – secure random byte generator.  
- **X25519** – X25519 key exchange helpers integrated with Ed25519.  

All modules expose fully typed interfaces and are documented inline. The library is tested with Jest and builds to an ES2020‑compatible `dist/` folder.

## Getting Started

```bash
# Install dependencies
npm install

# Build the library
npm run build

# Run tests
npm test
```

Import the compiled library in your project:

```ts
import * as crypto from 'millegrilles.cryptographie';
```

## License

MIT © 2024 MilleGrilles