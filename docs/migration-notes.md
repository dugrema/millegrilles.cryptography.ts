# Migration notes: removing the private `@dugrema/node-forge` fork

Audience: applications that import `millegrilles.cryptography` — notably
`millegrilles.authentication.typescript` and `millegrilles.coupdoeil.react`.

The private fork `@dugrema/node-forge` (`git+https://git.maple.maceroc.com/forge.git#ed25519`)
has been dropped. It was the only dependency pulled from a private Git host, with no
registry audit trail (finding `#4` of `docs/security_assessment_2026-11-25.md`).

Everything it provided is now implemented on top of `@peculiar/x509` and WebCrypto,
so no app needs node-forge (or any other crypto library) to keep working.

---

## 1. Removed and replaced API

The namespaces `forgeCsr` and `forgePrivateKey` **no longer exist**. Their replacements
live in the `certificates` namespace.

| Old | New | Notes |
|---|---|---|
| `forgeCsr.createCsr(username, userId?)` → `{ pem, privateKeyPem, privateKey, publicKey }` | `certificates.generateCsr(username, userId?)` → `Promise<{ csr, privateKeyPem, privateKey, publicKey, keys }>` | `pem` is renamed **`csr`**. Also returns `keys: CryptoKeyPair`. |
| `forgeCsr.verifyUserCsr(pem)` → `string` | `certificates.verifyCsr(pem)` → `Promise<{ commonName, userId?, publicKeyHex }>` | Now async. Also returns the `userId` extension and the CSR public key in hex. |
| `forgeCsr.loadPrivateKey(pem, password?)` → `Uint8Array` | `certificates.loadPrivateKeyEd25519(pem, password?)` → `Promise<Uint8Array>` | Now async. Returns the 32-byte seed in both cases. |
| `forgePrivateKey.loadEd25519PrivateKey(pem, { password, pemout })` → `{ privateKeyBytes, pem? }` | `certificates.loadPrivateKeyEd25519(pem, password)` for the bytes, or `certificates.loadPrivateKeyPem(pem, password)` → `Promise<string>` for the PEM | The options object is gone: pick the function that returns what you need. |
| `forgePrivateKey.generateNewPrivateKeyPem({ password })` | **removed**, no replacement | Use `certificates.generateCsr(...).privateKeyPem`, or `openssl genpkey -algorithm ED25519`. |
| `forgePrivateKey.generateMilleGrilleCertificate(password)` | **removed**, no replacement | CA issuance with a hard-coded 20-year validity (finding `#11`). Use an actual CA (`step-ca`, `openssl`, the MilleGrilles CA service). |
| `forgePrivateKey.generateIntermediateCertificate(...)` | **removed**, no replacement | Same reason. |

New in `certificates`:
`isEncryptedPrivateKeyPem(pem)` — tells you whether a keyfile needs a password.

`ed25519.loadSigningKeyFromPems(privateKeyPem, certificateChain, caPem, password?)` gained an
optional 4th argument so an encrypted signing key can be loaded in one call.

---

## 2. Encrypted private keys: what is supported

`ENCRYPTED PRIVATE KEY` PEMs (PKCS#8 / PBES2) are decrypted with WebCrypto, in Node and
in browsers, with:

- KDF: **PBKDF2**, PRF HMAC-SHA1 / SHA-256 / SHA-384 / SHA-512 (an absent `prf` field
  defaults to HMAC-SHA1, per RFC 8018)
- Cipher: **AES-128-CBC / AES-192-CBC / AES-256-CBC**

That covers `openssl genpkey -aes-256-cbc`, `openssl pkcs8 -topk8 -v2 …`,
python-cryptography's `BestAvailableEncryption`, and the older keys the node-forge fork
wrote (PBKDF2-HMAC-SHA512).

Explicitly **rejected** with a clear error: DES, 3DES, RC2/RC4, PBES1 (PKCS#5 v1.5),
SHA-224 PRF, and any non-PBKDF2 KDF. SubtleCrypto cannot decrypt those, and they should
not be re-enabled.

Other limits: salt ≥ 8 bytes, iteration count ≤ 10 000 000 (PBKDF2 runs on the caller's
thread; a browser tab is not a good place to burn 100M iterations), PEM body ≤ 16 KiB.

**Passwords are read as UTF-8.** This matches OpenSSL and python-cryptography. A key
whose password contains non-ASCII characters and was written by a tool using latin-1 will
fail to decrypt — there is no latin-1 fallback, on purpose.

Wrong-password behaviour: `"Unable to decrypt the private key (wrong password?)"`. A
missing password on an encrypted key gives
`"The private key is encrypted, a password is required"`. A password passed for an
unencrypted key is ignored.

Key format note: the old fork wrote a **non-standard** PKCS#8 (the 32-byte seed wrapped in
an OCTET STRING *plus* the public key appended after it). The loader accepts both that
shape and the standard RFC 8410 one, but everything the library now *writes* is standard,
so `openssl pkey` can read it.

---

## 3. Behaviour changes to watch for

1. **Everything crypto-related is now async.** Missing `await` shows up as a TypeScript
   error (`Promise<Uint8Array>` is not assignable to `Uint8Array`), which is the intended
   way to find the call sites.
2. **CN resolution is first-wins.** `getCommonName()`, `extractMillegrillesExtensions()`
   and `verifyCsr()` now read `getField("CN")[0]` instead of `.pop()`. Certificates with a
   single CN (all real ones) are unaffected.
3. **`verifyCsr` rejects CSRs that are not signed with Ed25519** (the old helper accepted
   any algorithm forge could verify).
4. **Private keys are validated before use**: the Ed25519 algorithm OID is checked, the
   seed must be exactly 32 bytes, and non-Ed25519 keys are rejected with
   `Invalid algorithm OID for Ed25519 private key`.

---

## 4. Exact call sites in the consumer apps

These are the places that need a change. Nothing else in those apps touches the removed
namespaces.

### `millegrilles.authentication.typescript/src/workers/connection.worker.ts` (~line 100)

```ts
// Before
async createCertificateRequest(username: string, userId?: string): Promise<{pem: string, privateKeyPem: string, privateKey: Uint8Array, publicKey: Uint8Array}> {
    return await forgeCsr.createCsr(username, userId);
}
```

```ts
// After — keep the wrapper's shape so `Login.tsx` and the IDB entries keep working
async createCertificateRequest(username: string, userId?: string): Promise<{pem: string, privateKeyPem: string, privateKey: Uint8Array, publicKey: Uint8Array}> {
    const result = await certificates.generateCsr(username, userId);
    return {
        pem: result.csr,            // the field was renamed to `csr` in the library
        privateKeyPem: result.privateKeyPem,
        privateKey: result.privateKey,
        publicKey: result.publicKey,
    };
}
```

`src/Login.tsx` (`createCertificateRequest`, ~line 675) and the `UserCertificateRequest`
entries in `src/idb/userStoreIdb.ts` keep the name `pem`, so **no change is needed there**
as long as the worker maps `csr` → `pem`. If you prefer to rename the field everywhere,
`UserCertificateRequest.pem` and its two readers (`registerAccount(username, certificateRequest.pem)`
and the recovery screen) are the only spots.

Also update the import on line 2:

```ts
// Before
import { forgeCsr, messageStruct } from 'millegrilles.cryptography'
// After
import { certificates, messageStruct } from 'millegrilles.cryptography'
```

### `millegrilles.authentication.typescript/src/ActivateCode.tsx`

Line ~312, verifying the CSR returned by the recovery flow:

```ts
// Before
let usernameCsr = forgeCsr.verifyUserCsr(csr);
// After
let usernameCsr = (await certificates.verifyCsr(csr)).commonName;
```

The surrounding callback is already `async`. If you want the extra fields, the result is
`{ commonName, userId?, publicKeyHex }` — `userId` lets you double-check the request came
from the expected account instead of trusting the CN alone.

Line ~440, loading the delegated CA key:

```ts
// Before
let privateCaKey = forgeCsr.loadPrivateKey(keyFile.racine.cleChiffree, password);
// After
let privateCaKey = await certificates.loadPrivateKeyEd25519(keyFile.racine.cleChiffree, password);
```

`activateDelegation` is already `async`, and the value still goes straight into
`ed25519.newMessageSigningKey`.

Import, line 6:

```ts
// Before
import { certificates, ed25519, forgeCsr, messageStruct } from 'millegrilles.cryptography';
// After
import { certificates, ed25519, messageStruct } from 'millegrilles.cryptography';
```

### `millegrilles.coupdoeil.react/src/utilities/MasterKeyLoader.tsx` (~line 67)

```ts
// Before
let decryptedKey = forgePrivateKey.loadEd25519PrivateKey(encryptedKey.racine.cleChiffree, {password, pemout: true});
setInvalid(false);
setPassword('');
setEncryptedKey(null);
let decryptedKeyBytes = decryptedKey.privateKeyBytes;
onChange({file: encryptedKey, key: decryptedKeyBytes});
```

```ts
// After — `pemout` is dropped: the PEM output was never used here
let decryptedKeyBytes = await certificates.loadPrivateKeyEd25519(encryptedKey.racine.cleChiffree, password);
setInvalid(false);
setPassword('');
setEncryptedKey(null);
onChange({file: encryptedKey, key: decryptedKeyBytes});
```

The call sits inside a `useEffect`, so wrap it in an async function (or keep the existing
`try/catch` and use `.then`). The `catch` already turns any failure — wrong password
included — into `setInvalid(true)`, which keeps the current UX.

Import, line 3:

```ts
// Before
import { certificates, forgePrivateKey } from 'millegrilles.cryptography';
// After
import { certificates } from 'millegrilles.cryptography';
```

---

## 5. Rolling out

1. Bump `millegrilles.cryptography` to the release that removes the fork.
2. `grep -rn "forgeCsr\|forgePrivateKey" src/` — the TypeScript errors do the rest.
3. Re-key nothing: both existing keyfile shapes (plain PKCS#8 and PBES2-encrypted) load
   unchanged, including keys written by the old fork.
4. If a keyfile was ever encrypted with a latin-1 password containing non-ASCII
   characters, it will now fail to decrypt. That is the documented UTF-8 contract; re-encrypt
   such a keyfile with OpenSSL if one turns up.
