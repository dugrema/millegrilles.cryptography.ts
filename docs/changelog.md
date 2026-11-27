# Changelog

All notable changes to **millegrilles.cryptographie.ts** are documented in this file.

The findings referenced below (numbers and `L#` ids) correspond to
`docs/security_assessment_2026-11-25.md`.

## [Unreleased]

### Removed
- **`@dugrema/node-forge`**, the private Git-fork dependency, is gone (`package.json`),
  along with the `forgeCsr` and `forgePrivateKey` namespaces (`lib/forgeCsr.ts`,
  `lib/forgePrivateKey.ts`, `lib/forge.d.ts`). This closes `#4` (no audit trail, no
  registry patch tracking, build breaks if the private Git host is unavailable).
  **Breaking change** for consumers — see `docs/migration-notes.md` for the exact
  call-site rewrites in `millegrilles.authentication.typescript` and
  `millegrilles.coupdoeil.react`.
- `forgePrivateKey.generateNewPrivateKeyPem`, `generateMilleGrilleCertificate` and
  `generateIntermediateCertificate` are removed with no replacement. They were CA
  issuance helpers with a hard-coded 20-year certificate validity (`#11`) and had no
  caller left in the ecosystem; issue certificates with a real CA instead.

### Added
- **Encrypted PKCS#8 private keys are now supported** (`#13`). `loadPrivateKeyEd25519`
  decrypts `ENCRYPTED PRIVATE KEY` blocks written by OpenSSL, python-cryptography and the
  old node-forge fork: PBES2 / PBKDF2 (HMAC-SHA1, SHA-256, SHA-384, SHA-512) with
  AES-128/192/256-CBC, using WebCrypto so it works in Node and in browsers. DES, 3DES,
  PBES1 and other non-decryptable schemes are rejected with an explicit error rather than
  silently failing. Passwords are decoded as UTF-8.
  - New internal module `lib/pkcs8.ts` with a bounded DER reader: indefinite lengths,
    non-minimal length encodings, multi-byte tags, truncated elements, negative
    iteration counts, absurd PEM sizes and runaway PBKDF2 iteration counts are all
    rejected before any crypto is performed.
- `certificates.loadPrivateKeyPem(pem, password?)` — decrypts to a plain PKCS#8 PEM.
- `certificates.isEncryptedPrivateKeyPem(pem)` — tells a caller whether a password is
  required without trying to load the key.
- `certificates.verifyCsr(pem)` — replaces `forgeCsr.verifyUserCsr`. Verifies the Ed25519
  self-signature (SubtleCrypto with a libsodium fallback, like certificate verification),
  rejects CSRs not signed with Ed25519, and returns
  `{ commonName, userId?, publicKeyHex }`.
- `ed25519.loadSigningKeyFromPems(..., password?)` accepts an optional password so an
  encrypted signing key can be loaded in one call.

### Changed
- **Breaking**: `loadPrivateKeyEd25519` is now `async` and returns `Promise<Uint8Array>`.
  Call sites that pass an unencrypted key keep working once they `await`.
- **Breaking**: `generateCsr` returns `csr` instead of `pem`, and now also returns
  `privateKeyPem`, `privateKey` (32-byte seed), `publicKey` and `keys` (the generated
  `CryptoKeyPair`), so a CSR + keypair can be created without the removed forge helpers.
  Keys it writes are standard RFC 8410 PKCS#8 (`openssl pkey` can read them), unlike the
  non-standard shape the fork emitted; both shapes still *load*.
- `getCommonName()`, `extractMillegrillesExtensions()` and `verifyCsr()` read the
  **first** CN (`getField("CN")[0]`) instead of the last (`.pop()`).
- `savePrivateKeyEd25519(key, password)` still refuses to encrypt — it says so in terms of
  what to use instead, rather than saying "not implemented".
- Pinned `@peculiar/asn1-asym-key`, `@peculiar/asn1-pkcs8`, `@peculiar/asn1-schema` and
  `@peculiar/asn1-x509` to `2.11.1`, and added `@peculiar/asn1-csr@2.11.1` as a direct
  dependency. The previous mix resolved to two copies of `@peculiar/asn1-schema`, which
  made every `@peculiar/x509` CSR parse and generate call fail with
  `Cannot get schema for 'CertificationRequestInfo' target`.

### Tests
- `tests/privateKey.test.ts`: OpenSSL (AES-256-CBC, HMAC-SHA256, UTF-8 password),
  OpenSSL (AES-128-CBC, PRF field absent → HMAC-SHA1 default), node-forge legacy
  (HMAC-SHA512), wrong password, missing password, truncated DER, 3DES and PBES1
  rejection, non-Ed25519 key rejection, save/load round-trip.
- CSR generation is now asserted to *work*, plus verification of a CSR produced by
  another tool and rejection of a tampered one.

## [2026.8.1] - 2026-11-26

Security release addressing the 2026-11-25 automated security assessment.
It bundles the fixes already applied on this version line with the hardening
passes completed on 2026-11-26.

### Fixed in this pass (2026-11-26)

- **[HIGH] `#20` Certificate chain validated against attacker-controlled timestamp**
  (`lib/certificates.ts`, `CertificateStore.verifyMessage`). The chain is now
  validated against the current wall-clock by default instead of the message's
  own `estampille`. A holder of an expired key could previously backdate
  `estampille` into the certificate's old validity window and reactivate it.
  Added an explicit `options.validateAt` opt-in that lets a *trusted* caller
  (e.g. replaying a transaction from a redo-log backup) validate against a
  recorded historical date; the opt-in pins a date, it does not skip expiry.
  - Added a 5-minute clock-skew tolerance (`CERT_VALIDITY_SKEW_MS`) to the
    validity-period comparison.
- **[MEDIUM] `#8` Decompression bomb (completed the partial fix)**
  (`lib/messageStruct.ts`, `decryptMessageContent`). Replaced `pako.ungzip`
  with a streaming `pako.Inflate` that accumulates a running byte total and
  aborts as soon as the 10 MB cap is exceeded, instead of materialising the
  entire plaintext first.
- **[MEDIUM] `#10` `splitCertificatePems` could produce invalid PEM blocks**
  (`lib/certificates.ts`). Replaced the `split(CERTIFICATE_END)` approach with a
  regex anchored to `^-----BEGIN CERTIFICATE-----` at line start and matching
  non-greedily to the END marker. Each returned block is now self-contained
  (BEGIN and END headers preserved), text sitting between/before certificates is
  ignored, and a stray END marker in surrounding text no longer corrupts the
  first block.
- **[Logic] `L1` `date: false` did not disable certificate date checks**
  (`lib/certificates.ts`, `verifyCertificate` / `verifyCertficateKeys`). The
  `false` and `undefined` cases were collapsed and fell back to the current
  clock, so the documented "skip date checks" option never actually skipped
  them. `verifyCertificate` now resolves `Date` / `false` / `null` distinctly
  and threads an explicit `skipDateCheck` flag through verification.
- **[Logic] `L2` `verifyDigest` guarded the wrong argument** (`lib/digest.ts`).
  The `ArrayBuffer.isView(content)` guard mutated `encodedDigest`; the block was
  both unreachable and incorrect, and has been removed.
- **[Logic] `L4` `decryptKey` returned `undefined` for unexpected input length**
  (`lib/keymaster.ts`). Any length that is neither 32 nor 80 bytes now throws
  with the actual length instead of falling through to an implicit `undefined`.
- **[LOW] `#17` Certificate date comparison used strict `<`**
  (`lib/certificates.ts`). Resolved as part of the `#20` work: validity bounds
  are now inclusive (`<=`) so a certificate valid exactly at `notAfter` is
  accepted, alongside the added skew tolerance.
- **[LOW] `#16` Duplicate `reflect-metadata` import** (`lib/messageStruct.ts`).
  Removed the redundant side-effect import. `lib/index.ts` already imports it
  and no decorators or reflection APIs are used, so it served no purpose and
  only pulled the polyfill in when `messageStruct` was loaded directly.
- **[LOW] `#18` `MilleGrillesMessage` constructor did not validate required
  fields** (`lib/messageStruct.ts`). The constructor now rejects a missing /
  non-numeric / `NaN` `estampille`, an out-of-range `kind`, and an empty
  `contenu` (type-based, so a legitimate epoch-0 stamp or `Document` kind 0 is
  still accepted). Since `parseMessage` builds through the constructor,
  malformed input now fails loudly instead of producing an invalid message.

### Tests

- Added an expired-leaf fixture generator (`tests/certificates.test.ts`) and
  tests covering `#20` (default rejection, trusted `validateAt` acceptance,
  out-of-window rejection, wall-clock-not-estampille) and `L1` (`date: false`
  truly skips).
- Added a `splitCertificatePems` suite (`tests/certificates.test.ts`) for `#10`
  (single/multiple blocks, leading prose with a stray END marker, round-trip
  parseability, empty input).
- Added a streaming decompression-bomb test (`tests/messageStruct.test.ts`).
- Added a `decryptKey` unexpected-length rejection test
  (`tests/keymaster.test.ts`).
- Added a `MilleGrillesMessage` constructor-validation suite
  (`tests/messageStruct.test.ts`) for `#18` (missing/wrong-typed fields,
  legitimate zero values, malformed `parseMessage` inputs).

### Previously applied on this version line (from the 2026-11-25 audit)

- **[HIGH] `#2` Wrong certificate referenced in the chain-building loop**
  (`lib/certificates.ts:105`). Each certificate's own `basicConstraints`
  extension is now inspected (`cert.getExtension(...)`) rather than the CA's.
- **[HIGH] `#3` ASN.1 parsing without bounds validation**
  (`lib/certificates.ts`, `loadPrivateKeyEd25519`). Added a
  `privateKey.byteLength < 32` check; maliciously short keys now throw
  `"Invalid private key: too short"`.
- **[HIGH] `#5` PKCS#8 key parsing did not validate the algorithm OID**
  (`lib/certificates.ts`, `loadPrivateKeyEd25519`). The OID is checked against
  Ed25519 (`1.3.101.112`); mismatched keys throw.
- **[MEDIUM] `#7` `CertificateCache` had no eviction when full**
  (`lib/certificates.ts`). `saveCertificate()` now calls `maintain()` before
  rejecting new entries, evicting expired entries and retrying.
- **[MEDIUM] `#8` Decompression bomb (first iteration)**
  (`lib/messageStruct.ts`). A 10 MB maximum decompressed size check was added
  (completed by the streaming fix above in this pass).
- **[MEDIUM] `#9` Deprecated `multihashes` and `multibase` packages removed**
  (`lib/multiencoding.ts`). Replaced with a native multibase/multihash
  implementation supporting legacy and modern hash codes; decoding accepts both
  regardless of mode.

### Known open items (not addressed in this release)

- `#4` Private `@dugrema/node-forge` Git-fork dependency (audit upstream).
- `N1` Possibly-unused `multiformats` dependency (confirm intent or drop).
- `N2` Breaking API changes (`createHasher`, `WrappedHasher`, `domaines`,
  `cleSecrete`) - keep deprecated aliases under a major version bump.
- `L3` Non-constant-time digest comparison, `L6` `pathLenConstraint` not
  enforced, `#11` 20-year CA validity, `#13` password support not implemented.
