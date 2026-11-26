# Security Assessment Report

**Library**: millegrilles.cryptography.ts  
**Date**: 2026-11-25  
**Version**: 2026.7.1 (reviewed); working tree at 2026.8.1  
**Assessor**: Automated security review, completed & re-verified against source  
**Status**: Completed 2026-11-25 -- every finding re-checked against the working tree, verdicts corrected, new findings added. No code changed in the original pass (documentation only).  
**Update 2026-11-26**: code pass landed on `fix20261126` (shipped as `2026.8.1`). `#20`, `#8` (now fully), `#17`, `L1`, `L2` and `L4` are **Resolved** and moved to "Resolved & Partially Resolved"; the Summary Table was updated accordingly. See `docs/changelog.md`.  
**Update 2026-11-26 (follow-up)**: second code pass on `fix20261126` resolved `#10` (PEM splitting), `#16` (duplicate `reflect-metadata` import) and `#18` (constructor field validation). Moved to "Resolved & Partially Resolved"; Summary Table and remaining-priorities notes updated.  

---

## Severity Legend

- **CRITICAL** - Direct compromise of confidentiality, integrity, or authenticity
- **HIGH** - Significant weakness that could be exploited
- **MEDIUM** - Design flaw or missing mitigation
- **LOW** - Code quality / best practice issue
- **INFO** - Observations and recommendations

---

## CRITICAL

**No critical findings confirmed after re-verification.**

The only critical candidate in the original automated review -- the deterministic ChaCha20 nonce in X25519 encryption (was #1) -- was re-checked against the source and is a **false positive**. Full analysis is recorded under "Reclassified / Working As Intended" below.

---

## HIGH

### 4. `@dugrema/node-forge` fork from a private Git repository (`package.json:39`)

```
"@dugrema/node-forge": "git+https://git.maple.maceroc.com/forge.git#ed25519"
```

Using a private, non-NPM fork as a direct dependency means:
- No vulnerability tracking or patch auditing from the npm registry
- Supply chain risk: if the Git hosting service goes down, the build breaks
- The fork's changes are opaque to reviewers
- Node-forge itself has had multiple past CVEs (e.g., CVE-2022-24771 signature verification bypass); even if patched in this fork, there's no way to verify

**Recommendation**: Audit the fork's diff against upstream node-forge, and track it for security patches. Consider upstreaming changes.

---

## MEDIUM

### 6. `verifyDigest` throws on mismatch instead of returning `false` (`lib/digest.ts:50`)

```ts
if(comparerArraybuffers(oldDigest, newDigest)) {
    return true;
} else {
    throw new Error("Digest mismatch");
}
```

The function returns `true` on match but throws on mismatch, making it asymmetric and harder to use safely. Callers must use try/catch or risk unhandled exceptions. This is especially risky in message verification pipelines where a malformed digest should be handled gracefully.

**Recommendation**: Return `false` on mismatch instead of throwing.

---

### 11. `generateMilleGrilleCertificate` uses 20-year validity (`lib/forgePrivateKey.ts:57`)

```ts
cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 20);
```

A 20-year CA certificate validity is extremely long by modern standards. CA certificates are typically 5-10 years. This increases the attack window if the CA private key is compromised.

**Recommendation**: Reduce CA certificate validity to 5-10 years.

---

## LOW

### 12. `console.info` used in production code (`lib/certificates.ts:149`)

```ts
console.info("Subtle does not support Ed25519, reverting to libsodium");
```

Console statements in production code can leak information and should be replaced with a proper logging abstraction or removed.

---

### 13. `savePrivateKeyEd25519` and `loadPrivateKeyEd25519` don't support encryption (`lib/certificates.ts:401,422`)

```ts
if(password) throw new Error("not implemented");
```

The "not implemented" error is clear, but it's worth noting that the public API suggests password support exists.

---

### 14. `DomainSignature` property name inconsistency (`lib/keymaster.ts:17`)

Uses the French spelling `domaines` instead of `domains`. While not a security issue, it's inconsistent with the rest of the codebase and could cause confusion for international developers.

---

### 15. `cleSecrete` typo in `EncryptionResult` / `EncryptionBase64Result` (`lib/keymaster.ts:104,115`)

```ts
cleSecrete?: Uint8Array,
```

Typo in property name ("secrete" instead of "secret"). This inconsistency could cause serialization mismatches.

---

### 19. Hardcoded test seeds may propagate to production patterns (`tests/*.test.ts`, multiple files)

Test fixtures use static seeds like `'0123456789012345678901234567890123456789012345678901234567890123'` for deterministic key generation. While this is confined to tests, it indicates a pattern: the library has no built-in guard against seed reuse. If a consumer calls `generateKeypairEd5519(seed)` with a predictable seed, **all cryptographic operations become trivially breakable**.

**Recommendation**: Add documentation warning that `seed` must never be reused or derived from predictable sources.

---

## Logic Bugs & Code Smells

Findings surfaced during re-verification that are logic defects or code-quality issues rather than severity-rated vulnerabilities. Several have real consequences if left in place. **`L1`, `L2` and `L4` were fixed in the 2026-11-26 code pass** and moved to "Resolved & Partially Resolved"; `L3`, `L5` and `L6` remain open.

### L3. Non-constant-time digest comparison (`lib/digest.ts:122-129`) [NEW]

`comparerArraybuffers` returns as soon as a byte differs. This is acceptable for comparing content digests, but if `verifyDigest` is ever relied on to compare a MAC / secret-derived value, the early return is a timing side-channel.

**Recommendation**: use libsodium's constant-time compare (`crypto_memcmp`) for any secret comparison.

### L5. Lenient base64 / hex / multihash decoding (`lib/multiencoding.ts:156-182,389-395,403-421`) [NEW]

`base64Decode` maps any unrecognized character to `0`; `decodeHex` silently accepts odd-length or non-hex input (producing `NaN` coerced to `0`); `multihashDecode` slices the declared `length` without bounds-checking it against the remaining buffer. Malformed or truncated input therefore decodes silently instead of failing.

**Impact**: for key material and signatures this masks corruption and accepts non-canonical encodings. Not directly exploitable, but it removes an integrity signal.

**Recommendation**: validate character sets, even lengths, and declared-vs-actual lengths, and throw on mismatch.

### L6. `verifyCertificate` ignores `pathLenConstraint` (`lib/certificates.ts:105-112`) [NEW]

Chain building only inspects `basicConstraints.ca` to decide whether a certificate may act as the parent of the next entry; the `pathLenConstraint` value is never checked.

**Recommendation**: enforce `pathLenConstraint` if intermediate-CA depth ever needs to be bounded under this model.

---

## Dependency & API Notes

### N1. `multiformats` appears to be a redundant dependency (`package.json:56`) [NEW -- flagged for owner revisit]

`multiformats` is declared as a runtime dependency, but a grep across `lib/` and `tests/` found **no import of it anywhere** -- `lib/multiencoding.ts` reimplements multibase/multihash natively. The stated goal of #9 was to drop the external multi-* libraries, and `multiformats` was added in the same change while remaining unused.

**Note**: leaving this as an observation only for now -- the related code is uncommitted and pending an owner review. Revisit whether `multiformats` is intended (e.g. for planned usage) or should be removed.

### N2. Breaking API changes from the #9 rewrite and still-open field names [NEW]

The #9 rework changes two exported signatures -- `createHasher(digestName: string)` becomes `createHasher(hashMeta: HashMeta)` (`lib/digest.ts:99`) and the `WrappedHasher` constructor (`lib/digest.ts:71-80`). Combined with the still-open `DomainSignature.domaines` (#14) and `cleSecrete` (#15) naming, this is a breaking surface change for the consuming React apps.

**Agreed direction (not implemented in this pass)**: keep deprecated aliases for the old signatures / property names during a transition window, record a migration note, and ship under a major version bump.

---

## Reclassified / Working As Intended

### 1. Deterministic ChaCha20 nonce in X25519 -- false positive, working as intended (`lib/x25519.ts:96-112,114-132`)

The original CRITICAL finding assumed the nonce is derived from a *reused* recipient key pair. Re-verification shows each `encryptEd25519` call builds a **fresh ephemeral keypair**: `secretFromEd25519` (`lib/x25519.ts:20-47`) calls `generateKeypairEd5519()` with no seed, which resolves to `getRandom(32)`. Consequently, per call:

1. The symmetric key is a fresh ECDH shared secret (new ephemeral private scalar).
2. `peerBytes` is a fresh random X25519 public value, so the derived nonce differs per call.
3. Even the secret being encrypted is a fresh per-message session key -- `createEncryptedResponse` / `createEncryptedCommand` call `secretFromEd25519(millegrilleKey)` separately per message (`lib/messageStruct.ts:210,256`).

So there is no `(key, nonce)` reuse across encryptions and two messages never produce identical ciphertexts. The nonce is recoverable at decryption from the transmitted 32-byte peer (`decryptEd25519`, `lib/x25519.ts:121-129`): a standard ECIES-style construction.

**Disposition**: closed as "working as intended." No nonce fix required. Follow-up (deferred): add a code comment documenting why the nonce is derived from the ephemeral public peer, so future reviewers don't re-raise this.

---

## Summary Table

| # | Severity | Status | Section | File | Issue |
|---|----------|--------|---------|------|-------|
| 1 | INFO | **Reclassified** (was CRITICAL) | Reclassified | `lib/x25519.ts:96-112` | Deterministic ChaCha20 nonce -- false positive, fresh ephemeral per call |
| 2 | HIGH | **Resolved** | Resolved | `lib/certificates.ts:105` | Certificate chain verification uses wrong cert |
| 3 | HIGH | **Resolved** | Resolved | `lib/certificates.ts:412` | No bounds check on ASN.1 key parsing |
| 4 | HIGH | Open | Security | `package.json:39` | Private Git fork dependency, no audit trail |
| 5 | HIGH | **Resolved** | Resolved | `lib/certificates.ts:419` | Algorithm OID not validated for private key |
| 6 | MEDIUM | Open | Security | `lib/digest.ts:49` | `verifyDigest` throws instead of returning false |
| 7 | MEDIUM | **Resolved** | Resolved | `lib/certificates.ts:495-501` | Cache never evicts when full |
| 8 | MEDIUM | **Resolved** | Resolved | `lib/messageStruct.ts` | Decompression bomb: streaming decompression with running byte cap |
| 9 | MEDIUM | **Resolved** | Resolved | `lib/multiencoding.ts` | Deprecated `multihashes`/`multibase` packages removed (see N1) |
| 10 | MEDIUM | **Resolved** | Resolved | `lib/certificates.ts` | PEM splitting now uses a block regex preserving BEGIN headers |
| 11 | MEDIUM | Open | Security | `lib/forgePrivateKey.ts:57` | 20-year CA certificate validity |
| 12 | LOW | Open | Security | `lib/certificates.ts:149` | `console.info` in production code |
| 13 | LOW | Open | Security | `lib/certificates.ts:402,438` | Password support marked "not implemented" |
| 14 | LOW | Open | Security | `lib/keymaster.ts:17` | French spelling inconsistency (`domaines`) |
| 15 | LOW | Open | Security | `lib/keymaster.ts:104,115` | Typo in property name (`cleSecrete`) |
| 16 | LOW | **Resolved** | Resolved | `lib/messageStruct.ts` | Duplicate `reflect-metadata` import removed |
| 17 | LOW | **Resolved** | Resolved | `lib/certificates.ts` | Date comparison now inclusive (`<=`); folded into #20 |
| 18 | LOW | **Resolved** | Resolved | `lib/messageStruct.ts` | Constructor now validates required fields |
| 19 | LOW | Open | Security | `tests/*.test.ts` | Hardcoded test seeds may propagate |
| 20 | HIGH | **Resolved** | Resolved | `lib/certificates.ts` | Chain validated against wall-clock; `validateAt` opt-in for trusted replay |
| L1 | -- | **Resolved** | Resolved | `lib/certificates.ts` | `date: false` now skips date checks via explicit flag |
| L2 | -- | **Resolved** | Resolved | `lib/digest.ts` | Wrong-argument guard removed from `verifyDigest` |
| L3 | -- | Open (New) | Logic | `lib/digest.ts:122-129` | Non-constant-time digest comparison |
| L4 | -- | **Resolved** | Resolved | `lib/keymaster.ts` | `decryptKey` throws on unexpected length |
| L5 | -- | Open (New) | Logic | `lib/multiencoding.ts` | Lenient base64/hex/multihash decoding |
| L6 | -- | Open (New) | Logic | `lib/certificates.ts:105-112` | `pathLenConstraint` not enforced |
| N1 | -- | Open (New) | Dep/API | `package.json:56` | `multiformats` appears unused / redundant |
| N2 | -- | Open (New) | Dep/API | `lib/digest.ts`, `lib/keymaster.ts` | Breaking API changes; use deprecated aliases |

---

## Resolved & Partially Resolved

### 2. Certificate chain verification bug: `ca` referenced instead of `cert` in the loop (HIGH)

**Fix**: Changed `ca.getExtension(...)` to `cert.getExtension(...)` on line 105 of `lib/certificates.ts`. Each certificate in the chain is now correctly checked for its own `basicConstraints` extension.

### 3. ASN.1 parsing without bounds validation in `loadPrivateKeyEd25519` (HIGH)

**Fix**: Added validation `ecParams.privateKey.byteLength < 32` before slicing. Maliciously short keys now throw `"Invalid private key: too short"`.

### 5. PKCS#8 key parsing does not validate algorithm OID (HIGH)

**Fix**: Added OID check against Ed25519 (`1.3.101.112`) in `loadPrivateKeyEd25519`. Keys with mismatched algorithm identifiers throw `"Invalid algorithm OID for Ed25519 private key: expected 1.3.101.112, got <actual>"`.

### 7. `CertificateCache` has no eviction when full (MEDIUM)

**Fix**: Added `await this.maintain()` call in `saveCertificate()` before rejecting new entries. The cache now evicts expired entries automatically and retries the save.

### 8. `pako` compression without decompression limits (MEDIUM) -- RESOLVED 2026-11-26

**Fix (2026-11-26)**: replaced `pako.ungzip(output)` with a streaming `pako.Inflate({ chunkSize: 64 * 1024 })` in `decryptMessageContent` (`lib/messageStruct.ts`). An `onData` callback accumulates a running byte total and throws `"Decompressed content exceeds maximum allowed size"` as soon as it passes the 10 MB cap, so decompression aborts **before** the full plaintext is materialised. A regression test feeds an 11 MB repetitive payload (which compresses to a tiny ciphertext) and asserts the guard fires on decryption.

### 9. Deprecated `multihashes` and `multibase` packages (MEDIUM)

**Fix**: Removed `multihashes` (v4.0.3) and `multibase` (v4.0.6) dependencies. Replaced with a native implementation in `lib/multiencoding.ts` that provides the same API surface with dual-mode support:

- **Legacy mode (default)**: uses multihashes v4 custom codes (`blake2b-512` → 0xb240, `blake2s-256` → 0xb260). Backward compatible with all existing stored hashes.
- **Modern mode**: uses standard multiformats codes (`blake2b-512` → 0xb5, `blake2s-256` → 0xb2). Available via `setHashEncodingMode('modern')`.
- **Decoding**: always accepts both legacy and modern hash codes, regardless of mode.

Switch mode at runtime: `setHashEncodingMode('modern')` for new hash generation, or keep the default `legacy` mode. All 50 tests pass, build succeeds.

### 10. `splitCertificatePems` can produce invalid PEMs (MEDIUM) -- RESOLVED 2026-11-26 (follow-up)

**Fix**: replaced the `pems.split(CERTIFICATE_END) … + CERTIFICATE_END` reconstruction with a block-matching regex anchored to `^-----BEGIN CERTIFICATE-----` at line start and matching non-greedily to `-----END CERTIFICATE-----`. Each returned block is now self-contained (BEGIN *and* END headers), text between or before certificates is dropped, and an `END` marker appearing in surrounding text can no longer split a block in half. `splitCertificatePems` returns `[]` when no block is found. Covered by a dedicated `splitCertificatePems` test suite (`tests/certificates.test.ts`).

### 20. Certificate chain validated against an attacker-controlled timestamp (HIGH) -- RESOLVED 2026-11-26

**Fix**: `CertificateStore.verifyMessage` (`lib/certificates.ts`) now validates the chain against `new Date()` by default instead of the message's own `estampille`. Added `options.validateAt?: Date` so a *trusted* caller (e.g. replaying a transaction from a redo-log / backup) can pin validation to a recorded historical timestamp; `validateAt` still enforces the validity window (it does **not** skip expiry), and `estampille` freshness remains the caller's responsibility. Covered by an expired-leaf test suite.

### 17. Certificate date comparison uses strict `<` (LOW) -- RESOLVED 2026-11-26

**Fix**: folded into the `#20` work. `verifyCertficateKeys` now uses inclusive bounds (`<=`) and a 5-minute clock-skew tolerance (`CERT_VALIDITY_SKEW_MS`), so a certificate valid exactly at `notAfter` is accepted.

### 16. `reflect-metadata` imported in multiple files (LOW) -- RESOLVED 2026-11-26 (follow-up)

**Fix**: removed the redundant `import "reflect-metadata"` from `lib/messageStruct.ts`; `lib/index.ts` already imports it. No decorators or `Reflect` metadata APIs are used anywhere in the library, so the side-effect import had no runtime purpose and only pulled the polyfill in when `messageStruct` was loaded directly.

### 18. `MilleGrillesMessage` constructor doesn't validate required fields (LOW) -- RESOLVED 2026-11-26 (follow-up)

**Fix**: the constructor (`lib/messageStruct.ts`) now validates the three required arguments and throws before an invalid message can be created or serialized: `estampille` must be a non-`NaN` number, `kind` must be a member of `MessageKind`, and `contenu` must be a non-empty string. The checks are type-based (not truthiness), so a legitimate epoch-0 stamp or `Document` (`kind === 0`) is still accepted. Because `parseMessage()` builds through the constructor, deserializing input that is missing `estampille` / `kind` / `contenu` now fails loudly instead of silently producing a malformed message. Covered by a constructor-validation test suite (`tests/messageStruct.test.ts`).

### L1. `date: false` does not disable certificate date checks -- RESOLVED 2026-11-26

**Fix**: `verifyCertificate` now resolves `Date` / `false` / `null` distinctly and threads an explicit `skipDateCheck` boolean through `verifyCertficateKeys`; the `false` path no longer silently falls back to the current clock. Covered by a test asserting `date: false` truly skips validity checks.

### L2. `verifyDigest` guards the wrong argument -- RESOLVED 2026-11-26

**Fix**: removed the dead and incorrect `if (!ArrayBuffer.isView(content)) { encodedDigest = new Uint8Array(content); }` block from `verifyDigest` (`lib/digest.ts`).

### L4. `decryptKey` returns `undefined` for unexpected input length -- RESOLVED 2026-11-26

**Fix**: `decryptKey` (`lib/keymaster.ts`) now throws with the actual length when `encryptedKeyBytes.length` is neither 32 nor 80, instead of falling through to an implicit `undefined`. Covered by a unit test.

---

## Recommended Priorities

### Completed in the 2026-11-26 code pass (shipped as `2026.8.1`)

1. **`#20`** -- certificate chain now validated against wall-clock time (with a 5-minute skew window); `validateAt` opt-in added for trusted replay.
2. **`#8`** -- decompression cap is now enforced by streaming (`pako.Inflate`, running byte total), so the guard fires before the full plaintext is allocated.
3. **`L1`, `L2`, `L4`** (and `#17`, folded into `#20`) -- logic fixes landed.
4. **Follow-up pass** -- **`#10`** (PEM splitting now uses a block regex preserving BEGIN headers), **`#16`** (duplicate `reflect-metadata` import removed) and **`#18`** (`MilleGrillesMessage` constructor validates required fields) landed. All 65 tests pass, typecheck and build clean.

### Remaining priorities

1. **Resolve `N1`** -- the `multiformats` dependency looks unused; confirm intent or drop it as part of the #9 rework.
2. **Document `N2`** -- keep deprecated aliases for `createHasher` / `WrappedHasher` / `domaines` / `cleSecrete` and ship under a major bump with a migration note.
3. **Audit the private `@dugrema/node-forge` fork (#4)** against upstream node-forge for known CVEs.
4. **Add the deferred code comment for `#1`** so the ephemeral-derived-nonce design is recorded and not re-raised.
5. **Tighten `L5`** (decode validation); `L3` (constant-time compare) and `L6` (`pathLenConstraint`) are lower urgency.

### Notes on remaining out-of-scope items

- `#11` (20-year CA) and `#13` (password not implemented) are accepted as documented limitations and need no action right now.
- Open MEDIUM `#6` (`verifyDigest` throw-vs-`false`, deferred for API-transition reasons) and the remaining open LOWs (`#12`, `#14`, `#15`, `#19`) stay as logged in the Summary Table. (`#10` and `#18`, previously listed here, were resolved in the follow-up pass.)
