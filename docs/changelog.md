# Changelog

All notable changes to **millegrilles.cryptographie.ts** are documented in this file.

The findings referenced below (numbers and `L#` ids) correspond to
`docs/security_assessment_2026-11-25.md`.

## [2026.8.1] - 2026-11-26

Security release addressing the 2026-11-25 automated security assessment.
It bundles the fixes already applied on this version line with the hardening
pass completed on 2026-11-26.

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

### Tests

- Added an expired-leaf fixture generator (`tests/certificates.test.ts`) and
  tests covering `#20` (default rejection, trusted `validateAt` acceptance,
  out-of-window rejection, wall-clock-not-estampille) and `L1` (`date: false`
  truly skips).
- Added a streaming decompression-bomb test (`tests/messageStruct.test.ts`).
- Added a `decryptKey` unexpected-length rejection test
  (`tests/keymaster.test.ts`).

### Known open items (not addressed in this release)

- `#4` Private `@dugrema/node-forge` Git-fork dependency (audit upstream).
- `N1` Possibly-unused `multiformats` dependency (confirm intent or drop).
- `N2` Breaking API changes (`createHasher`, `WrappedHasher`, `domaines`,
  `cleSecrete`) - keep deprecated aliases under a major version bump.
- `L3` Non-constant-time digest comparison, `L6` `pathLenConstraint` not
  enforced, `#11` 20-year CA validity, `#13` password support not implemented,
  `#18` constructor field validation.
