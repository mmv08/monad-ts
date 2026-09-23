# Architecture — Security Review Guide

This document describes the security boundaries of `@monad-crypto/btx`. Usage is documented in [README.md](./README.md).

## 1. Scope

The package implements the sender-facing part of BTX, the batched threshold encryption scheme in the encrypted transaction specification (`encrypted_txs_specs_wip.pdf`, "BTX Implementation", pp. 49–64, and Appendix E, pp. 68–69):

- `encrypt`, including the length-prefixed zero padding of the plaintext.
- The Schnorr proof of knowledge of the encryption randomness, bound to the ciphertext and the associated data.
- `serialize_ciphertext` and `deserialize_ciphertext`.
- `assertValidCiphertext` (the PDF's `verify_ciphertext`), the admission gate.
- `verifyDecryption` (the PDF's `verify_decryption`), the guardrail a decryptor and a witness holder run.

A test-only entry adds key generation from a trapdoor and single-ciphertext decryption. Shares, `combine`, precomputes, `batch_decrypt`, fault attribution, public-parameter and secret-share encodings, transactions, associated-data construction, and RPC are outside this package.

Under `src/`, `btx.ts` implements the scheme, `ciphertext.ts` the wire codec, `curve.ts` the Noble wrappers, and `hash.ts` the hash transcripts. `bytes.ts` and `error.ts` hold shared helpers. `index.ts` exports the public API; `testing.ts` is the separate test-only entry.

## 2. Specification-Fixed Constants

| Item | Value |
| --- | --- |
| Curve | BLS12-381; R in G_1, ek and pad in G_T |
| Scalar field | q = `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| Seed S | 16 bytes |
| Compressed G_1 point | 48 bytes |
| Scalar | 32 bytes, big endian, strictly below q |
| G_T element | 576 bytes |
| Proof π | c ∥ s, 64 bytes |
| Wire form | `R (48) ∥ C_1 (16) ∥ len(C_2) u32be ∥ C_2 ∥ π (64)`, total `132 + \|C_2\|` |
| Padded plaintext P | `u32be(\|M\|) ∥ M ∥ 0x00 × (padded_len − \|M\|)`, so `\|C_2\| = 4 + padded_len` |
| Blake3 contexts | `btx/coins/v1`, `btx/r/v1`, `btx/kem/v1`, `btx/dem/v1`, `btx/nizk/v1` |
| Scalar derivation | 64 squeezed bytes reduced modulo q; never bit masking |
| Absorption rule | Fixed-width inputs bare; variable-width inputs prefixed with their u64be length |

Changing any row changes ciphertext bytes and requires new fixtures and a review against the specification.

## 3. Encryption Pipeline

`src/btx.ts` follows the specification's `encrypt` (p. 51–52) in order:

1. `P = pad(M, padded_len)`; reject `padded_len < |M|` and lengths that overflow the u32 prefix.
2. Draw `S`; `r = expand_r(H_rho(AD, P, S))`; redraw `S` while `r = 0`.
3. `R = g_1·r`; `pad = ek·r` in G_T (`Fp12.pow`).
4. `C_1 = S ⊕ H_kem(pad, R, AD)`; `C_2 = P ⊕ PRG(KDF(S, AD), |P|)`.
5. Draw the nonce `k`; `π = prove(R, C_1, C_2, AD, r, k)` with `T = g_1·k`, `c = challenge(R, T, C_1, C_2, AD)`, `s = k − c·r`.

`assertValidCiphertext` (p. 52) decodes R, which enforces subgroup membership, rejects the identity, then recomputes `T' = g_1·s + R·c` and the challenge. It returns nothing on success and throws on rejection. `verifyDecryption` (p. 60) rebuilds `P` from the candidate plaintext and `|C_2|`, recomputes `r`, and checks both `R` and `C_2`. It returns a boolean witness result, not an admission result: it does not check `C_1` or the proof, so callers must run `assertValidCiphertext` first. Malformed inputs can throw.

The hash primitives in `src/hash.ts` match Appendix E and the challenge on p. 64 exactly: `S`, `R`, `T`, `C_1`, and the encoded pad are absorbed bare; `AD`, `P`, and `C_2` are length-prefixed; the Blake3 context is a derive_key context, not absorbed input.

`encrypt` and `verifyDecryption` take named parameter objects. `encrypt` checks inputs and pads the plaintext, then calls the internal `encryptPadded` core. That core derives `r` once per seed attempt and retains it for masking and proof generation. Tests also call it with malformed padding to check rejection after decryption.

## 4. Encoding and Canonicality

The ciphertext has exactly one serialization, because associated data may later be bound to it by its bytes.

- `deserializeCiphertext` applies the specification's seven steps in order and rejects trailing data, a length prefix that disagrees with the buffer, a masked payload above the caller's `maxMaskedPayloadLength`, and non-canonical scalars. That limit includes the inner four-byte plaintext-length prefix but excludes the 132-byte `CIPHERTEXT_OVERHEAD`.
- Decoded components own their bytes, including for Node `Buffer` inputs; later input changes cannot alter the ciphertext.
- G_1 decoding relies on the pinned noble decoder: the x limb is range-checked, the identity has one encoding, and the compressed flag must be set. Subgroup membership is checked at decode as well as in `assertValidCiphertext`, which is stricter than the specification's deferral and changes no outcome.
- G_T decoding uses noble `Fp12.fromBytes`, which range-checks every limb, so one byte string decodes to each element.
- Scalars are 32 big-endian bytes strictly below q.

## 5. Randomness Boundary

`encrypt` draws only `S` and the proof nonce, from noble `randomBytes` (the platform CSPRNG) unless the caller passes `randomBytes`. Injection exists for fixtures and tests. `r` is derived from `(AD, P, S)`, so a ciphertext is a deterministic function of those inputs and the nonce, which is what fixtures pin.

Each seed attempt consumes 16 bytes. The proof nonce uses Noble's BLS12-381 `randomSecretKey` helper, which maps 48 random bytes to a scalar in `[1, q)`. The test-key generator uses the same helper for its default trapdoor. Neither call uses the PDF's wide-reduction helper; that remains unchanged for `r` and the proof challenge.

The fixture helper supplies entropy that yields each stored seed and nonce through `encrypt`; the committed ciphertext bytes remain unchanged. Vector tests compare each intermediate value and ciphertext against the file without also regenerating the full file.

## 6. Error Mapping

| Condition | Error |
| --- | --- |
| Wrong JavaScript type or fixed length at a public boundary | `TypeError` or `RangeError` from noble `abytes` |
| Ciphertext shorter than 132 bytes, length prefix disagreeing with the buffer, payload over the limit, invalid `padded_len` | `BtxError` `InvalidLength` |
| R or ek not a canonical encoding of a valid element | `BtxError` `InvalidPoint` |
| Proof scalar not below q, or proof not 64 bytes | `BtxError` `InvalidScalar` |
| R is the identity | `BtxError` `InvalidCiphertext` |
| Proof does not verify (any component or AD altered) | `BtxError` `ClientNizkFailed` |
| Plaintext/seed witness does not reproduce R or C_2 in `verifyDecryption` | `false` |
| Padding malformed or guardrail failed during test decryption | `null` (⊥), never an exception |

## 7. Test-Only Decryption

`src/testing.ts` is a separate entry, `@monad-crypto/btx/testing`, and the main entry never imports it. It computes `h = g_2·τ^(B_max+1)`, the reference-string slot the DKG withholds, so `e(g_1, h) = ek` and `e(R, h) = ek·r` is the pad the threshold path reconstructs. Decryption then follows `batch_decrypt` for one slot: recover `S`, unmask `P`, `unpad`, and run `verify_decryption`. One process holds τ, so this offers no threshold, no share release, and no privacy. It exists so tests and the local mock can decrypt real ciphertexts without a DKG.

## 8. Dependencies

| Dependency | Version | Purpose |
| --- | --- | --- |
| `@noble/curves` | `2.3.0` | BLS12-381 G_1, G_2, G_T arithmetic, pairing, point and field codecs |
| `@noble/hashes` | `2.3.0` | Blake3 in derive_key, keyed, and XOF modes; byte utilities; CSPRNG |

Both versions are exact pins. Section 4 depends on the decoder behaviour of these versions. A dependency upgrade requires rerunning every fixture and the malformed-input tests.

Audit coverage is component- and version-specific. Noble's security notes list an independent Cure53 audit of BLS12-381 and the pairing/tower primitives at curves 1.6.0, not the installed 2.3.0. The listed independent hashes audit at 1.0.0 excludes BLAKE3; the full-scope 2.2.0 review was a self-audit. Reusing Noble does not make this BTX implementation independently audited.

## 9. Source and Conformance Boundary

The code is written from the PDF. The Rust implementation in `monad-bft-private` (`monad-encryption/src/btx.rs` at `0fd4485`) and CatBlst's admission verifier (`BTE/btx/admission.cpp` at `05d5a4f`) were read as structural references; no code was copied from either, and both carry licenses that differ from this package's MIT.

The fixtures in `tests/fixtures/vectors.json` are produced by this library. They are regression vectors and a future comparison target, not independent evidence of conformance. Phase 1 uses PDF review, protocol-focused tests, and stored expected bytes; it does not include maintaining the external Rust code or building a Rust runner. Cross-implementation comparison remains follow-up work.

## 10. Specification Gaps

Each item is marked `TODO(spec)` where it lands in code.

1. **Proof nonce.** `prove` takes `k = rng.scalar()` without fixing the derivation. This package uses Noble's nonzero-scalar sampler with 48 random bytes. Fixtures record the scalar `k`, so a future cross-language comparison need not use the same sampler.
2. **G_T encoding.** The PDF names a canonical 576-byte encoding without defining limb order. This package uses noble `Fp12.toBytes`: c0 ∥ c1, each Fp6 as c0 ∥ c1 ∥ c2, each Fp2 as c0 ∥ c1, 48-byte big-endian limbs. The Rust reference writes the same order. Compare with node-owned vectors when available.
3. **Sender-side ek checks.** The PDF requires none beyond decoding. This package rejects non-canonical limbs only; it does not check that ek has order q.
4. **Ciphertext size limit.** `deserialize_ciphertext` step 5 defers to "the caller's limit". Exposed as `maxMaskedPayloadLength` with no default.
5. **Padding policy.** `padded_len` is the sender's choice. The default of rounding to 256 bytes comes from the delivery plan, not the PDF.
6. **External reference mismatch.** The Rust reference differs from the PDF: it absorbs `S` length-prefixed in `H_rho` and `KDF`, hashes a 32-byte digest of the pad instead of its 576-byte encoding in `H_kem`, has no padding layer, and signals ⊥ with empty bytes. Its output is not a target for our implementation, and updating that external code is outside our scope.
7. **Threshold path.** Shares, `combine`, precomputes, and `batch_decrypt` are absent by design. Add them to the testing entry only if the mock needs share-level fidelity.

## 11. Review Checklist

Before changing this package:

- Confirm every constant in section 2 against the current PDF, including which inputs are absorbed bare and which are length-prefixed.
- Preserve the order of `encrypt`: pad, derive `r` from `(AD, P, S)`, mask, then prove over the final `(R, C_1, C_2, AD)`.
- Preserve one serialization per ciphertext; keep the point, scalar, and length checks in `deserializeCiphertext`.
- Keep `assertValidCiphertext` as the admission gate, and keep the identity rejected.
- Keep the testing entry out of the main entry and out of any sender bundle.
- Regenerate the fixtures only for a deliberate scheme change, and review the diff.
- Run package tests with coverage, typecheck, build, and Biome.

From the `monad-ts` root:

```bash
bun test --cwd packages/btx --coverage
bun run --cwd packages/btx typecheck
bun run --cwd packages/btx build
bunx --no-install biome check packages/btx
```

After a deliberate scheme change, run `bun run packages/btx/tests/fixtures/generate.ts` and review the changes to `tests/fixtures/vectors.json`.
