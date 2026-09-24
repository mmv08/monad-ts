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

Under `src/`, `btx.ts` implements the scheme, `ciphertext.ts` the wire codec, `curve.ts` the Noble wrappers, and `hash.ts` the hash transcripts. `bytes.ts` and `error.ts` hold shared helpers. `index.ts` exports the public API; the separate test-only entry, `testing.ts`, exports only `createTestKey`.

`Ciphertext` is the only named type export on the main entry. Option and result types remain in function signatures but are not separate exports.

## 2. Specification-Fixed Constants

| Item | Value |
| --- | --- |
| Curve | BLS12-381; R in G_1, ek and pad in G_T |
| Scalar field | q = `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| Seed S | 16 bytes |
| Compressed G_1 point | 48 bytes |
| Scalar | 32 bytes, big endian, strictly below q |
| G_T element | 576 bytes; CatBLST order: Fp2 index, then Fp6 half, then Fp component; 48-byte big-endian limbs |
| Proof π | c ∥ s, 64 bytes |
| Wire form | `R (48) ∥ C_1 (16) ∥ len(C_2) u32be ∥ C_2 ∥ π (64)`, total `132 + \|C_2\|` |
| Padded plaintext P | `u32be(\|M\|) ∥ M ∥ 0x00 × (padded_len − \|M\|)`, so `\|C_2\| = 4 + padded_len` |
| Blake3 contexts | `btx/coins/v1`, `btx/r/v1`, `btx/kem/v1`, `btx/dem/v1`, `btx/nizk/v1` |
| Scalar derivation | 64 squeezed bytes reduced modulo q; never bit masking |
| Absorption rule | Fixed-width inputs bare; variable-width inputs prefixed with their u64be length |

Changing any row changes ciphertext bytes and requires new fixtures and a review against the specification.

## 3. Encryption Pipeline

`encrypt` first decodes the key's canonical bytes, requires `ek^q = 1`, and rejects `ek = 1`. The membership check rejects field zero and elements outside G_T; the identity check rejects a degenerate key whose mask anyone could compute. These checks do not authenticate the key's source or epoch. The caller must obtain the right epoch key from a trusted source.

`src/btx.ts` follows the specification's `encrypt` (p. 51–52) in order:

1. `P = pad(M, padded_len)`; reject `padded_len < |M|` and lengths that overflow the u32 prefix.
2. Draw `S`; `r = expand_r(H_rho(AD, P, S))`; redraw `S` while `r = 0`.
3. `R = g_1·r`; `pad = ek·r` in G_T (`Fp12.pow`).
4. `C_1 = S ⊕ H_kem(pad, R, AD)`; `C_2 = P ⊕ PRG(KDF(S, AD), |P|)`.
5. Draw the nonce `k`; `π = prove(R, C_1, C_2, AD, r, k)` with `T = g_1·k`, `c = challenge(R, T, C_1, C_2, AD)`, `s = k − c·r`.

`assertValidCiphertext` (p. 52) checks that C_1 is 16 bytes, decodes R to enforce subgroup membership, rejects identity R, then recomputes `T' = g_1·s + R·c` and the challenge. It returns nothing on success and throws on rejection. The internal `validateCiphertext` helper returns the admitted point so test decryption can reuse it.

`verifyDecryption` rebuilds `P` from the candidate plaintext and `|C_2|`, recomputes nonzero `r`, and checks `R`, `C_1`, and `C_2`. It takes the authenticated encryption key and independently computes `ek^r` to require `C_1 = S XOR H_kem(ek^r, R, AD)`, matching current Rust. This strengthens the PDF's R/C_2-only check (p. 60): a sender who knows `r` can make a valid proof over an inconsistent `C_1`. It compares canonical commitment bytes rather than decoding R again. Mismatches return `false`; invalid keys, types, or seed lengths can throw. It does not check the proof, so callers must run `assertValidCiphertext` first.

The hash primitives in `src/hash.ts` match Appendix E and the challenge on p. 64 exactly: `S`, `R`, `T`, `C_1`, and the encoded pad are absorbed bare; `AD`, `P`, and `C_2` are length-prefixed; the Blake3 context is a derive_key context, not absorbed input.

`encrypt` and `verifyDecryption` take named parameter objects. `encrypt` calls the internal `encryptWithRandom` helper with the platform CSPRNG. That helper checks inputs, pads the plaintext, and calls `encryptPadded`, which derives `r` once per seed attempt and retains it for masking and proof generation. Tests use these internal helpers for fixed randomness and malformed padding; neither helper is exported by a package entry.

## 4. Encoding and Canonicality

The ciphertext has exactly one serialization, because associated data may later be bound to it by its bytes.

- After checking its arguments, `deserializeCiphertext` applies the specification's seven steps in order and rejects trailing data, a length prefix that disagrees with the buffer, a masked payload above the caller's `maxMaskedPayloadLength`, and non-canonical scalars. An explicit limit must be a nonnegative safe integer; omit it for no limit. The limit includes the inner four-byte plaintext-length prefix but excludes the 132-byte `CIPHERTEXT_OVERHEAD`, and the check precedes copying C_2.
- Decoded components own their bytes, including for Node `Buffer` inputs; later input changes cannot alter the ciphertext.
- G_1 decoding relies on the pinned noble decoder: the x limb is range-checked, the identity has one encoding, and the compressed flag must be set. Subgroup membership is checked at decode as well as in `assertValidCiphertext`. This preserves acceptance and rejection but may change the rejection stage and error precedence for inputs with several faults.
- G_1 encoding normalizes computed identity points to Noble's canonical `Point.ZERO`. Nonzero terms in the proof check can cancel to a non-normalized projective identity, which Noble 2.3.0 otherwise refuses to encode. Identity T is valid; identity R remains forbidden.
- Encryption-key decoding converts CatBLST wire order to Noble tower order, uses `Fp12.fromBytes` to range-check every limb, then enforces target-group membership and rejects the identity. Encoding applies the inverse conversion. In 48-byte limb indices, CatBLST bytes select `[0, 1, 6, 7, 2, 3, 8, 9, 4, 5, 10, 11]` from Noble's output. The same codec encodes the KEM pad. Field decoding alone does not establish G_T membership.
- Scalars are 32 big-endian bytes strictly below q.
- Canonicality tests include a valid subgroup point with x replaced by x + p and a valid key with one limb v replaced by v + p. A decoder that reduced either value would restore a valid element, so subgroup checks cannot hide a canonicality regression.
- Integer encoders use Noble's fixed-width big-endian helper, which rejects overflow rather than wrapping.

## 5. Randomness Boundary

`encrypt` draws only `S` and the proof nonce, from Noble's `randomBytes` (the platform CSPRNG). Its public API has no randomness override. Fixtures and tests inject randomness through the internal `encryptWithRandom` helper. `r` is derived from `(AD, P, S)`, so a ciphertext is a deterministic function of those inputs and the nonce, which is what fixtures pin.

Each seed attempt consumes 16 bytes. The proof nonce uses Noble's BLS12-381 `randomSecretKey` helper, which maps 48 random bytes to a scalar in `[1, q)`. The test-key generator uses the same helper for its default trapdoor. Neither call uses the PDF's wide-reduction helper; that remains unchanged for `r` and the proof challenge.

The fixture helper supplies entropy that yields each stored seed and nonce through `encryptWithRandom`. Vector tests compare each intermediate value and ciphertext against the stored file.

## 6. Error Mapping

| Condition | Error |
| --- | --- |
| Wrong JavaScript type or fixed length at a public boundary | `TypeError` or `RangeError` from noble `abytes` |
| Ciphertext shorter than 132 bytes, length prefix disagreeing with the buffer, payload over the limit, invalid size limit, invalid padding length or default-padding input | `BtxError` `InvalidLength` |
| R or ek not canonical or outside its subgroup, or ek is the identity | `BtxError` `InvalidPoint` |
| Proof scalar not below q, or proof not 64 bytes | `BtxError` `InvalidScalar` |
| R is the identity | `BtxError` `InvalidCiphertext` |
| Proof does not verify (any component or AD altered) | `BtxError` `ClientNizkFailed` |
| Plaintext/seed witness does not reproduce R, C_1, or C_2 under the supplied key in `verifyDecryption` | `false` |
| Padding malformed or guardrail failed during test decryption | `null` (⊥), never an exception |

## 7. Test-Only Decryption

`src/testing.ts` is a separate entry, `@monad-crypto/btx/testing`, and the main entry never imports it. It computes `h = g_2·τ^(B_max+1)`, the reference-string slot the DKG withholds, so `e(g_1, h) = ek` and `e(R, h) = ek·r` is the pad the threshold path reconstructs. Decryption then follows `batch_decrypt` for one slot: recover `S`, unmask `P`, `unpad`, and run `verify_decryption`. One process holds τ, so this offers no threshold, no share release, and no privacy. It exists so tests and the local mock can decrypt real ciphertexts without a DKG.

## 8. Dependencies

| Dependency | Version | Purpose |
| --- | --- | --- |
| `@noble/curves` | `2.3.0` | BLS12-381 G_1, G_2, G_T arithmetic, pairing, point and field codecs |
| `@noble/hashes` | `2.3.0` | Blake3 in derive_key, keyed, and XOF modes; byte utilities; CSPRNG |

Both versions are exact pins. Section 4 depends on the decoder behaviour of these versions. A dependency upgrade requires rerunning every fixture and the malformed-input tests.

Noble uses JavaScript bigint arithmetic and does not guarantee constant-time execution. In particular, `Gt.pow(ek, r)` uses secret-dependent control flow and table access. Running on the sender's machine does not rule out local or shared-runtime side channels.

Audit coverage is component- and version-specific. Noble's security notes list an independent Cure53 audit of BLS12-381 and the pairing/tower primitives at curves 1.6.0, not the installed 2.3.0. The listed independent hashes audit at 1.0.0 excludes BLAKE3; the full-scope 2.2.0 review was a self-audit. Reusing Noble does not make this BTX implementation independently audited.

## 9. Source and Conformance Boundary

The PDF is the authority. The Rust comparison target is `category-labs/monad-bft-private`, branch `peter/btx-audit-sync`, commit `71a4400bc82e2879acfcd064de5472b098b0e593`, in `monad-encrypted-tx/src/btx.rs`. It pins CatBLST at `05d5a4f6a4508445c0c6f10ceefea2bea4cc0dc0`. This package uses CatBLST's G_T wire order and Rust's stronger independent witness check.

The fixtures in `tests/fixtures/vectors.json` come from this library and serve as regression vectors. Independent checks live in `tests/rust-conformance.test.ts`: Rust's fixed padding, coins, scalar, KEM, DEM, PRG, and challenge answers, plus all 13 admission vectors from its `test-vectors/btx-conformance-v1.txt`. `tests/fixtures/rust-admission.json` stores those admission bytes as a base vector and exact byte edits, with the source commit. These tests need no Rust checkout or network. Do not regenerate the Rust expectations with the TypeScript generator.

Local tests cover challenge binding, canonicality, direct object validation, and byte ownership; the eight generated fixtures cover varied message, padding, and AD lengths. The Rust-derived data establishes primitive and admission parity, not a full Rust/TypeScript threshold-decryption round trip. The Rust suite was not run for this comparison. Share/MSM/combine vectors test APIs outside this package. Proof nonce samplers differ: Rust rejection-samples `[0, q)` from 32 little-endian bytes; Noble maps 48 random bytes into `[1, q)`. Compare fixed nonce scalars, not raw RNG streams.

The Rust and CatBLST reference repositories carry licenses that differ from this package's MIT; the imported known-answer data records its source separately from this package's implementation.

## 10. Specification Gaps and Explicit Differences

Each item is marked `TODO(spec)` where it lands in code.

1. **Proof nonce.** `prove` takes `k = rng.scalar()` without fixing the derivation. This package uses Noble's nonzero-scalar sampler with 48 random bytes. Fixtures record the scalar `k`, so a future cross-language comparison need not use the same sampler.
2. **G_T encoding.** The PDF names a canonical 576-byte encoding without defining limb order. This package follows CatBLST's Fp2-index/Fp6-half/Fp-component order. Rust's fixed KEM answer checks this choice.
3. **Ciphertext size limit.** `deserialize_ciphertext` step 5 defers to "the caller's limit". Exposed as `maxMaskedPayloadLength` with no default.
4. **Padding policy.** `padded_len` is the sender's choice. The default of rounding to 256 bytes comes from the delivery plan, not the PDF.
5. **Independent witness verification — deliberate extension.** The PDF specifies an R/C_2-only check. This package also reproduces C_1 from the public encryption key, following Rust and its HTML specification, so a valid proof over an inconsistent masked seed cannot make an invalid witness pass. This changes witness acceptance for inconsistent ciphertexts, not honest encryption bytes.
6. **Threshold path.** Shares, `combine`, precomputes, and `batch_decrypt` are absent by design. Add them to the testing entry only if the mock needs share-level fidelity.

## 11. Review Checklist

Before changing this package:

- Confirm every constant in section 2 against the current PDF and the explicit compatibility choices in section 10, including which inputs are absorbed bare and which are length-prefixed.
- Preserve the order of `encrypt`: pad, derive `r` from `(AD, P, S)`, mask, then prove over the final `(R, C_1, C_2, AD)`.
- Preserve one serialization per ciphertext; keep the point, scalar, and length checks in `deserializeCiphertext`.
- Keep `assertValidCiphertext` as the admission gate: reject identity R, but allow identity T.
- Keep the encryption-key membership and identity checks; neither authenticates the epoch key.
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
