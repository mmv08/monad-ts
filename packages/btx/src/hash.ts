import { blake3 } from "@noble/hashes/blake3.js";
import { bytesToNumberBE, u64be, utf8ToBytes } from "./bytes.js";
import { encodeGt, type Fp12, Fr } from "./curve.js";

type Hasher = ReturnType<typeof blake3.create>;

/** Starts a Blake3 hash in derive_key mode; the context is a key, not absorbed input. */
function derive(context: string): Hasher {
  return blake3.create({ context: utf8ToBytes(context) });
}

/** Absorbs a variable-length input as its 8-byte big-endian length followed by its bytes. */
function absorbLp(hasher: Hasher, bytes: Uint8Array): Hasher {
  return hasher.update(u64be(bytes.length)).update(bytes);
}

/** H_rho: the 16-byte coins derived from (AD, P, S) that fix the encryption randomness. */
function hRho(
  associatedData: Uint8Array,
  paddedPlaintext: Uint8Array,
  seed: Uint8Array,
): Uint8Array {
  const hasher = derive("btx/coins/v1");
  absorbLp(hasher, associatedData);
  absorbLp(hasher, paddedPlaintext);
  return hasher.update(seed).xof(16);
}

/** expand_r: the encryption scalar from the coins. Zero must be resampled by the caller. */
function expandR(coins: Uint8Array): bigint {
  return Fr.create(bytesToNumberBE(derive("btx/r/v1").update(coins).xof(64)));
}

/** H_kem: the 16-byte mask that hides the seed under the pad. */
function hKem(
  pad: Fp12,
  commitment: Uint8Array,
  associatedData: Uint8Array,
): Uint8Array {
  const hasher = derive("btx/kem/v1").update(encodeGt(pad)).update(commitment);
  return absorbLp(hasher, associatedData).xof(16);
}

/** KDF: the 32-byte stream key derived from (S, AD). */
function kdf(seed: Uint8Array, associatedData: Uint8Array): Uint8Array {
  return absorbLp(derive("btx/dem/v1").update(seed), associatedData).xof(32);
}

/** PRG: `length` bytes of keyed Blake3 output. */
function prg(key: Uint8Array, length: number): Uint8Array {
  return blake3.create({ key }).xof(length);
}

/** challenge: the Fiat-Shamir scalar over (R, T, C_1, C_2, AD); fixed-width inputs bare, others length-prefixed. */
function challenge(
  commitment: Uint8Array,
  nonceCommitment: Uint8Array,
  maskedSeed: Uint8Array,
  maskedPayload: Uint8Array,
  associatedData: Uint8Array,
): bigint {
  const hasher = derive("btx/nizk/v1")
    .update(commitment)
    .update(nonceCommitment)
    .update(maskedSeed);
  absorbLp(hasher, maskedPayload);
  return Fr.create(bytesToNumberBE(absorbLp(hasher, associatedData).xof(64)));
}

export { challenge, expandR, hKem, hRho, kdf, prg };
