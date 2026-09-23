import { getMinHashLength } from "@noble/curves/abstract/modular.js";
import type { Fp12 } from "@noble/curves/abstract/tower.js";
import type { WeierstrassPoint } from "@noble/curves/abstract/weierstrass.js";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import {
  abytes,
  bytesToNumberBE,
  numberToBytesBE,
  randomBytes,
} from "./bytes.js";
import { BtxError } from "./error.js";

const { G1, G2, pairing } = bls12_381;
const { Fr, Fp12: Gt } = bls12_381.fields;

/** A point of G_1. */
type G1Point = WeierstrassPoint<bigint>;

/** Byte length of a compressed G_1 point. */
const G1_SIZE = 48;
/** Byte length of a scalar. */
const SCALAR_SIZE = 32;
/** Byte length of a target-group element. */
const GT_SIZE = 576;
/** Entropy length required by Noble's nonzero-scalar sampler. */
const SCALAR_ENTROPY_SIZE = getMinHashLength(Fr.ORDER);

/**
 * Decodes a compressed G_1 point. Rejects non-canonical encodings, points off the curve, and
 * points outside the prime-order subgroup. The identity decodes; `assertValidCiphertext` rejects it.
 *
 * Canonicality rests on the noble decoder: limbs are range-checked, the identity has one
 * encoding, and the compressed flag must be set. The dependency pin fixes that behaviour.
 */
function decodeG1(bytes: Uint8Array): G1Point {
  if (bytes.length !== G1_SIZE) {
    throw new BtxError("InvalidPoint", `expected ${G1_SIZE} bytes`);
  }
  try {
    return G1.Point.fromBytes(bytes);
  } catch {
    throw new BtxError(
      "InvalidPoint",
      "not a canonical G_1 point in the prime-order subgroup",
    );
  }
}

/** Encodes a G_1 point in its compressed form. */
function encodeG1(point: G1Point): Uint8Array {
  return point.toBytes(true);
}

/** Decodes a 32-byte big-endian scalar strictly below the group order. */
function decodeScalar(bytes: Uint8Array): bigint {
  if (bytes.length !== SCALAR_SIZE) {
    throw new BtxError("InvalidScalar", `expected ${SCALAR_SIZE} bytes`);
  }
  const scalar = bytesToNumberBE(bytes);
  if (scalar >= Fr.ORDER) {
    throw new BtxError("InvalidScalar", "not below the group order");
  }
  return scalar;
}

/** Encodes a scalar as 32 big-endian bytes. */
function encodeScalar(scalar: bigint): Uint8Array {
  return numberToBytesBE(scalar, SCALAR_SIZE);
}

/** Reduces 64 big-endian bytes modulo the group order: wide reduction, never bit masking. */
function wideScalar(bytes: Uint8Array): bigint {
  abytes(bytes, 64);
  return Fr.create(bytesToNumberBE(bytes));
}

/** Samples a nonzero scalar with Noble's BLS12-381 secret-key sampler. */
function randomScalar(
  random: (byteLength: number) => Uint8Array = randomBytes,
): bigint {
  return bytesToNumberBE(
    bls12_381.utils.randomSecretKey(random(SCALAR_ENTROPY_SIZE)),
  );
}

/**
 * Decodes a canonical 576-byte target-group element. The noble decoder range-checks every limb,
 * so exactly one byte string decodes to each element.
 *
 * TODO(spec): the PDF names a "canonical G_T encoding" without defining it. This uses the tower
 * order c0 ∥ c1 (Fp6 as c0 ∥ c1 ∥ c2, Fp2 as c0 ∥ c1) with 48-byte big-endian limbs, which is the
 * limb order the Rust reference writes. Compare with node-owned vectors when available.
 */
function decodeGt(bytes: Uint8Array): Fp12 {
  try {
    return Gt.fromBytes(bytes);
  } catch {
    throw new BtxError(
      "InvalidPoint",
      `not a canonical ${GT_SIZE}-byte G_T element`,
    );
  }
}

/** Encodes a target-group element in its canonical 576-byte form. */
function encodeGt(element: Fp12): Uint8Array {
  return Gt.toBytes(element);
}

export type { Fp12, G1Point };
export {
  decodeG1,
  decodeGt,
  decodeScalar,
  encodeG1,
  encodeGt,
  encodeScalar,
  Fr,
  G1,
  G1_SIZE,
  G2,
  Gt,
  GT_SIZE,
  pairing,
  randomScalar,
  SCALAR_ENTROPY_SIZE,
  SCALAR_SIZE,
  wideScalar,
};
