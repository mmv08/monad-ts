import type { Fp12 } from "@noble/curves/abstract/tower.js";
import type { WeierstrassPoint } from "@noble/curves/abstract/weierstrass.js";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { abytes, bytesToNumberBE, numberToBytesBE } from "./bytes.js";
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
/** CatBLST interleaves the two Fp6 halves at each Fp2 index; Noble stores each half together. */
const GT_FP2_ORDER = [0, 3, 1, 4, 2, 5] as const;
const FP2_SIZE = 96;

/**
 * Decodes a 48-byte compressed G_1 slice from the wire decoder. Rejects non-canonical encodings,
 * points off the curve, and points outside the prime-order subgroup. Admission rejects the identity.
 *
 * Canonicality rests on the noble decoder: limbs are range-checked, the identity has one
 * encoding, and the compressed flag must be set. The dependency pin fixes that behaviour.
 */
function decodeG1(bytes: Uint8Array): G1Point {
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
  // Arithmetic can produce a projective identity that Noble's encoder rejects.
  return (point.is0() ? G1.Point.ZERO : point).toBytes(true);
}

/** Decodes a 32-byte slice from the wire proof, rejecting scalars at or above the group order. */
function decodeScalar(bytes: Uint8Array): bigint {
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

/** Samples a nonzero scalar with Noble's BLS12-381 secret-key sampler. */
function randomScalar(): bigint {
  return bytesToNumberBE(bls12_381.utils.randomSecretKey());
}

/**
 * Decodes a canonical 576-byte encryption key, rejecting the identity and values outside G_T.
 * This checks the key's form, not its source or epoch.
 *
 * TODO(spec): the PDF does not fix the limb order. Use CatBLST's wire contract: Fp2 index,
 * then Fp6 half, then Fp component, with 48-byte big-endian limbs.
 */
function decodeEncryptionKey(bytes: Uint8Array): Fp12 {
  let key: Fp12;
  try {
    abytes(bytes, GT_SIZE);
    const nobleBytes = new Uint8Array(GT_SIZE);
    for (const [wireIndex, nobleIndex] of GT_FP2_ORDER.entries()) {
      nobleBytes.set(
        bytes.subarray(wireIndex * FP2_SIZE, (wireIndex + 1) * FP2_SIZE),
        nobleIndex * FP2_SIZE,
      );
    }
    key = Gt.fromBytes(nobleBytes);
  } catch {
    throw new BtxError(
      "InvalidPoint",
      `not a canonical ${GT_SIZE}-byte G_T element`,
    );
  }
  if (Gt.eql(key, Gt.ONE) || !Gt.eql(Gt.pow(key, Fr.ORDER), Gt.ONE)) {
    throw new BtxError(
      "InvalidPoint",
      "encryption key must be a non-identity element of G_T",
    );
  }
  return key;
}

/** Encodes a target-group element in CatBLST's canonical 576-byte form. */
function encodeGt(element: Fp12): Uint8Array {
  const nobleBytes = Gt.toBytes(element);
  const bytes = new Uint8Array(GT_SIZE);
  for (const [wireIndex, nobleIndex] of GT_FP2_ORDER.entries()) {
    bytes.set(
      nobleBytes.subarray(nobleIndex * FP2_SIZE, (nobleIndex + 1) * FP2_SIZE),
      wireIndex * FP2_SIZE,
    );
  }
  return bytes;
}

export type { Fp12, G1Point };
export {
  decodeEncryptionKey,
  decodeG1,
  decodeScalar,
  encodeG1,
  encodeGt,
  encodeScalar,
  Fr,
  G1,
  G1_SIZE,
  G2,
  Gt,
  pairing,
  randomScalar,
  SCALAR_SIZE,
};
