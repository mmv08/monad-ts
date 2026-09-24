import { abytes, concatBytes, readU32be, u32be } from "./bytes.js";
import { decodeG1, decodeScalar, G1_SIZE, SCALAR_SIZE } from "./curve.js";
import { BtxError } from "./error.js";

/** A BTX ciphertext (R, C_1, C_2, π), each component in its canonical byte form. */
type Ciphertext = {
  /** R: the KEM commitment, a compressed G_1 point (48 bytes). */
  readonly commitment: Uint8Array;
  /** C_1: the seed masked under the pad (16 bytes). */
  readonly maskedSeed: Uint8Array;
  /** C_2: the padded plaintext masked by the stream (4 + padded_len bytes). */
  readonly maskedPayload: Uint8Array;
  /** π = (c, s): the Schnorr proof as two 32-byte scalars (64 bytes). */
  readonly proof: Uint8Array;
};

/** Wire decoding options, also used by admission and test decryption. */
type DeserializeOptions = {
  /**
   * Largest accepted maskedPayload length (C_2), including the 4-byte plaintext-length prefix.
   * Excludes CIPHERTEXT_OVERHEAD. Must be a nonnegative safe integer; no limit when omitted.
   *
   * TODO(spec): the PDF leaves this limit to the caller and fixes no default.
   */
  readonly maxMaskedPayloadLength?: number;
};

/** Byte length of C_1. */
const MASKED_SEED_SIZE = 16;
/** Byte length of the C_2 length prefix. */
const LENGTH_PREFIX_SIZE = 4;
/** Byte length of π. */
const PROOF_SIZE = 2 * SCALAR_SIZE;
/** 132 wire bytes beyond maskedPayload; excludes its inner 4-byte plaintext-length prefix. */
const CIPHERTEXT_OVERHEAD =
  G1_SIZE + MASKED_SEED_SIZE + LENGTH_PREFIX_SIZE + PROOF_SIZE;

/**
 * serialize_ciphertext: `R ∥ C_1 ∥ len(C_2) as u32be ∥ C_2 ∥ π`.
 * Checks component widths, not point/scalar canonicality or the client proof.
 *
 * @throws {TypeError} If a component is not a Uint8Array.
 * @throws {RangeError} If a fixed-width component has the wrong length.
 */
function serializeCiphertext(ciphertext: Ciphertext): Uint8Array {
  abytes(ciphertext.commitment, G1_SIZE);
  abytes(ciphertext.maskedSeed, MASKED_SEED_SIZE);
  abytes(ciphertext.maskedPayload);
  abytes(ciphertext.proof, PROOF_SIZE);
  return concatBytes(
    ciphertext.commitment,
    ciphertext.maskedSeed,
    u32be(ciphertext.maskedPayload.length),
    ciphertext.maskedPayload,
    ciphertext.proof,
  );
}

/**
 * deserialize_ciphertext: decodes the wire form, rejecting anything that is not its one canonical
 * serialization. Internal codec entry for format tests; consumers use admitCiphertext.
 * The point is fully validated here, including subgroup membership. Decoding does not check
 * the client proof or reject an identity commitment.
 *
 * @throws {BtxError} If the wire encoding, masked-payload length, or size limit is rejected.
 * @throws {TypeError} If bytes is not a Uint8Array.
 */
function deserializeCiphertext(
  bytes: Uint8Array,
  options: DeserializeOptions = {},
): Ciphertext {
  return decodeCiphertextBytes(bytes, options).ciphertext;
}

/** Owns the wire components and decodes each point and scalar once. */
function decodeCiphertextBytes(
  bytes: Uint8Array,
  options: DeserializeOptions = {},
) {
  abytes(bytes);
  const maxMaskedPayloadLength = options.maxMaskedPayloadLength;
  if (
    maxMaskedPayloadLength !== undefined &&
    (!Number.isSafeInteger(maxMaskedPayloadLength) ||
      maxMaskedPayloadLength < 0)
  ) {
    throw new BtxError(
      "InvalidLength",
      "masked-payload size limit must be a nonnegative safe integer",
    );
  }
  if (bytes.length < CIPHERTEXT_OVERHEAD) {
    throw new BtxError(
      "InvalidLength",
      `shorter than ${CIPHERTEXT_OVERHEAD} bytes`,
    );
  }
  const payloadLength = readU32be(bytes, G1_SIZE + MASKED_SEED_SIZE);
  if (bytes.length !== CIPHERTEXT_OVERHEAD + payloadLength) {
    throw new BtxError(
      "InvalidLength",
      "declared C_2 length disagrees with the buffer",
    );
  }
  if (
    maxMaskedPayloadLength !== undefined &&
    payloadLength > maxMaskedPayloadLength
  ) {
    throw new BtxError("InvalidLength", "C_2 exceeds the size limit");
  }
  const commitment = Uint8Array.from(bytes.subarray(0, G1_SIZE));
  const maskedSeed = Uint8Array.from(
    bytes.subarray(G1_SIZE, G1_SIZE + MASKED_SEED_SIZE),
  );
  const payloadStart = G1_SIZE + MASKED_SEED_SIZE + LENGTH_PREFIX_SIZE;
  const maskedPayload = Uint8Array.from(
    bytes.subarray(payloadStart, payloadStart + payloadLength),
  );
  const proof = Uint8Array.from(bytes.subarray(payloadStart + payloadLength));
  return {
    ciphertext: { commitment, maskedSeed, maskedPayload, proof },
    commitment: decodeG1(commitment),
    c: decodeScalar(proof.subarray(0, SCALAR_SIZE)),
    s: decodeScalar(proof.subarray(SCALAR_SIZE)),
  };
}

export type { Ciphertext, DeserializeOptions };
export {
  CIPHERTEXT_OVERHEAD,
  decodeCiphertextBytes,
  deserializeCiphertext,
  LENGTH_PREFIX_SIZE,
  MASKED_SEED_SIZE,
  serializeCiphertext,
};
