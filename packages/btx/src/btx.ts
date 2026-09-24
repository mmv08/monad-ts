import {
  abytes,
  concatBytes,
  equalBytes,
  randomBytes,
  readU32be,
  u32be,
  xorBytes,
} from "./bytes.js";
import {
  type Ciphertext,
  LENGTH_PREFIX_SIZE,
  MASKED_SEED_SIZE,
} from "./ciphertext.js";
import {
  decodeEncryptionKey,
  decodeG1,
  decodeScalar,
  encodeG1,
  encodeScalar,
  type Fp12,
  Fr,
  G1,
  type G1Point,
  Gt,
  randomScalar,
  SCALAR_SIZE,
} from "./curve.js";
import { BtxError } from "./error.js";
import { challenge, expandR, hKem, hRho, kdf, prg } from "./hash.js";

/** Named inputs for {@link encrypt}. */
type EncryptParameters = {
  /** Unpadded plaintext bytes. */
  readonly plaintext: Uint8Array;
  /** Canonical 576-byte, non-identity G_T key. The caller must authenticate its source and epoch. */
  readonly encryptionKey: Uint8Array;
  /** Transaction binding bytes, constructed by the caller. */
  readonly associatedData: Uint8Array;
  /** Plaintext capacity, excluding the 4-byte length prefix. Defaults to {@link paddedLengthFor}. */
  readonly paddedLength?: number;
};

/** Named inputs for {@link verifyDecryption}. */
type VerifyDecryptionParameters = {
  /** Ciphertext already admitted by {@link assertValidCiphertext}. */
  readonly ciphertext: Ciphertext;
  /** Canonical 576-byte, non-identity G_T key used for encryption. The caller must authenticate its source and epoch. */
  readonly encryptionKey: Uint8Array;
  /** Candidate unpadded plaintext. */
  readonly plaintext: Uint8Array;
  /** Recovered 16-byte seed that witnesses the plaintext. */
  readonly seed: Uint8Array;
  /** The same transaction binding bytes used for encryption. */
  readonly associatedData: Uint8Array;
};

/** Byte length of the seed S. */
const SEED_SIZE = MASKED_SEED_SIZE;
/** The default padding rounds |M| up to a multiple of this many bytes. */
const PADDING_UNIT = 256;
/** The largest padded_len whose C_2 length still fits the 4-byte prefix. */
const MAX_PADDED_LENGTH = 0xffff_ffff - LENGTH_PREFIX_SIZE;

/**
 * The default padded length: |M| rounded up to a multiple of 256, and at least 256.
 *
 * @throws {BtxError} If the length is not a nonnegative integer or the padded result exceeds the wire limit.
 *
 * TODO(spec): the PDF leaves padded_len to the sender and fixes no policy. This default comes
 * from the delivery plan; an unusual padded length is itself distinguishing.
 */
function paddedLengthFor(plaintextLength: number): number {
  if (!Number.isInteger(plaintextLength) || plaintextLength < 0) {
    throw new BtxError(
      "InvalidLength",
      "plaintext length must be a nonnegative integer",
    );
  }
  const paddedLength = Math.max(
    PADDING_UNIT,
    Math.ceil(plaintextLength / PADDING_UNIT) * PADDING_UNIT,
  );
  if (paddedLength > MAX_PADDED_LENGTH) {
    throw new BtxError(
      "InvalidLength",
      "default padding exceeds the wire limit",
    );
  }
  return paddedLength;
}

/** P = u32be(|M|) ∥ M ∥ 0x00 × (padded_len − |M|). */
function pad(plaintext: Uint8Array, paddedLength: number): Uint8Array {
  if (
    !Number.isInteger(paddedLength) ||
    paddedLength < plaintext.length ||
    paddedLength > MAX_PADDED_LENGTH
  ) {
    throw new BtxError(
      "InvalidLength",
      `padded length ${paddedLength} is not valid for ${plaintext.length} plaintext bytes`,
    );
  }
  const padded = new Uint8Array(LENGTH_PREFIX_SIZE + paddedLength);
  padded.set(u32be(plaintext.length));
  padded.set(plaintext, LENGTH_PREFIX_SIZE);
  return padded;
}

/** unpad: recovers M from P, or null when the declared length overruns or the filler is not zero. */
function unpad(padded: Uint8Array): Uint8Array | null {
  if (padded.length < LENGTH_PREFIX_SIZE) return null;
  const end = LENGTH_PREFIX_SIZE + readU32be(padded, 0);
  if (end > padded.length) return null;
  for (let i = end; i < padded.length; i++) if (padded[i] !== 0) return null;
  return padded.slice(LENGTH_PREFIX_SIZE, end);
}

/** prove: the Schnorr proof (c, s) of knowledge of r, its challenge bound to (R, C_1, C_2, AD). */
function prove(
  ciphertext: Omit<Ciphertext, "proof">,
  associatedData: Uint8Array,
  r: bigint,
  nonce: bigint,
): Uint8Array {
  const nonceCommitment = encodeG1(G1.Point.BASE.multiply(nonce));
  const c = challenge(
    ciphertext.commitment,
    nonceCommitment,
    ciphertext.maskedSeed,
    ciphertext.maskedPayload,
    associatedData,
  );
  return concatBytes(
    encodeScalar(c),
    encodeScalar(Fr.sub(nonce, Fr.mul(c, r))),
  );
}

/** verify: recomputes T' = g_1·s + R·c and checks that it reproduces the challenge. */
function verifyProof(
  commitment: G1Point,
  ciphertext: Ciphertext,
  associatedData: Uint8Array,
): boolean {
  const c = decodeScalar(ciphertext.proof.subarray(0, SCALAR_SIZE));
  const s = decodeScalar(ciphertext.proof.subarray(SCALAR_SIZE));
  const nonceCommitment = G1.Point.BASE.multiplyUnsafe(s).add(
    commitment.multiplyUnsafe(c),
  );
  const expected = challenge(
    ciphertext.commitment,
    encodeG1(nonceCommitment),
    ciphertext.maskedSeed,
    ciphertext.maskedPayload,
    associatedData,
  );
  return expected === c;
}

/** Encrypts padded bytes; tests can also supply malformed padding to exercise decryption. */
function encryptPadded(
  paddedPlaintext: Uint8Array,
  encryptionKey: Fp12,
  associatedData: Uint8Array,
  random: (byteLength: number) => Uint8Array,
): Ciphertext {
  let seed: Uint8Array;
  let r: bigint;
  do {
    seed = abytes(random(SEED_SIZE), SEED_SIZE);
    r = expandR(hRho(associatedData, paddedPlaintext, seed));
  } while (r === 0n);
  const commitment = encodeG1(G1.Point.BASE.multiply(r));
  const pad = Gt.pow(encryptionKey, r);
  const maskedSeed = xorBytes(seed, hKem(pad, commitment, associatedData));
  const maskedPayload = xorBytes(
    paddedPlaintext,
    prg(kdf(seed, associatedData), paddedPlaintext.length),
  );
  const body = { commitment, maskedSeed, maskedPayload };
  // TODO(spec): the PDF writes the proof nonce as `rng.scalar()` without fixing its derivation.
  const nonce = randomScalar(random);
  return { ...body, proof: prove(body, associatedData, r, nonce) };
}

/**
 * Encrypts plaintext under the epoch encryption key, bound to associated data.
 *
 * @throws {BtxError} If the encryption key or padded length is invalid.
 * @throws {TypeError} If plaintext or associated data is not a Uint8Array.
 */
function encrypt(parameters: EncryptParameters): Ciphertext {
  return encryptWithRandom(parameters, randomBytes);
}

/** Internal encryption entry for fixtures; the public entry always uses the platform CSPRNG. */
function encryptWithRandom(
  { plaintext, encryptionKey, associatedData, paddedLength }: EncryptParameters,
  random: (byteLength: number) => Uint8Array,
): Ciphertext {
  abytes(plaintext);
  abytes(associatedData);
  const padded = pad(
    plaintext,
    paddedLength ?? paddedLengthFor(plaintext.length),
  );
  const ek = decodeEncryptionKey(encryptionKey);
  return encryptPadded(padded, ek, associatedData, random);
}

/** Runs admission and returns the decoded commitment for test decryption to reuse. */
function validateCiphertext(
  ciphertext: Ciphertext,
  associatedData: Uint8Array,
): G1Point {
  abytes(associatedData);
  abytes(ciphertext.maskedSeed, MASKED_SEED_SIZE);
  const commitment = decodeG1(ciphertext.commitment);
  if (commitment.is0()) {
    throw new BtxError("InvalidCiphertext", "R is the identity");
  }
  if (!verifyProof(commitment, ciphertext, associatedData)) {
    throw new BtxError("ClientNizkFailed", "the client proof does not verify");
  }
  return commitment;
}

/**
 * Admits a ciphertext by checking its commitment and client proof against associated data
 * (the specification's verify_ciphertext). Decode received bytes with deserializeCiphertext first.
 *
 * @returns Nothing on success; does not decrypt or check a plaintext witness.
 * @throws {BtxError} If the commitment or proof is rejected.
 * @throws {TypeError} If associated data or the masked seed is not a Uint8Array.
 * @throws {RangeError} If the masked seed is not 16 bytes.
 */
function assertValidCiphertext(
  ciphertext: Ciphertext,
  associatedData: Uint8Array,
): void {
  validateCiphertext(ciphertext, associatedData);
}

/**
 * Checks that the plaintext and seed reproduce the commitment, masked seed, and masked payload
 * under the encryption key. Does not check the proof; call {@link assertValidCiphertext} first.
 *
 * @returns True for a matching witness, false for a mismatch.
 * @throws {BtxError} If the encryption key is invalid.
 * @throws {TypeError} If a byte input is not a Uint8Array.
 * @throws {RangeError} If the seed is not 16 bytes.
 */
function verifyDecryption({
  ciphertext,
  encryptionKey,
  plaintext,
  seed,
  associatedData,
}: VerifyDecryptionParameters): boolean {
  abytes(plaintext);
  abytes(seed, SEED_SIZE);
  abytes(associatedData);
  const paddedLength = ciphertext.maskedPayload.length - LENGTH_PREFIX_SIZE;
  if (plaintext.length > paddedLength) return false;
  const padded = pad(plaintext, paddedLength);
  const ek = decodeEncryptionKey(encryptionKey);
  const r = expandR(hRho(associatedData, padded, seed));
  if (
    r === 0n ||
    !equalBytes(
      encodeG1(G1.Point.BASE.multiplyUnsafe(r)),
      ciphertext.commitment,
    )
  ) {
    return false;
  }
  // TODO(spec): Rust's independent witness check also binds C_1 to ek. The PDF's
  // R/C_2-only check cannot reject a sender's inconsistent C_1 with a valid proof.
  const expectedMaskedSeed = xorBytes(
    seed,
    hKem(Gt.pow(ek, r), ciphertext.commitment, associatedData),
  );
  if (!equalBytes(ciphertext.maskedSeed, expectedMaskedSeed)) return false;
  const stream = prg(kdf(seed, associatedData), padded.length);
  return equalBytes(ciphertext.maskedPayload, xorBytes(padded, stream));
}

export {
  assertValidCiphertext,
  encrypt,
  encryptPadded,
  encryptWithRandom,
  pad,
  paddedLengthFor,
  unpad,
  validateCiphertext,
  verifyDecryption,
};
