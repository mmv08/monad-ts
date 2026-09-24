/**
 * Test-only key material and decryption.
 *
 * INSECURE. One party holds the trapdoor τ, so whoever holds a test key decrypts at once. There is
 * no threshold, no share release, and no privacy or MEV-protection guarantee. Use it only in tests
 * and local development, and never import it from the sender library.
 */

import { unpad, validateCiphertext } from "./btx.js";
import { xorBytes, xorInto } from "./bytes.js";
import type { Ciphertext, DeserializeOptions } from "./ciphertext.js";
import { encodeGt, Fr, G1, G2, pairing, randomScalar } from "./curve.js";
import { expandR, hKem, hRho, kdf, prg } from "./hash.js";

/** Options for {@link createTestKey}. */
type TestKeyOptions = {
  /** The secret τ; drawn at random when omitted. */
  readonly trapdoor?: bigint;
  /** B_max, which selects the power of τ behind ek. Defaults to the production value. */
  readonly maxBatchSize?: number;
};

/** A recovered plaintext and the seed that witnesses it. */
type Decryption = {
  readonly plaintext: Uint8Array;
  readonly seed: Uint8Array;
};

/** A test-only encryption key together with the trapdoor that decrypts under it. */
type TestKey = {
  /** ek = [τ^(B_max+1)]_T, the 576-byte key a sender encrypts against. */
  readonly encryptionKey: Uint8Array;
  /** τ, the secret no party holds in production. */
  readonly trapdoor: bigint;
  /** B_max the key was generated for. */
  readonly maxBatchSize: number;
  /**
   * Admits and decrypts one ciphertext. Pass wire bytes to decode and verify once.
   * Options apply to wire bytes, before payload copying and curve work.
   *
   * @returns Plaintext and seed, or null if padding is malformed or the guardrail fails.
   * @throws {BtxError} If admission rejects the commitment or proof.
   * @throws {TypeError} If associated data or the masked seed is not a Uint8Array.
   * @throws {RangeError} If the masked seed is not 16 bytes.
   */
  decrypt(
    ciphertext: Ciphertext | Uint8Array,
    associatedData: Uint8Array,
    options?: DeserializeOptions,
  ): Decryption | null;
};

/** The production B_max. */
const DEFAULT_MAX_BATCH_SIZE = 256;

/**
 * Generates ek from a trapdoor and returns it with a decryptor that uses the trapdoor directly.
 * @throws {RangeError} If B_max is not a positive u32 or the trapdoor is not in [1, q).
 */
function createTestKey(options: TestKeyOptions = {}): TestKey {
  const maxBatchSize = options.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
  if (
    !Number.isSafeInteger(maxBatchSize) ||
    maxBatchSize < 1 ||
    maxBatchSize > 0xffff_ffff
  ) {
    throw new RangeError("maxBatchSize must be a positive u32");
  }
  const trapdoor = options.trapdoor ?? randomScalar();
  if (typeof trapdoor !== "bigint" || trapdoor <= 0n || trapdoor >= Fr.ORDER) {
    throw new RangeError("trapdoor must be a scalar in [1, q)");
  }
  // h = g_2·τ^(B_max+1) is the reference-string slot the DKG withholds, so e(g_1, h) = ek and
  // e(R, h) = ek·r is the pad the threshold path reconstructs from shares.
  const hole = G2.Point.BASE.multiply(
    Fr.pow(trapdoor, BigInt(maxBatchSize + 1)),
  );
  const encryptionKey = encodeGt(pairing(G1.Point.BASE, hole));
  return {
    encryptionKey,
    trapdoor,
    maxBatchSize,
    decrypt(input, associatedData, options) {
      const { ciphertext, commitment } = validateCiphertext(
        input,
        associatedData,
        options,
      );
      const pad = pairing(commitment, hole);
      const seed = xorBytes(
        ciphertext.maskedSeed,
        hKem(pad, ciphertext.commitment, associatedData),
      );
      const padded = xorInto(
        prg(kdf(seed, associatedData), ciphertext.maskedPayload.length),
        ciphertext.maskedPayload,
      );
      const plaintext = unpad(padded);
      if (plaintext === null) return null;
      // P was recovered from C_2 with this seed. Once padding is canonical,
      // re-encrypting P only repeats that XOR. The independent check is R = g_1·r.
      // The pairing pad equals ek^r when R matches, so C_1 needs no second check here.
      const r = expandR(hRho(associatedData, padded, seed));
      if (r === 0n || !G1.Point.BASE.multiply(r).equals(commitment)) {
        return null;
      }
      return { plaintext, seed };
    },
  };
}

export { createTestKey };
