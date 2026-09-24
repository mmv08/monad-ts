import { describe, expect, test } from "bun:test";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { numberToBytesBE, u32be } from "../src/bytes.js";
import { deserializeCiphertext } from "../src/ciphertext.js";
import {
  admitCiphertext,
  CIPHERTEXT_OVERHEAD,
  encrypt,
  serializeCiphertext,
} from "../src/index.js";
import { createTestKey } from "../src/testing.js";
import { expectBtxError, hexToBytes, pattern, utf8ToBytes } from "./utils.js";

const key = createTestKey({ trapdoor: 0x5eedn });
const ad = utf8ToBytes("associated data");
const ciphertext = encrypt({
  plaintext: pattern(40),
  encryptionKey: key.encryptionKey,
  associatedData: ad,
  paddedLength: 40,
});
const bytes = serializeCiphertext(ciphertext);

// Compressed G_1 encodings with flag bits 0b100 and a small x; found by trying x = 1, 2, …
// x = 1: x³ + 4 has no square root, so no point has this x.
const OFF_CURVE = `${"80".padEnd(94, "0")}01`;
// x = p: the field modulus is not a canonical field element.
const NON_CANONICAL =
  "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
// The identity has one encoding: the infinity flag and zero x.
const IDENTITY = "c0".padEnd(96, "0");

function withCommitment(hex: string): Uint8Array {
  const copy = bytes.slice();
  copy.set(hexToBytes(hex));
  return copy;
}

describe("serialization", () => {
  test.each([
    ["commitment", 47],
    ["commitment", 49],
    ["maskedSeed", 15],
    ["maskedSeed", 17],
    ["proof", 63],
    ["proof", 65],
  ] as const)("rejects %s with %i bytes", (field, length) => {
    expect(() =>
      serializeCiphertext({ ...ciphertext, [field]: new Uint8Array(length) }),
    ).toThrow(RangeError);
  });

  test("lays out R ∥ C_1 ∥ len(C_2) ∥ C_2 ∥ π", () => {
    expect(bytes).toHaveLength(CIPHERTEXT_OVERHEAD + 44);
    expect(bytes.subarray(0, 48)).toEqual(ciphertext.commitment);
    expect(bytes.subarray(48, 64)).toEqual(ciphertext.maskedSeed);
    expect(bytes.subarray(64, 68)).toEqual(u32be(44));
    expect(bytes.subarray(68, 112)).toEqual(ciphertext.maskedPayload);
    expect(bytes.subarray(112)).toEqual(ciphertext.proof);
  });

  test("round-trips", () => {
    expect(deserializeCiphertext(bytes)).toEqual(ciphertext);
    expect(serializeCiphertext(deserializeCiphertext(bytes))).toEqual(bytes);
  });

  test("rejects non-byte input", () => {
    expect(() => deserializeCiphertext("00" as unknown as Uint8Array)).toThrow(
      TypeError,
    );
  });
});

describe("deserialization rejects", () => {
  test("a non-canonical x that reduces to a valid subgroup point", () => {
    const point = bls12_381.G1.Point.BASE.multiply(2n);
    const canonical = point.toBytes();
    const overflowingX = point.toAffine().x + bls12_381.fields.Fp.ORDER;
    expect(overflowingX).toBeLessThan(1n << 381n);
    const nonCanonical = numberToBytesBE(overflowingX, 48);
    nonCanonical[0] |= canonical[0] & 0xe0;
    const wire = bytes.slice();
    wire.set(nonCanonical);
    expectBtxError(() => deserializeCiphertext(wire), "InvalidPoint");

    // A reducing decoder would recover this valid point, so subgroup checks cannot help.
    wire.set(canonical);
    expect(deserializeCiphertext(wire).commitment).toEqual(canonical);
  });

  // Rust admission vectors cover trailing bytes, non-subgroup points, and noncanonical scalars.
  test("input shorter than the fixed-width components", () => {
    expectBtxError(
      () => deserializeCiphertext(bytes.subarray(0, CIPHERTEXT_OVERHEAD - 1)),
      "InvalidLength",
    );
  });

  test("a declared C_2 length that disagrees with the buffer", () => {
    const shorter = bytes.slice();
    shorter.set(u32be(43), 64);
    const longer = bytes.slice();
    longer.set(u32be(45), 64);

    expectBtxError(() => deserializeCiphertext(shorter), "InvalidLength");
    expectBtxError(() => deserializeCiphertext(longer), "InvalidLength");
  });

  test("a C_2 above the caller's size limit", () => {
    expect(() =>
      deserializeCiphertext(bytes, { maxMaskedPayloadLength: 44 }),
    ).not.toThrow();
    expectBtxError(
      () => deserializeCiphertext(bytes, { maxMaskedPayloadLength: 43 }),
      "InvalidLength",
    );
  });

  test("a nonempty C_2 when the size limit is zero", () => {
    expectBtxError(
      () => deserializeCiphertext(bytes, { maxMaskedPayloadLength: 0 }),
      "InvalidLength",
    );
    const empty = { ...ciphertext, maskedPayload: new Uint8Array(0) };
    expect(
      deserializeCiphertext(serializeCiphertext(empty), {
        maxMaskedPayloadLength: 0,
      }),
    ).toEqual(empty);
  });

  test.each([
    -1,
    43.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ])("an invalid size limit of %d", (maxMaskedPayloadLength) => {
    expectBtxError(
      () => deserializeCiphertext(bytes, { maxMaskedPayloadLength }),
      "InvalidLength",
    );
  });

  test.each([
    ["an x with no point on the curve", OFF_CURVE],
    ["a non-canonical field element", NON_CANONICAL],
    ["an uncompressed flag", `00${OFF_CURVE.slice(2)}`],
    ["the infinity flag with a nonzero x", `c0${OFF_CURVE.slice(2)}`],
    ["the infinity flag with the sort bit set", `e0${IDENTITY.slice(2)}`],
  ])("%s as R", (_, hex) => {
    expectBtxError(
      () => deserializeCiphertext(withCommitment(hex)),
      "InvalidPoint",
    );
  });
});

describe("the identity as R", () => {
  test("decodes, but admission rejects it", () => {
    const decoded = deserializeCiphertext(withCommitment(IDENTITY));

    expect(decoded.commitment).toEqual(hexToBytes(IDENTITY));
    expectBtxError(
      () => admitCiphertext(withCommitment(IDENTITY), ad),
      "InvalidCiphertext",
    );
  });
});
