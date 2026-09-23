import { describe, expect, test } from "bun:test";
import { Buffer } from "node:buffer";
import { u32be } from "../src/bytes.js";
import { encodeScalar, Fr } from "../src/curve.js";
import {
  assertValidCiphertext,
  CIPHERTEXT_OVERHEAD,
  deserializeCiphertext,
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
// x = 4: on the curve, but the point is not in the prime-order subgroup.
const OUT_OF_SUBGROUP = `${"80".padEnd(94, "0")}04`;
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

  test.each([
    ["Uint8Array", bytes.slice()],
    ["Buffer", Buffer.from(bytes)],
  ] as const)("returns copies that later mutation of the %s input cannot change", (_, input) => {
    const decoded = deserializeCiphertext(input);
    assertValidCiphertext(decoded, ad);
    input.fill(0);

    expect(decoded).toEqual(ciphertext);
    assertValidCiphertext(decoded, ad);
  });

  test("rejects non-byte input", () => {
    expect(() => deserializeCiphertext("00" as unknown as Uint8Array)).toThrow(
      TypeError,
    );
  });
});

describe("deserialization rejects", () => {
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

  test("trailing bytes", () => {
    const trailing = new Uint8Array(bytes.length + 1);
    trailing.set(bytes);

    expectBtxError(() => deserializeCiphertext(trailing), "InvalidLength");
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

  test.each([
    ["an x with no point on the curve", OFF_CURVE],
    ["a point outside the prime-order subgroup", OUT_OF_SUBGROUP],
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

  test("a proof scalar that is not below the group order", () => {
    const tampered = bytes.slice();
    tampered.set(encodeScalar(Fr.ORDER), bytes.length - 32);

    expectBtxError(() => deserializeCiphertext(tampered), "InvalidScalar");
  });
});

describe("the identity as R", () => {
  test("decodes, and is rejected by assertValidCiphertext", () => {
    const decoded = deserializeCiphertext(withCommitment(IDENTITY));

    expect(decoded.commitment).toEqual(hexToBytes(IDENTITY));
    expectBtxError(
      () => assertValidCiphertext(decoded, ad),
      "InvalidCiphertext",
    );
  });
});
