import { describe, expect, spyOn, test } from "bun:test";
import { G1 } from "../src/curve.js";
import {
  admitCiphertext,
  assertValidCiphertext,
  encrypt,
  serializeCiphertext,
  verifyDecryption,
} from "../src/index.js";
import { createTestKey } from "../src/testing.js";
import { expectBtxError, pattern } from "./utils.js";

const key = createTestKey({ trapdoor: 42n });
const plaintext = pattern(30);
const ad = pattern(32);
const ciphertext = encrypt({
  plaintext,
  associatedData: ad,
  encryptionKey: key.encryptionKey,
});
const wire = serializeCiphertext(ciphertext);

describe("wire admission", () => {
  test("decodes the point once in admission and once in wire decryption", () => {
    const decode = spyOn(G1.Point, "fromBytes");
    try {
      expect(admitCiphertext(wire, ad)).toEqual(ciphertext);
      expect(decode).toHaveBeenCalledTimes(1);
      expect(key.decrypt(wire, ad)?.plaintext).toEqual(plaintext);
      expect(decode).toHaveBeenCalledTimes(2);
    } finally {
      decode.mockRestore();
    }
  });

  test.each(["Uint8Array", "Buffer"])("owns admitted bytes from %s", (kind) => {
    const input = kind === "Buffer" ? Buffer.from(wire) : wire.slice();
    const admitted = admitCiphertext(input, ad);
    input.fill(0);
    expect(admitted).toEqual(ciphertext);
    expect(key.decrypt(admitted, ad)?.plaintext).toEqual(plaintext);

    admitted.maskedPayload[0] ^= 1;
    expectBtxError(
      () => assertValidCiphertext(admitted, ad),
      "ClientNizkFailed",
    );
    expectBtxError(() => key.decrypt(admitted, ad), "ClientNizkFailed");
    expect(admitCiphertext(wire, ad)).toEqual(ciphertext);
  });

  test("enforces wire limits before curve work in both paths", () => {
    const options = {
      maxMaskedPayloadLength: ciphertext.maskedPayload.length - 1,
    };
    const decode = spyOn(G1.Point, "fromBytes");
    try {
      expectBtxError(() => admitCiphertext(wire, ad, options), "InvalidLength");
      expectBtxError(() => key.decrypt(wire, ad, options), "InvalidLength");
      expect(decode).not.toHaveBeenCalled();
    } finally {
      decode.mockRestore();
    }
    expect(
      key.decrypt(wire, ad, {
        maxMaskedPayloadLength: ciphertext.maskedPayload.length,
      })?.plaintext,
    ).toEqual(plaintext);
  });

  test("binds wire decryption to associated data", () => {
    expectBtxError(
      () => key.decrypt(wire, new Uint8Array(32)),
      "ClientNizkFailed",
    );
  });

  test("owned-buffer XOR does not change caller inputs", () => {
    const originalPlaintext = plaintext.slice();
    const originalAd = ad.slice();
    const originalKey = key.encryptionKey.slice();
    const encrypted = encrypt({
      plaintext,
      associatedData: ad,
      encryptionKey: key.encryptionKey,
    });
    const before = serializeCiphertext(encrypted);
    const result = key.decrypt(encrypted, ad);
    expect(result).not.toBeNull();
    if (!result) throw new Error("decryption failed");
    const seed = result.seed.slice();
    expect(
      verifyDecryption({
        ciphertext: encrypted,
        plaintext,
        seed: result.seed,
        associatedData: ad,
        encryptionKey: key.encryptionKey,
      }),
    ).toBe(true);
    expect(serializeCiphertext(encrypted)).toEqual(before);
    expect(plaintext).toEqual(originalPlaintext);
    expect(ad).toEqual(originalAd);
    expect(key.encryptionKey).toEqual(originalKey);
    expect(result.seed).toEqual(seed);
    result.plaintext.fill(0);
    expect(key.decrypt(encrypted, ad)?.plaintext).toEqual(plaintext);
  });
});
