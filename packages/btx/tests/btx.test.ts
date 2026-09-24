import { describe, expect, spyOn, test } from "bun:test";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { encryptPadded, encryptWithRandom, pad, unpad } from "../src/btx.js";
import {
  bytesToNumberBE,
  concatBytes,
  numberToBytesBE,
  u32be,
} from "../src/bytes.js";
import {
  decodeEncryptionKey,
  decodeScalar,
  encodeG1,
  encodeGt,
  encodeScalar,
  Fr,
  G1,
  Gt,
} from "../src/curve.js";
import * as hashes from "../src/hash.js";
import {
  assertValidCiphertext,
  type Ciphertext,
  deserializeCiphertext,
  encrypt,
  paddedLengthFor,
  serializeCiphertext,
  verifyDecryption,
} from "../src/index.js";
import { createTestKey } from "../src/testing.js";
import {
  expectBtxError,
  fixedRandom,
  pattern,
  scriptedRandom,
  utf8ToBytes,
} from "./utils.js";

const key = createTestKey({ trapdoor: 0x5eedn });
const ad = utf8ToBytes("associated data");

describe("padding", () => {
  test.each([
    [0, 256],
    [1, 256],
    [255, 256],
    [256, 256],
    [257, 512],
    [1000, 1024],
    [0xffff_ff00, 0xffff_ff00],
  ])("pads a %i-byte plaintext to %i bytes by default", (length, padded) => {
    expect(paddedLengthFor(length)).toBe(padded);
  });

  test.each([
    -1,
    0.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    0xffff_ff01,
    0xffff_fffb,
    Number.MAX_SAFE_INTEGER,
  ])("rejects %d as a default-padding input", (length) => {
    expectBtxError(() => paddedLengthFor(length), "InvalidLength");
  });

  test("prefixes the true length and fills with zeroes", () => {
    const padded = pad(utf8ToBytes("abc"), 8);

    expect(padded).toEqual(
      Uint8Array.from([0, 0, 0, 3, 0x61, 0x62, 0x63, 0, 0, 0, 0, 0]),
    );
    expect(unpad(padded)).toEqual(utf8ToBytes("abc"));
  });

  test("allows an exact fit", () => {
    expect(unpad(pad(pattern(300), 300))).toEqual(pattern(300));
    expect(unpad(pad(new Uint8Array(0), 0))).toEqual(new Uint8Array(0));
  });

  test.each([
    ["shorter than the plaintext", 2],
    ["not an integer", 4.5],
    ["too long for the length prefix", 0xffff_fffc],
  ])("rejects a padded length %s", (_, paddedLength) => {
    expectBtxError(
      () => pad(utf8ToBytes("abc"), paddedLength),
      "InvalidLength",
    );
  });

  test("unpad rejects a declared length that overruns the buffer", () => {
    const padded = new Uint8Array(8);
    padded.set(u32be(5));

    expect(unpad(padded)).toBeNull();
    expect(unpad(new Uint8Array(3))).toBeNull();
  });

  test("unpad rejects nonzero filler", () => {
    const padded = pad(utf8ToBytes("abc"), 8);
    padded[padded.length - 1] = 1;

    expect(unpad(padded)).toBeNull();
  });
});

describe("encrypt and decrypt", () => {
  test.each([
    0, 1, 255, 256, 257, 1000,
  ])("round-trips a %i-byte plaintext with default padding", (length) => {
    const plaintext = pattern(length);
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });

    expect(ciphertext.maskedPayload).toHaveLength(4 + paddedLengthFor(length));
    const received = deserializeCiphertext(serializeCiphertext(ciphertext));
    assertValidCiphertext(received, ad);
    const decrypted = key.decrypt(received, ad);

    expect(decrypted?.plaintext).toEqual(plaintext);
    expect(decrypted?.seed).toHaveLength(16);
  });

  test("round-trips an exact-fit ciphertext, including trailing zeroes", () => {
    const plaintext = Uint8Array.from([1, 2, 3, 0, 0, 0]);
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
      paddedLength: plaintext.length,
    });

    expect(ciphertext.maskedPayload).toHaveLength(4 + plaintext.length);
    expect(key.decrypt(ciphertext, ad)?.plaintext).toEqual(plaintext);
  });

  test("is a deterministic function of (AD, P, S) and the proof nonce", () => {
    const seed = pattern(16);
    const nonce = 0x1234n;
    const plaintext = utf8ToBytes("same inputs");
    const parameters = {
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    };
    const first = encryptWithRandom(parameters, fixedRandom(seed, nonce));
    const second = encryptWithRandom(parameters, fixedRandom(seed, nonce));

    expect(serializeCiphertext(first)).toEqual(serializeCiphertext(second));
  });

  test("draws fresh randomness by default", () => {
    const plaintext = utf8ToBytes("same inputs");
    const first = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });
    const second = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });

    expect(first.commitment).not.toEqual(second.commitment);
  });

  test("the public entry cannot use a caller's randomness override", () => {
    const plaintext = utf8ToBytes("platform randomness only");
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
      // @ts-expect-error Randomness injection is not part of the public API.
      randomBytes: scriptedRandom(),
    });

    expect(key.decrypt(ciphertext, ad)?.plaintext).toEqual(plaintext);
  });

  test("round-trips with a generated test key", () => {
    const generated = createTestKey();
    const plaintext = utf8ToBytes("generated key");
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: generated.encryptionKey,
      associatedData: ad,
    });

    expect(generated.decrypt(ciphertext, ad)?.plaintext).toEqual(plaintext);
  });

  test("reuses the admitted commitment throughout test decryption", () => {
    const plaintext = utf8ToBytes("one point decode");
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });
    const decode = spyOn(G1.Point, "fromBytes");
    try {
      expect(key.decrypt(ciphertext, ad)?.plaintext).toEqual(plaintext);
      expect(decode).toHaveBeenCalledTimes(1);
    } finally {
      decode.mockRestore();
    }
  });

  test("derives r once per seed and resamples a zero result", () => {
    const seed = pattern(16);
    const plaintext = utf8ToBytes("resampled");
    const expand = spyOn(hashes, "expandR").mockReturnValueOnce(0n);
    let ciphertext: Ciphertext;
    try {
      ciphertext = encryptWithRandom(
        {
          plaintext,
          encryptionKey: key.encryptionKey,
          associatedData: ad,
        },
        scriptedRandom(new Uint8Array(16), seed, new Uint8Array(48)),
      );
      expect(expand).toHaveBeenCalledTimes(2);
    } finally {
      expand.mockRestore();
    }

    const decrypted = key.decrypt(ciphertext, ad);
    expect(decrypted?.plaintext).toEqual(plaintext);
    expect(decrypted?.seed).toEqual(seed);
  });

  test.each([
    ["seed", new Uint8Array(15), new Uint8Array(48)],
    ["nonce entropy", new Uint8Array(16), new Uint8Array(64)],
  ] as const)("rejects injected %s of the wrong length", (_, seed, entropy) => {
    expect(() =>
      encryptWithRandom(
        {
          plaintext: new Uint8Array(0),
          encryptionKey: key.encryptionKey,
          associatedData: ad,
        },
        (length) => (length === 16 ? seed : entropy),
      ),
    ).toThrow(RangeError);
  });

  test("rejects non-byte inputs", () => {
    expect(() =>
      encrypt({
        plaintext: "text" as unknown as Uint8Array,
        encryptionKey: key.encryptionKey,
        associatedData: ad,
      }),
    ).toThrow(TypeError);
    expect(() =>
      encrypt({
        plaintext: new Uint8Array(0),
        encryptionKey: key.encryptionKey,
        associatedData: 1 as unknown as Uint8Array,
      }),
    ).toThrow(TypeError);
  });

  test("rejects an encryption key of the wrong length", () => {
    expectBtxError(
      () =>
        encrypt({
          plaintext: new Uint8Array(0),
          encryptionKey: new Uint8Array(576 - 1),
          associatedData: ad,
        }),
      "InvalidPoint",
    );
  });

  test("rejects a non-canonical encryption key", () => {
    const nonCanonical = key.encryptionKey.slice();
    // A limb equal to the field modulus is not the canonical form of zero.
    nonCanonical.set(
      Uint8Array.from(
        Buffer.from(
          "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
          "hex",
        ),
      ),
    );

    expectBtxError(
      () =>
        encrypt({
          plaintext: new Uint8Array(0),
          encryptionKey: nonCanonical,
          associatedData: ad,
        }),
      "InvalidPoint",
    );
  });

  test("rejects an overflowing key limb that reduces to a valid G_T element", () => {
    const nonCanonical = key.encryptionKey.slice();
    const limb = bytesToNumberBE(nonCanonical.subarray(0, 48));
    nonCanonical.set(numberToBytesBE(limb + bls12_381.fields.Fp.ORDER, 48));

    // Modular reduction would restore this valid key and evade the membership check.
    expect(() => decodeEncryptionKey(key.encryptionKey)).not.toThrow();
    expectBtxError(() => decodeEncryptionKey(nonCanonical), "InvalidPoint");
  });

  test.each([
    ["zero", Gt.ZERO],
    ["the identity", Gt.ONE],
    ["a canonical field element outside G_T", Gt.add(Gt.ONE, Gt.ONE)],
  ] as const)("rejects %s as an encryption key", (_, encryptionKey) => {
    expectBtxError(
      () =>
        encrypt({
          plaintext: utf8ToBytes("must not encrypt under a public constant"),
          encryptionKey: encodeGt(encryptionKey),
          associatedData: ad,
        }),
      "InvalidPoint",
    );
  });

  test("rejects a padded length below the plaintext length", () => {
    expectBtxError(
      () =>
        encrypt({
          plaintext: pattern(10),
          encryptionKey: key.encryptionKey,
          associatedData: ad,
          paddedLength: 9,
        }),
      "InvalidLength",
    );
  });
});

describe("assertValidCiphertext", () => {
  const plaintext = utf8ToBytes("bound to this transaction");
  const seed = pattern(16);
  const ciphertext = encryptWithRandom(
    { plaintext, encryptionKey: key.encryptionKey, associatedData: ad },
    fixedRandom(seed, 0x1234n),
  );
  const r = hashes.expandR(
    hashes.hRho(ad, pad(plaintext, ciphertext.maskedPayload.length - 4), seed),
  );
  const other = encrypt({
    plaintext,
    encryptionKey: key.encryptionKey,
    associatedData: ad,
  });

  function flipLastByte(bytes: Uint8Array): Uint8Array {
    const copy = bytes.slice();
    copy[copy.length - 1] ^= 1;
    return copy;
  }

  function withProof(body: Ciphertext, nonce: bigint): Ciphertext {
    const c = hashes.challenge(
      body.commitment,
      encodeG1(G1.Point.BASE.multiplyUnsafe(nonce)),
      body.maskedSeed,
      body.maskedPayload,
      ad,
    );
    return {
      ...body,
      proof: concatBytes(
        encodeScalar(c),
        encodeScalar(Fr.sub(nonce, Fr.mul(c, r))),
      ),
    };
  }

  test.each([
    "maskedSeed",
    "maskedPayload",
  ] as const)("rejects a witness for altered %s even with a valid new proof", (field) => {
    const altered = withProof(
      { ...ciphertext, [field]: flipLastByte(ciphertext[field]) },
      7n,
    );
    assertValidCiphertext(altered, ad);
    expect(
      verifyDecryption({
        ciphertext: altered,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(false);
    expect(key.decrypt(altered, ad)).toBeNull();
  });

  test("accepts a zero-nonce proof whose nonzero terms cancel to the identity", () => {
    const received = deserializeCiphertext(
      serializeCiphertext(withProof(ciphertext, 0n)),
    );
    expect(decodeScalar(received.proof.subarray(0, 32))).not.toBe(0n);
    expect(decodeScalar(received.proof.subarray(32))).not.toBe(0n);

    expect(assertValidCiphertext(received, ad)).toBeUndefined();
    expect(
      verifyDecryption({
        ciphertext: received,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(true);
    expect(key.decrypt(received, ad)).toEqual({ plaintext, seed });
  });

  test("rejects an invalid proof whose reconstructed nonce commitment is the identity", () => {
    const proof = concatBytes(encodeScalar(1n), encodeScalar(Fr.neg(r)));

    expectBtxError(
      () => assertValidCiphertext({ ...ciphertext, proof }, ad),
      "ClientNizkFailed",
    );
  });

  test.each([
    0, 15, 17,
  ])("rejects a %i-byte masked seed even with a matching proof", (length) => {
    const malformed = withProof(
      { ...ciphertext, maskedSeed: new Uint8Array(length) },
      1n,
    );

    expect(() => assertValidCiphertext(malformed, ad)).toThrow(RangeError);
    expect(() => key.decrypt(malformed, ad)).toThrow(RangeError);
  });

  test.each<[string, Partial<Ciphertext>]>([
    ["commitment", { commitment: other.commitment }],
    ["masked seed", { maskedSeed: flipLastByte(ciphertext.maskedSeed) }],
    [
      "masked payload",
      { maskedPayload: flipLastByte(ciphertext.maskedPayload) },
    ],
    ["proof", { proof: flipLastByte(ciphertext.proof) }],
  ])("rejects a ciphertext whose %s was altered", (_, change) => {
    expectBtxError(
      () => assertValidCiphertext({ ...ciphertext, ...change }, ad),
      "ClientNizkFailed",
    );
  });

  test("rejects a ciphertext lifted into another context", () => {
    const otherAd = utf8ToBytes("another sender or transaction");

    expectBtxError(
      () => assertValidCiphertext(ciphertext, otherAd),
      "ClientNizkFailed",
    );
    expectBtxError(() => key.decrypt(ciphertext, otherAd), "ClientNizkFailed");
  });

  test("rejects a proof scalar that is not below the group order", () => {
    const proof = ciphertext.proof.slice();
    proof.set(encodeScalar(Fr.ORDER), 32);

    expectBtxError(
      () => assertValidCiphertext({ ...ciphertext, proof }, ad),
      "InvalidScalar",
    );
  });

  test("rejects a proof of the wrong length", () => {
    expectBtxError(
      () =>
        assertValidCiphertext({ ...ciphertext, proof: new Uint8Array(63) }, ad),
      "InvalidScalar",
    );
  });

  test.each([47, 48, 96])("rejects a zero commitment of %i bytes", (length) => {
    expectBtxError(
      () =>
        assertValidCiphertext(
          { ...ciphertext, commitment: new Uint8Array(length) },
          ad,
        ),
      "InvalidPoint",
    );
  });
});

describe("decryption guardrails", () => {
  const plaintext = utf8ToBytes("guarded");
  const ek = decodeEncryptionKey(key.encryptionKey);
  const seed = pattern(16);
  const nonce = 0x1234n;

  test("returns ⊥ under the wrong key", () => {
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });

    expect(
      createTestKey({ trapdoor: 0xbadn }).decrypt(ciphertext, ad),
    ).toBeNull();
  });

  test("returns ⊥ when the padding declares an overrunning length", () => {
    const padded = new Uint8Array(4 + 8);
    padded.set(u32be(9));
    const ciphertext = encryptPadded(padded, ek, ad, fixedRandom(seed, nonce));

    assertValidCiphertext(ciphertext, ad);
    expect(key.decrypt(ciphertext, ad)).toBeNull();
  });

  test("returns ⊥ when the filler is not zero", () => {
    const padded = pad(plaintext, 16);
    padded[padded.length - 1] = 0xff;
    const ciphertext = encryptPadded(padded, ek, ad, fixedRandom(seed, nonce));

    assertValidCiphertext(ciphertext, ad);
    expect(key.decrypt(ciphertext, ad)).toBeNull();
  });

  test("returns ⊥ for a C_2 shorter than the length prefix", () => {
    const ciphertext = encryptPadded(
      new Uint8Array(2),
      ek,
      ad,
      fixedRandom(seed, nonce),
    );

    expect(key.decrypt(ciphertext, ad)).toBeNull();
  });

  test("rejects zero as an explicit trapdoor", () => {
    expect(() => createTestKey({ trapdoor: 0n })).toThrow(RangeError);
  });
});

describe("verifyDecryption", () => {
  const plaintext = utf8ToBytes("witnessed");
  const ciphertext = encrypt({
    plaintext,
    encryptionKey: key.encryptionKey,
    associatedData: ad,
    paddedLength: 32,
  });
  const decrypted = key.decrypt(ciphertext, ad);
  if (decrypted === null) throw new Error("decryption failed");
  const { seed } = decrypted;

  test("accepts the seed recovered by decryption", () => {
    expect(
      verifyDecryption({
        ciphertext,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(true);
  });

  test("rejects a witness under another valid encryption key", () => {
    assertValidCiphertext(ciphertext, ad);
    expect(
      verifyDecryption({
        ciphertext,
        encryptionKey: createTestKey({ trapdoor: 0xbadn }).encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(false);
  });

  test("rejects an invalid encryption key", () => {
    expectBtxError(
      () =>
        verifyDecryption({
          ciphertext,
          encryptionKey: encodeGt(Gt.ONE),
          plaintext,
          seed,
          associatedData: ad,
        }),
      "InvalidPoint",
    );
  });

  test("rejects a payload shorter than the length prefix", () => {
    expect(
      verifyDecryption({
        ciphertext: { ...ciphertext, maskedPayload: new Uint8Array(3) },
        encryptionKey: key.encryptionKey,
        plaintext: new Uint8Array(0),
        seed,
        associatedData: ad,
      }),
    ).toBe(false);
  });

  test("checks the witness without replacing ciphertext admission", () => {
    const invalid = { ...ciphertext, proof: new Uint8Array(64) };

    expect(
      verifyDecryption({
        ciphertext: invalid,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(true);
    expectBtxError(
      () => assertValidCiphertext(invalid, ad),
      "ClientNizkFailed",
    );
  });

  test.each<[string, Uint8Array, Uint8Array, Uint8Array]>([
    ["plaintext", utf8ToBytes("witnesses"), seed, ad],
    ["seed", plaintext, pattern(16), ad],
    ["associated data", plaintext, seed, utf8ToBytes("other")],
  ])("rejects a wrong %s", (_, m, s, a) => {
    expect(
      verifyDecryption({
        ciphertext,
        encryptionKey: key.encryptionKey,
        plaintext: m,
        seed: s,
        associatedData: a,
      }),
    ).toBe(false);
  });

  test("rejects a plaintext longer than the padded capacity", () => {
    expect(
      verifyDecryption({
        ciphertext,
        encryptionKey: key.encryptionKey,
        plaintext: pattern(33),
        seed,
        associatedData: ad,
      }),
    ).toBe(false);
  });

  test.each([
    47, 48, 96,
  ])("returns false for a %i-byte commitment that does not match the witness", (length) => {
    expect(
      verifyDecryption({
        ciphertext: { ...ciphertext, commitment: new Uint8Array(length) },
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(false);
  });

  test("returns false rather than throwing when the witness derives zero", () => {
    const expand = spyOn(hashes, "expandR").mockReturnValue(0n);
    try {
      expect(
        verifyDecryption({
          ciphertext,
          encryptionKey: key.encryptionKey,
          plaintext,
          seed,
          associatedData: ad,
        }),
      ).toBe(false);
    } finally {
      expand.mockRestore();
    }
  });

  test("rejects a seed of the wrong length", () => {
    expect(() =>
      verifyDecryption({
        ciphertext,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed: new Uint8Array(15),
        associatedData: ad,
      }),
    ).toThrow(RangeError);
  });
});
