import { describe, expect, spyOn, test } from "bun:test";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { encryptPadded, encryptWithRandom, pad, unpad } from "../src/btx.js";
import {
  bytesToNumberBE,
  concatBytes,
  numberToBytesBE,
  u32be,
  xorBytes,
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
  admitCiphertext,
  type Ciphertext,
  encrypt,
  paddedLengthFor,
  serializeCiphertext,
  verifyDecryption,
} from "../src/index.js";
import { createTestKey } from "../src/testing.js";
import {
  expectBtxError,
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
});

describe("encrypt and decrypt", () => {
  test("round-trips through public encryption with default padding", () => {
    const plaintext = pattern(30);
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });

    expect(ciphertext.maskedPayload).toHaveLength(260);
    const decrypted = key.decrypt(serializeCiphertext(ciphertext), ad);

    expect(decrypted?.plaintext).toEqual(plaintext);
    expect(decrypted?.seed).toHaveLength(16);
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
    expect(() =>
      encrypt({
        plaintext: utf8ToBytes("platform randomness only"),
        encryptionKey: key.encryptionKey,
        associatedData: ad,
        // @ts-expect-error Randomness injection is not part of the public API.
        randomBytes: () => {
          throw new Error("caller randomness must not be used");
        },
      }),
    ).not.toThrow();
  });

  test("round-trips with a generated test key", () => {
    const generated = createTestKey();
    const plaintext = utf8ToBytes("generated key");
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: generated.encryptionKey,
      associatedData: ad,
    });

    expect(
      generated.decrypt(serializeCiphertext(ciphertext), ad)?.plaintext,
    ).toEqual(plaintext);
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
        scriptedRandom(new Uint8Array(16), seed),
        () => 1n,
      );
      expect(expand).toHaveBeenCalledTimes(2);
    } finally {
      expand.mockRestore();
    }

    const decrypted = key.decrypt(serializeCiphertext(ciphertext), ad);
    expect(decrypted?.plaintext).toEqual(plaintext);
    expect(decrypted?.seed).toEqual(seed);
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

  test.each([
    ["shorter than the plaintext", 9],
    ["not an integer", 10.5],
    ["too long for the length prefix", 0xffff_fffc],
  ])("rejects a padded length %s", (_, paddedLength) => {
    expectBtxError(
      () =>
        encrypt({
          plaintext: pattern(10),
          encryptionKey: key.encryptionKey,
          associatedData: ad,
          paddedLength,
        }),
      "InvalidLength",
    );
  });
});

describe("ciphertext admission and witnesses", () => {
  const plaintext = utf8ToBytes("bound to this transaction");
  const seed = pattern(16);
  const ciphertext = encryptWithRandom(
    { plaintext, encryptionKey: key.encryptionKey, associatedData: ad },
    scriptedRandom(seed),
    () => 0x1234n,
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
    const wire = serializeCiphertext(altered);
    admitCiphertext(wire, ad);
    expect(
      verifyDecryption({
        ciphertext: altered,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(false);
    expect(key.decrypt(wire, ad)).toBeNull();
  });

  test("rejects a nonzero commitment mismatch after valid admission and unpadding", () => {
    const maskedPayload = ciphertext.maskedPayload.slice();
    // Change a message byte, leaving the encrypted length and zero filler intact.
    maskedPayload[4] ^= 1;
    const altered = withProof({ ...ciphertext, maskedPayload }, 7n);
    const wire = serializeCiphertext(altered);
    admitCiphertext(wire, ad);

    const recoveredPadded = xorBytes(
      maskedPayload,
      hashes.prg(hashes.kdf(seed, ad), maskedPayload.length),
    );
    const recovered = unpad(recoveredPadded);
    expect(recovered).not.toBeNull();
    expect(recovered).not.toEqual(plaintext);
    const recoveredR = hashes.expandR(hashes.hRho(ad, recoveredPadded, seed));
    expect(recoveredR).not.toBe(0n);
    expect(recoveredR).not.toBe(r);
    expect(key.decrypt(wire, ad)).toBeNull();
  });

  test("accepts a zero-nonce proof whose nonzero terms cancel to the identity", () => {
    const wire = serializeCiphertext(withProof(ciphertext, 0n));
    const received = admitCiphertext(wire, ad);
    expect(decodeScalar(received.proof.subarray(0, 32))).not.toBe(0n);
    expect(decodeScalar(received.proof.subarray(32))).not.toBe(0n);

    expect(
      verifyDecryption({
        ciphertext: received,
        encryptionKey: key.encryptionKey,
        plaintext,
        seed,
        associatedData: ad,
      }),
    ).toBe(true);
    expect(key.decrypt(wire, ad)).toEqual({ plaintext, seed });
  });

  test("rejects an invalid proof whose reconstructed nonce commitment is the identity", () => {
    const proof = concatBytes(encodeScalar(1n), encodeScalar(Fr.neg(r)));

    expectBtxError(
      () => admitCiphertext(serializeCiphertext({ ...ciphertext, proof }), ad),
      "ClientNizkFailed",
    );
  });

  test.each<[string, Partial<Ciphertext>]>([
    ["commitment", { commitment: other.commitment }],
    ["masked seed", { maskedSeed: flipLastByte(ciphertext.maskedSeed) }],
    ["proof", { proof: flipLastByte(ciphertext.proof) }],
  ])("rejects a ciphertext whose %s was altered", (_, change) => {
    expectBtxError(
      () =>
        admitCiphertext(serializeCiphertext({ ...ciphertext, ...change }), ad),
      "ClientNizkFailed",
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
      createTestKey({ trapdoor: 0xbadn }).decrypt(
        serializeCiphertext(ciphertext),
        ad,
      ),
    ).toBeNull();
  });

  test("returns ⊥ when the padding declares an overrunning length", () => {
    const padded = new Uint8Array(4 + 8);
    padded.set(u32be(9));
    const ciphertext = encryptPadded(
      padded,
      ek,
      ad,
      scriptedRandom(seed),
      () => nonce,
    );

    expect(key.decrypt(serializeCiphertext(ciphertext), ad)).toBeNull();
  });

  test("returns ⊥ when the filler is not zero", () => {
    const padded = pad(plaintext, 16);
    padded[padded.length - 1] = 0xff;
    const ciphertext = encryptPadded(
      padded,
      ek,
      ad,
      scriptedRandom(seed),
      () => nonce,
    );

    expect(key.decrypt(serializeCiphertext(ciphertext), ad)).toBeNull();
  });

  test("returns ⊥ for a C_2 shorter than the length prefix", () => {
    const ciphertext = encryptPadded(
      new Uint8Array(2),
      ek,
      ad,
      scriptedRandom(seed),
      () => nonce,
    );

    expect(key.decrypt(serializeCiphertext(ciphertext), ad)).toBeNull();
  });

  test.each([
    -1n,
    0n,
    Fr.ORDER,
    Fr.ORDER + 1n,
  ])("rejects invalid trapdoor %s", (trapdoor) => {
    expect(() => createTestKey({ trapdoor })).toThrow(RangeError);
  });

  test.each([
    -1,
    0,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    0x1_0000_0000,
  ])("rejects invalid batch size %s", (maxBatchSize) => {
    expect(() => createTestKey({ maxBatchSize })).toThrow(RangeError);
  });

  test.each([
    1, 0xffff_ffff,
  ])("accepts batch-size boundary %s", (maxBatchSize) => {
    const boundaryKey = createTestKey({ trapdoor: 42n, maxBatchSize });
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: boundaryKey.encryptionKey,
      associatedData: ad,
    });
    expect(
      boundaryKey.decrypt(serializeCiphertext(ciphertext), ad)?.plaintext,
    ).toEqual(plaintext);
  });

  test("returns bottom when the recovered witness derives zero", () => {
    const ciphertext = encrypt({
      plaintext,
      encryptionKey: key.encryptionKey,
      associatedData: ad,
    });
    const expand = spyOn(hashes, "expandR").mockReturnValue(0n);
    try {
      expect(key.decrypt(serializeCiphertext(ciphertext), ad)).toBeNull();
    } finally {
      expand.mockRestore();
    }
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
  const decrypted = key.decrypt(serializeCiphertext(ciphertext), ad);
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
      () => admitCiphertext(serializeCiphertext(invalid), ad),
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
