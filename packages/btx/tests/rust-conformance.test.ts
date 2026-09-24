import { describe, expect, test } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils.js";
import { pad } from "../src/btx.js";
import { concatBytes, numberToBytesBE, utf8ToBytes } from "../src/bytes.js";
import {
  decodeEncryptionKey,
  encodeG1,
  encodeGt,
  G1,
  G2,
  Gt,
  pairing,
} from "../src/curve.js";
import { challenge, expandR, hKem, hRho, kdf, prg } from "../src/hash.js";
import {
  admitCiphertext,
  BtxError,
  serializeCiphertext,
} from "../src/index.js";
import admission from "./fixtures/rust-admission.json" with { type: "json" };

// Independent known answers from monad-encrypted-tx/src/btx.rs,
// reviewed_primitive_transcripts_match_known_answers, at 71a4400bc82e2879acfcd064de5472b098b0e593.
// Do not regenerate these with the TypeScript fixture generator.
describe("Rust primitive known answers", () => {
  const ad = utf8ToBytes("btx/ad/vector");
  const seed = utf8ToBytes("0123456789abcdef");
  const padded = pad(utf8ToBytes("message\0"), 12);
  const generator = pairing(G1.Point.BASE, G2.Point.BASE);
  const commitment = encodeG1(G1.Point.BASE.multiply(7n));

  test("padding, coins, and scalar match Rust", () => {
    expect(padded).toEqual(hexToBytes("000000086d6573736167650000000000"));
    const rho = hRho(ad, padded, seed);
    expect(rho).toEqual(hexToBytes("0bb20a951445b56ccf3f381064b72bbe"));
    expect(expandR(rho)).toBe(
      0x3722104c35efc2a868977b98297d90268bff40c8a6de41d8614055e2a88f2045n,
    );
  });

  test("KEM uses CatBLST's GT coefficient order", () => {
    expect(hKem(generator, commitment, ad)).toEqual(
      hexToBytes("860dbbc5a14c011232556bbcc6da71c7"),
    );
  });

  test("key decoding reads CatBLST order rather than Noble order", () => {
    // Spell out the wire order independently of the production codec.
    const { c0: a, c1: b } = generator;
    // Each Fp2 has both its real and imaginary coefficient (48 bytes each).
    const canonical = concatBytes(
      ...[a.c0, b.c0, a.c1, b.c1, a.c2, b.c2].flatMap((fp2) => [
        numberToBytesBE(fp2.c0, 48),
        numberToBytesBE(fp2.c1, 48),
      ]),
    );
    expect(encodeGt(generator)).toEqual(canonical);
    expect(Gt.eql(decodeEncryptionKey(canonical), generator)).toBe(true);
    expect(() => decodeEncryptionKey(Gt.toBytes(generator))).toThrow(BtxError);
  });

  test("DEM key and stream match Rust", () => {
    const dem = kdf(seed, ad);
    expect(dem).toEqual(
      hexToBytes(
        "217ace3d27563001818b48d6b85f753fc06e7bd0e359db340cf9fcecadf4fb5e",
      ),
    );
    expect(prg(dem, 40)).toEqual(
      hexToBytes(
        "0f6f1759ba2771b86c894e04984f3e6c540a0be064e75da50a31aae6ab1825d98e749ed89f817b7c",
      ),
    );
  });

  test("proof challenge matches Rust", () => {
    expect(
      challenge(
        new Uint8Array(48).fill(0x11),
        new Uint8Array(48).fill(0x22),
        new Uint8Array(16).fill(0x33),
        padded,
        ad,
      ),
    ).toBe(0x023a8684e45862caf6d91d4597389d8b21965ee1e7a6790ffe3a76e6a4746bcan);
  });
});

describe("Rust admission vectors", () => {
  const errorIds: Record<string, string> = {
    InvalidLength: "invalid_length",
    InvalidPoint: "invalid_point",
    InvalidScalar: "invalid_scalar",
    InvalidCiphertext: "identity_point",
    ClientNizkFailed: "client_nizk_failed",
  };

  test.each(admission.cases)("$name", (vector) => {
    let wire = hexToBytes(admission.ciphertext);
    if (vector.replace !== undefined) {
      wire.set(hexToBytes(vector.replace), vector.offset);
    }
    if (vector.truncate !== undefined) wire = wire.slice(0, -vector.truncate);
    if (vector.append !== undefined)
      wire = concatBytes(wire, hexToBytes(vector.append));
    const ad = hexToBytes(vector.ad ?? admission.ad);
    let result = "ok";
    try {
      const ciphertext = admitCiphertext(wire, ad);
      expect(serializeCiphertext(ciphertext)).toEqual(wire);
    } catch (error) {
      if (!(error instanceof BtxError)) throw error;
      result = errorIds[error.code];
    }
    expect(result).toBe(vector.expect);
  });
});
