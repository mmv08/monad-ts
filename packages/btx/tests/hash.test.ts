import { describe, expect, test } from "bun:test";
import { blake3 } from "@noble/hashes/blake3.js";
import { concatBytes, hexToBytes, utf8ToBytes } from "../src/bytes.js";
import { Gt } from "../src/curve.js";
import { challenge, expandR, hKem, hRho, kdf, prg } from "../src/hash.js";

describe("Appendix E transcripts", () => {
  const ad = utf8ToBytes("ad");
  const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");

  test("H_rho prefixes AD and P, then absorbs S bare", () => {
    const padded = hexToBytes("0000000361626300");
    const expected = blake3
      .create({ context: utf8ToBytes("btx/coins/v1") })
      .update(
        concatBytes(
          hexToBytes("0000000000000002"),
          ad,
          hexToBytes("0000000000000008"),
          padded,
          seed,
        ),
      )
      .xof(16);

    expect(hRho(ad, padded, seed)).toEqual(expected);
  });

  test("H_kem absorbs the full pad and R bare, then prefixes AD", () => {
    const commitment = new Uint8Array(48).fill(1);
    const encodedPad = new Uint8Array(576);
    // G_T's identity has one in its first 48-byte big-endian limb.
    encodedPad[47] = 1;
    const expected = blake3
      .create({ context: utf8ToBytes("btx/kem/v1") })
      .update(
        concatBytes(encodedPad, commitment, hexToBytes("0000000000000002"), ad),
      )
      .xof(16);

    expect(hKem(Gt.ONE, commitment, ad)).toEqual(expected);
  });

  test("KDF absorbs S bare, then prefixes AD", () => {
    const expected = blake3
      .create({ context: utf8ToBytes("btx/dem/v1") })
      .update(concatBytes(seed, hexToBytes("0000000000000002"), ad))
      .xof(32);

    expect(kdf(seed, ad)).toEqual(expected);
  });

  test.each([
    0, 65,
  ])("PRG squeezes %i bytes in keyed mode without absorbing a message", (length) => {
    const key = new Uint8Array(32).fill(5);
    const expected = blake3.create({ key }).xof(length);

    expect(prg(key, length)).toEqual(expected);
  });
});

describe("challenge", () => {
  const r = new Uint8Array(48).fill(1);
  const t = new Uint8Array(48).fill(2);
  const c1 = new Uint8Array(16).fill(3);

  test("matches the fixed transcript scalar", () => {
    const ad = utf8ToBytes("ad");
    const c2 = utf8ToBytes("c2");

    expect(challenge(r, t, c1, c2, ad)).toBe(
      0x1d3067ff0d66fcf67bf8131b7dba1e0fbd0a443216c3f2c25b41c988ac9e3581n,
    );
  });

  test("distinguishes where C_2 ends and AD begins", () => {
    const shifted = challenge(r, t, c1, utf8ToBytes("ab"), utf8ToBytes("c"));

    expect(challenge(r, t, c1, utf8ToBytes("a"), utf8ToBytes("bc"))).not.toBe(
      shifted,
    );
  });

  test("changes with the nonce commitment", () => {
    const c2 = new Uint8Array(0);
    const ad = new Uint8Array(0);

    expect(challenge(r, t, c1, c2, ad)).not.toBe(challenge(r, r, c1, c2, ad));
  });
});

describe("scalar expansion", () => {
  test("expandR reduces modulo the group order", () => {
    expect(expandR(new Uint8Array(16).fill(0xff))).toBe(
      0x13d4f67fae97dfa2f12d058c35f829de2ec0354f232261372ee3a8c55519df1cn,
    );
  });
});
