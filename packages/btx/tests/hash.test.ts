import { describe, expect, test } from "bun:test";
import { blake3 } from "@noble/hashes/blake3.js";
import { concatBytes, u64be, utf8ToBytes } from "../src/bytes.js";
import { absorbLp, challenge, derive, expandR } from "../src/hash.js";

describe("absorbLp", () => {
  test("absorbs the 8-byte big-endian length before the bytes", () => {
    const input = utf8ToBytes("length prefixed");
    const context = utf8ToBytes("test/context");
    const expected = blake3
      .create({ context })
      .update(concatBytes(u64be(input.length), input))
      .xof(32);

    expect(absorbLp(derive("test/context"), input).xof(32)).toEqual(expected);
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
