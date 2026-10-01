import { describe, expect, test } from "bun:test";
import { utf8ToBytes } from "../src/bytes.js";
import { challenge } from "../src/hash.js";

describe("challenge", () => {
  const r = new Uint8Array(48).fill(1);
  const t = new Uint8Array(48).fill(2);
  const c1 = new Uint8Array(16).fill(3);

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
