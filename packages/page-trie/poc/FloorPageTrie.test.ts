import { describe, expect, test } from "bun:test";
import { bytesToHex } from "@noble/hashes/utils.js";

import { createPageTrie } from "../src/index.js";
import { SLOT_SIZE } from "../src/page.js";
import { uint256 } from "../testing/utils.js";
import { type FloorBatchOperation, FloorPageTrie } from "./FloorPageTrie.js";

// Root fixtures copied verbatim from src/PageTrie.test.ts: the floor design
// must produce byte-identical roots.
const EMPTY_MPT_ROOT =
  "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
const SINGLE_SLOT_ROOT =
  "29612e2a4d60ff8ea37cd72e9ed9dba7ae3329b31b3ff9127b531951c100937b";
const MULTI_PAGE_ROOT =
  "775e329db94de90aa7838a2100d87ce4554743a3c53e17af6c08ec8ae30d2e2e";
const MULTI_PAGE_ROOT_WITHOUT_PAGE_1 =
  "6fe15d13e490eccd84df0e2d452fe2c2eb4920e6ea164c85a0235be5e4d09292";
const PAGE_0_ONLY_ROOT =
  "5a288fbd769c48b925182c924fffa24f252c0ec4f8c2d5d2dcf41f11b08ad20f";
const MULTI_PAGE_ENTRIES = [
  [0n, 11n],
  [1n, 12n],
  [127n, 13n],
  [128n, 14n],
  [511n, 15n],
] as const;

async function rootHex(trie: FloorPageTrie): Promise<string> {
  return bytesToHex(await trie.root());
}

describe("FloorPageTrie roots", () => {
  test("starts at the canonical empty MPT root", async () => {
    expect(await rootHex(new FloorPageTrie())).toBe(EMPTY_MPT_ROOT);
  });

  test("matches the single-slot root fixture", async () => {
    const trie = new FloorPageTrie();

    trie.put(uint256(0n), uint256(1n));

    expect(await rootHex(trie)).toBe(SINGLE_SLOT_ROOT);
  });

  test("matches the multi-page root fixture in both orders", async () => {
    const sequential = new FloorPageTrie();
    const batched = new FloorPageTrie();

    for (const [key, value] of MULTI_PAGE_ENTRIES) {
      sequential.put(uint256(key), uint256(value));
    }
    batched.batch(
      [...MULTI_PAGE_ENTRIES].reverse().map(([key, value]) => ({
        type: "put",
        key: uint256(key),
        value: uint256(value),
      })),
    );

    expect(await rootHex(sequential)).toBe(MULTI_PAGE_ROOT);
    expect(await rootHex(batched)).toBe(MULTI_PAGE_ROOT);
  });

  test("matches the deletion fixtures while deleting whole pages", async () => {
    const trie = new FloorPageTrie();
    trie.batch(
      MULTI_PAGE_ENTRIES.map(([key, value]) => ({
        type: "put",
        key: uint256(key),
        value: uint256(value),
      })),
    );

    trie.del(uint256(128n));
    expect(await rootHex(trie)).toBe(MULTI_PAGE_ROOT_WITHOUT_PAGE_1);

    trie.del(uint256(511n));
    expect(await rootHex(trie)).toBe(PAGE_0_ONLY_ROOT);
  });
});

describe("FloorPageTrie storage", () => {
  test("puts, gets, and deletes a slot", async () => {
    const trie = new FloorPageTrie();
    const key = uint256(42n);
    const value = uint256(99n);

    expect(trie.get(key)).toBeNull();
    trie.put(key, value);
    expect(trie.get(key)).toEqual(value);
    trie.del(key);
    expect(trie.get(key)).toBeNull();
    expect(await rootHex(trie)).toBe(EMPTY_MPT_ROOT);
  });

  test("treats a zero-word write as deletion", async () => {
    const trie = new FloorPageTrie();
    const key = uint256(7n);

    trie.put(key, uint256(1n));
    trie.put(key, new Uint8Array(SLOT_SIZE));

    expect(trie.get(key)).toBeNull();
    expect(await rootHex(trie)).toBe(EMPTY_MPT_ROOT);
  });
});

describe("FloorPageTrie differential", () => {
  test("matches the incremental design on a deterministic workload", async () => {
    const floor = new FloorPageTrie();
    const incremental = await createPageTrie();
    let seed = 42;
    const next = (bound: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % bound;
    };

    for (let round = 0; round < 8; round++) {
      const operations: FloorBatchOperation[] = Array.from(
        { length: 25 },
        () => {
          const key = uint256(BigInt(next(512)));
          return next(4) === 0
            ? { type: "del", key }
            : { type: "put", key, value: uint256(BigInt(next(1000000) + 1)) };
        },
      );

      floor.batch(operations);
      await incremental.batch(operations);

      expect(await rootHex(floor)).toBe(bytesToHex(incremental.root()));
    }
  });
});
