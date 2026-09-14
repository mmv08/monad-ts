import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "../src/bytes.js";
import { mptRoot } from "../src/mpt.js";

// Official Ethereum TrieTests, pinned to
// https://github.com/ethereum/tests/tree/c67e485ff8b5be9abc8ad15345ec21aa22e290d9/TrieTests
type OfficialCase = {
  in: Record<string, string> | [string, string | null][];
  root: string;
};

const OFFICIAL_SUITES = [
  ["hex_encoded_securetrie_test.json", true],
  ["trieanyorder_secureTrie.json", true],
  ["trietest_secureTrie.json", true],
  ["trieanyorder.json", false],
  ["trietest.json", false],
] as const;

function loadSuite(file: string): Record<string, OfficialCase> {
  return JSON.parse(
    readFileSync(
      new URL(`./fixtures/TrieTests/${file}`, import.meta.url),
      "utf8",
    ),
  ) as Record<string, OfficialCase>;
}

function toBytes(input: string): Uint8Array {
  return input.startsWith("0x")
    ? hexToBytes(input.slice(2))
    : utf8ToBytes(input);
}

function pairsFromInput(
  input: OfficialCase["in"],
  hashKeys: boolean,
): [Uint8Array, Uint8Array][] {
  const leaves = new Map<string, Uint8Array>();
  const entries = Array.isArray(input) ? input : Object.entries(input);

  for (const [key, value] of entries) {
    if (value === null) leaves.delete(key);
    else leaves.set(key, toBytes(value));
  }

  return [...leaves].map(([key, value]) => {
    const keyBytes = toBytes(key);
    return [hashKeys ? keccak_256(keyBytes) : keyBytes, value];
  });
}

describe("official Ethereum TrieTests", () => {
  for (const [file, hashKeys] of OFFICIAL_SUITES) {
    describe(file, () => {
      const suite = loadSuite(file);
      for (const [name, testCase] of Object.entries(suite)) {
        test(name, () => {
          expect(
            bytesToHex(mptRoot(pairsFromInput(testCase.in, hashKeys))),
          ).toBe(testCase.root.slice(2));
        });
      }
    });
  }
});

describe("mptRoot", () => {
  test("hashes a small leaf at the root", () => {
    expect(bytesToHex(mptRoot([[utf8ToBytes("a"), utf8ToBytes("b")]]))).toBe(
      "09ca68268104f67d9da9c8514ebdd8c98c6667aba87016f8602a1fbefb575216",
    );
  });
});
