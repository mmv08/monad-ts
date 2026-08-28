import { describe, expect, test } from "bun:test";
import { createMPT } from "@ethereumjs/mpt";
import { uint256 } from "../testing/utils.js";
import * as publicApi from "./index.js";
import { createPageTrie, type PageTrieBatchOperation } from "./index.js";
import { MemoryPageTrie, type Mpt } from "./PageTrie.js";
import {
  bytesToHex,
  computePageKey,
  PAGE_SIZE,
  pageCommit,
  SLOT_SIZE,
} from "./page.js";

const EMPTY_MPT_ROOT =
  "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

async function createInternalMpt(): Promise<
  Awaited<ReturnType<typeof createMPT>>
> {
  return createMPT({
    cacheSize: 0,
    useKeyHashing: true,
    useNodePruning: false,
    useRootPersistence: false,
  });
}

function delegateMpt(mpt: Awaited<ReturnType<typeof createMPT>>): Mpt {
  return {
    root: () => mpt.root(),
    put: (key, value) => mpt.put(key, value),
    del: (key) => mpt.del(key),
    checkpoint: () => mpt.checkpoint(),
    commit: () => mpt.commit(),
    revert: () => mpt.revert(),
    hasCheckpoints: () => mpt.hasCheckpoints(),
  };
}

describe("PageTrie roots", () => {
  test("exports only the documented runtime API", () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      "PAGE_SIZE",
      "PAGE_SLOTS",
      "SLOT_SIZE",
      "computePageKey",
      "computeSlotOffset",
      "createPageTrie",
      "pageCommit",
    ]);
  });

  test("starts at the canonical empty MPT root", async () => {
    const trie = await createPageTrie();

    expect(bytesToHex(trie.root())).toBe(EMPTY_MPT_ROOT);
  });

  test("matches the independent single-slot root fixture", async () => {
    const trie = await createPageTrie();

    await trie.put(uint256(0n), uint256(1n));

    expect(bytesToHex(trie.root())).toBe(
      "29612e2a4d60ff8ea37cd72e9ed9dba7ae3329b31b3ff9127b531951c100937b",
    );
  });

  test("is independent of insertion order", async () => {
    const forward = await createPageTrie();
    const reverse = await createPageTrie();
    const entries = [
      [0n, 11n],
      [1n, 12n],
      [127n, 13n],
      [128n, 14n],
      [511n, 15n],
    ] as const;

    for (const [key, value] of entries)
      await forward.put(uint256(key), uint256(value));
    for (const [key, value] of [...entries].reverse()) {
      await reverse.put(uint256(key), uint256(value));
    }

    expect(forward.root()).toEqual(reverse.root());
  });

  test("returns a defensive root copy", async () => {
    const trie = await createPageTrie();
    const expected = trie.root();
    const returned = trie.root();

    returned.fill(0xff);

    expect(trie.root()).toEqual(expected);
  });

  test("does not expose an uncommitted mutation", async () => {
    const trie = await createPageTrie();
    const write = trie.put(uint256(0n), uint256(1n));

    expect(bytesToHex(trie.root())).toBe(EMPTY_MPT_ROOT);
    await write;
    expect(bytesToHex(trie.root())).not.toBe(EMPTY_MPT_ROOT);
  });
});

describe("PageTrie storage", () => {
  test("puts, gets, and deletes a slot", async () => {
    const trie = await createPageTrie();
    const key = uint256(42n);
    const value = uint256(99n);

    expect(await trie.get(key)).toBeNull();
    await trie.put(key, value);
    expect(await trie.get(key)).toEqual(value);
    await trie.del(key);
    expect(await trie.get(key)).toBeNull();
    expect(bytesToHex(trie.root())).toBe(EMPTY_MPT_ROOT);
  });

  test("treats a zero-word write as deletion", async () => {
    const trie = await createPageTrie();
    const key = uint256(7n);

    await trie.put(key, uint256(1n));
    await trie.put(key, new Uint8Array(SLOT_SIZE));

    expect(await trie.get(key)).toBeNull();
    expect(bytesToHex(trie.root())).toBe(EMPTY_MPT_ROOT);
  });

  test("preserves untouched words in the same page", async () => {
    const trie = await createPageTrie();
    await trie.put(uint256(3n), uint256(30n));
    await trie.put(uint256(4n), uint256(40n));

    await trie.del(uint256(3n));

    expect(await trie.get(uint256(3n))).toBeNull();
    expect(await trie.get(uint256(4n))).toEqual(uint256(40n));
  });

  test("stores words on different pages", async () => {
    const trie = await createPageTrie();

    await trie.put(uint256(127n), uint256(1n));
    await trie.put(uint256(128n), uint256(2n));

    expect(await trie.get(uint256(127n))).toEqual(uint256(1n));
    expect(await trie.get(uint256(128n))).toEqual(uint256(2n));
  });

  test("copies mutation inputs before asynchronous work", async () => {
    const trie = await createPageTrie();
    const key = uint256(5n);
    const originalKey = key.slice();
    const value = uint256(55n);
    const originalValue = value.slice();

    const write = trie.put(key, value);
    key.fill(0xff);
    value.fill(0xff);
    await write;

    expect(await trie.get(originalKey)).toEqual(originalValue);
  });

  test("returns defensive value copies", async () => {
    const trie = await createPageTrie();
    const key = uint256(6n);
    const value = uint256(66n);
    await trie.put(key, value);

    const returned = await trie.get(key);
    returned?.fill(0xff);

    expect(await trie.get(key)).toEqual(value);
  });

  test("reads wait for previously submitted writes", async () => {
    const trie = await createPageTrie();
    const key = uint256(8n);
    const value = uint256(88n);

    const write = trie.put(key, value);
    const read = trie.get(key);

    expect(await read).toEqual(value);
    await write;
  });

  test("serializes concurrent writes in submission order", async () => {
    const trie = await createPageTrie();
    const key = uint256(9n);

    await Promise.all([
      trie.put(key, uint256(1n)),
      trie.put(uint256(128n), uint256(2n)),
      trie.put(key, uint256(3n)),
    ]);

    expect(await trie.get(key)).toEqual(uint256(3n));
    expect(await trie.get(uint256(128n))).toEqual(uint256(2n));
  });
});

describe("PageTrie batches", () => {
  test("applies duplicate operations in order", async () => {
    const trie = await createPageTrie();
    const key = uint256(10n);

    await trie.batch([
      { type: "put", key, value: uint256(1n) },
      { type: "del", key },
      { type: "put", key, value: uint256(2n) },
    ]);

    expect(await trie.get(key)).toEqual(uint256(2n));
  });

  test("treats an empty batch as a no-op", async () => {
    const trie = await createPageTrie();
    const before = trie.root();

    await trie.batch([]);

    expect(trie.root()).toEqual(before);
  });

  test("copies all batch inputs before queuing", async () => {
    const trie = await createPageTrie();
    const key = uint256(11n);
    const originalKey = key.slice();
    const value = uint256(111n);
    const originalValue = value.slice();
    const operations = [{ type: "put" as const, key, value }];

    const write = trie.batch(operations);
    key.fill(0xff);
    value.fill(0xff);
    operations.splice(0);
    await write;

    expect(await trie.get(originalKey)).toEqual(originalValue);
  });

  test("validates the whole batch before changing state", async () => {
    const trie = await createPageTrie();
    const before = trie.root();

    await expect(
      trie.batch([
        { type: "put", key: uint256(0n), value: uint256(1n) },
        { type: "put", key: uint256(1n), value: new Uint8Array(31) },
      ]),
    ).rejects.toThrow(RangeError);

    expect(trie.root()).toEqual(before);
    expect(await trie.get(uint256(0n))).toBeNull();
  });

  test("updates each affected page leaf once", async () => {
    const mpt = await createInternalMpt();
    const delegate = delegateMpt(mpt);
    let puts = 0;
    const counting: Mpt = {
      ...delegate,
      put: async (key, value) => {
        puts++;
        await delegate.put(key, value);
      },
    };
    const trie = new MemoryPageTrie(counting);

    await trie.batch([
      { type: "put", key: uint256(0n), value: uint256(1n) },
      { type: "put", key: uint256(1n), value: uint256(2n) },
      { type: "put", key: uint256(127n), value: uint256(3n) },
      { type: "put", key: uint256(128n), value: uint256(4n) },
    ]);

    expect(puts).toBe(2);
  });

  test("rolls back the MPT and pages after an internal failure", async () => {
    const mpt = await createInternalMpt();
    const delegate = delegateMpt(mpt);
    let puts = 0;
    const failing: Mpt = {
      ...delegate,
      put: async (key, value) => {
        puts++;
        if (puts === 2) throw new Error("injected MPT failure");
        await delegate.put(key, value);
      },
    };
    const trie = new MemoryPageTrie(failing);

    await expect(
      trie.batch([
        { type: "put", key: uint256(0n), value: uint256(1n) },
        { type: "put", key: uint256(128n), value: uint256(2n) },
      ]),
    ).rejects.toThrow("injected MPT failure");

    expect(bytesToHex(trie.root())).toBe(EMPTY_MPT_ROOT);
    expect(bytesToHex(mpt.root())).toBe(EMPTY_MPT_ROOT);
    expect(await trie.get(uint256(0n))).toBeNull();
    expect(await trie.get(uint256(128n))).toBeNull();

    await trie.put(uint256(256n), uint256(3n));
    expect(await trie.get(uint256(256n))).toEqual(uint256(3n));
  });
});

describe("MIP-8 MPT encoding", () => {
  test("stores RLP-wrapped commitments under unhashed page keys", async () => {
    const mpt = await createInternalMpt();
    const trie = new MemoryPageTrie(delegateMpt(mpt));
    const key = uint256(0n);
    const value = uint256(1n);
    const page = new Uint8Array(PAGE_SIZE);
    page.set(value);

    await trie.put(key, value);

    const stored = await mpt.get(computePageKey(key));
    const expected = new Uint8Array(33);
    expected[0] = 0xa0;
    expected.set(pageCommit(page), 1);
    expect(stored).toEqual(expected);
  });
});

describe("PageTrie validation", () => {
  test("rejects invalid keys and values", async () => {
    const trie = await createPageTrie();

    await expect(trie.get([] as unknown as Uint8Array)).rejects.toThrow(
      TypeError,
    );
    await expect(trie.get(new Uint8Array(31))).rejects.toThrow(RangeError);
    await expect(trie.del(new Uint8Array(33))).rejects.toThrow(RangeError);
    await expect(
      trie.put(uint256(0n), [] as unknown as Uint8Array),
    ).rejects.toThrow(TypeError);
    await expect(trie.put(uint256(0n), new Uint8Array(31))).rejects.toThrow(
      RangeError,
    );
  });

  test("rejects batches with malformed byte arrays", async () => {
    const trie = await createPageTrie();
    const sparseOperations = new Array<PageTrieBatchOperation>(1);

    await expect(trie.batch(sparseOperations)).rejects.toThrow(TypeError);
    await expect(
      trie.batch([null as unknown as { type: "del"; key: Uint8Array }]),
    ).rejects.toThrow(TypeError);
    await expect(
      trie.batch([{ type: "put", key: uint256(0n) } as never]),
    ).rejects.toThrow("operations[0].value must be a Uint8Array");
  });
});
