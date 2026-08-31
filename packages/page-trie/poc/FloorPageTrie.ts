import { createMPT } from "@ethereumjs/mpt";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import {
  assertBytes,
  computePageKey,
  computeSlotOffset,
  isZero,
  PAGE_SIZE,
  pageCommit,
  SLOT_SIZE,
} from "../src/page.js";

export type FloorBatchOperation =
  | { type: "put"; key: Uint8Array; value: Uint8Array }
  | { type: "del"; key: Uint8Array };

/**
 * Rebuild-on-demand MIP-8 page trie: the floor-design proof of concept.
 *
 * Mutations are synchronous map writes; `root()` folds every page into a
 * fresh MPT, so its cost grows with total state. For comparison with the
 * incremental `MemoryPageTrie` only — not exported from the package.
 */
export class FloorPageTrie {
  readonly #pages = new Map<string, Uint8Array>();

  get(key: Uint8Array): Uint8Array | null {
    assertBytes(key, SLOT_SIZE, "key");
    const page = this.#pages.get(bytesToHex(computePageKey(key)));
    if (!page) return null;
    const start = computeSlotOffset(key) * SLOT_SIZE;
    if (isZero(page, start, SLOT_SIZE)) return null;
    return page.slice(start, start + SLOT_SIZE);
  }

  put(key: Uint8Array, value: Uint8Array): void {
    assertBytes(key, SLOT_SIZE, "key");
    assertBytes(value, SLOT_SIZE, "value");
    const mapKey = bytesToHex(computePageKey(key));
    let page = this.#pages.get(mapKey);
    if (!page) {
      page = new Uint8Array(PAGE_SIZE);
      this.#pages.set(mapKey, page);
    }
    page.set(value, computeSlotOffset(key) * SLOT_SIZE);
    if (isZero(page)) this.#pages.delete(mapKey);
  }

  del(key: Uint8Array): void {
    this.put(key, new Uint8Array(SLOT_SIZE));
  }

  /** Applies operations in order; each is validated as it is applied. */
  batch(operations: readonly FloorBatchOperation[]): void {
    for (const operation of operations) {
      if (operation.type === "del") this.del(operation.key);
      else this.put(operation.key, operation.value);
    }
  }

  async root(): Promise<Uint8Array> {
    const mpt = await createMPT({
      cacheSize: 0,
      useKeyHashing: true,
      useRootPersistence: false,
    });
    for (const [mapKey, page] of this.#pages) {
      const value = new Uint8Array(SLOT_SIZE + 1);
      value[0] = 0xa0; // RLP short-string prefix for 32 bytes
      value.set(pageCommit(page), 1);
      await mpt.put(hexToBytes(mapKey), value);
    }
    return mpt.root();
  }
}
