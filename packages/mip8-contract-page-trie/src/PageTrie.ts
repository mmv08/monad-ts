import { keccak_256 } from "@noble/hashes/sha3.js";

import {
  abytes,
  bytesToHex,
  concatBytes,
  copyBytes,
  equalBytesAt,
  hexToBytes,
  isZero,
} from "./bytes.js";
import { mptRoot } from "./mpt.js";
import {
  computePageCommitment,
  computePageLocation,
  PAGE_SIZE,
  SLOT_SIZE,
} from "./page.js";

const RLP_STRING_32_PREFIX = Uint8Array.of(0xa0);
const ZERO_SLOT = new Uint8Array(SLOT_SIZE);

interface PageTrie {
  /** Returns a defensive copy of a slot value, or `null` for a zero or absent slot. */
  get(slot: Uint8Array): Uint8Array | null;
  /** Writes a slot value. A zero value deletes the slot. */
  set(slot: Uint8Array, value: Uint8Array): void;
  /** Deletes a slot. */
  delete(slot: Uint8Array): void;
  /** Returns a defensive copy of the root for the current stored state. */
  root(): Uint8Array;
}

class MemoryPageTrie implements PageTrie {
  readonly #pages: Map<string, Uint8Array>;
  #cachedRoot: Uint8Array | undefined;

  // Explicit: Bun counts an implicit constructor as an uncovered function,
  // which breaks the 100% coverage threshold.
  constructor() {
    this.#pages = new Map();
  }

  get(slot: Uint8Array): Uint8Array | null {
    const { pageKey, offset } = computePageLocation(slot);
    const page = this.#pages.get(bytesToHex(pageKey));
    if (!page) return null;

    const start = offset * SLOT_SIZE;
    if (isZero(page, start, SLOT_SIZE)) return null;
    return copyBytes(page.subarray(start, start + SLOT_SIZE));
  }

  set(slot: Uint8Array, value: Uint8Array): void {
    abytes(value, SLOT_SIZE, "value");

    const { pageKey, offset } = computePageLocation(slot);
    const mapKey = bytesToHex(pageKey);
    const start = offset * SLOT_SIZE;
    let page = this.#pages.get(mapKey);

    if (isZero(value)) {
      if (!page || isZero(page, start, SLOT_SIZE)) return;
      page.fill(0, start, start + SLOT_SIZE);
      if (isZero(page)) this.#pages.delete(mapKey);
    } else {
      if (page && equalBytesAt(page, start, value)) return;
      if (!page) {
        page = new Uint8Array(PAGE_SIZE);
        this.#pages.set(mapKey, page);
      }
      page.set(value, start);
    }

    this.#cachedRoot = undefined;
  }

  delete(slot: Uint8Array): void {
    this.set(slot, ZERO_SLOT);
  }

  root(): Uint8Array {
    if (!this.#cachedRoot) {
      const leaves: [Uint8Array, Uint8Array][] = [];
      for (const [mapKey, page] of this.#pages) {
        leaves.push([
          keccak_256(hexToBytes(mapKey)),
          concatBytes(RLP_STRING_32_PREFIX, computePageCommitment(page)),
        ]);
      }
      this.#cachedRoot = mptRoot(leaves);
    }
    return copyBytes(this.#cachedRoot);
  }
}

/** Creates a new empty in-memory page trie for one contract's storage. */
function createPageTrie(): PageTrie {
  return new MemoryPageTrie();
}

export { createPageTrie };
export type { PageTrie };
