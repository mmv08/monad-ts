import { createMPT } from "@ethereumjs/mpt";

import {
  assertBytes,
  bytesToHex,
  computePageKey,
  computeSlotOffset,
  isZero,
  PAGE_SIZE,
  pageCommit,
  SLOT_SIZE,
} from "./page.js";

const RLP_STRING_32_PREFIX = 0xa0;

export type PageTrieBatchOperation =
  | { type: "put"; key: Uint8Array; value: Uint8Array }
  | { type: "del"; key: Uint8Array };

export interface PageTrie {
  /** Returns a defensive copy of a slot value, or `null` for a zero or absent slot. */
  get(key: Uint8Array): Promise<Uint8Array | null>;
  /** Writes a slot value. A zero value deletes the slot. */
  put(key: Uint8Array, value: Uint8Array): Promise<void>;
  /** Deletes a slot. */
  del(key: Uint8Array): Promise<void>;
  /** Validates and atomically applies operations in array order. */
  batch(operations: readonly PageTrieBatchOperation[]): Promise<void>;
  /** Returns a defensive copy of the latest committed MPT root. */
  root(): Uint8Array;
}

/** @internal */
export interface Mpt {
  root(): Uint8Array;
  put(key: Uint8Array, value: Uint8Array): Promise<void>;
  del(key: Uint8Array): Promise<void>;
  checkpoint(): void;
  commit(): Promise<void>;
  revert(): Promise<void>;
  hasCheckpoints(): boolean;
}

type StagedPage = {
  key: Uint8Array;
  page: Uint8Array;
};

type PageChange = StagedPage & {
  mapKey: string;
  empty: boolean;
};

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function assertNever(_: never, message: string): never {
  throw new TypeError(message);
}

function copyOperation(
  operation: PageTrieBatchOperation,
  index: number,
): PageTrieBatchOperation {
  assertBytes(operation.key, SLOT_SIZE, `operations[${index}].key`);
  const key = Uint8Array.from(operation.key);

  switch (operation.type) {
    case "del":
      return { type: "del", key };
    case "put":
      assertBytes(operation.value, SLOT_SIZE, `operations[${index}].value`);
      return { type: "put", key, value: Uint8Array.from(operation.value) };
    default:
      return assertNever(
        operation,
        `operations[${index}].type must be "put" or "del"`,
      );
  }
}

function toMptValue(commitment: Uint8Array): Uint8Array {
  const value = new Uint8Array(SLOT_SIZE + 1);
  value[0] = RLP_STRING_32_PREFIX;
  value.set(commitment, 1);
  return value;
}

/** @internal */
export class MemoryPageTrie implements PageTrie {
  readonly #trie: Mpt;
  readonly #pages = new Map<string, Uint8Array>();
  #committedRoot: Uint8Array;
  #writeQueue: Promise<void> = Promise.resolve();

  constructor(trie: Mpt) {
    this.#trie = trie;
    this.#committedRoot = Uint8Array.from(trie.root());
  }

  async get(key: Uint8Array): Promise<Uint8Array | null> {
    const pageKey = computePageKey(key);
    const start = computeSlotOffset(key) * SLOT_SIZE;
    await this.#writeQueue;

    const page = this.#pages.get(bytesToHex(pageKey));
    if (!page) return null;
    if (isZero(page, start, SLOT_SIZE)) return null;
    return page.slice(start, start + SLOT_SIZE);
  }

  async put(key: Uint8Array, value: Uint8Array): Promise<void> {
    await this.batch([{ type: "put", key, value }]);
  }

  async del(key: Uint8Array): Promise<void> {
    await this.batch([{ type: "del", key }]);
  }

  async batch(operations: readonly PageTrieBatchOperation[]): Promise<void> {
    const copiedOperations: PageTrieBatchOperation[] = [];
    for (let index = 0; index < operations.length; index++) {
      copiedOperations.push(copyOperation(operations[index], index));
    }
    await this.#enqueue(() => this.#apply(copiedOperations));
  }

  root(): Uint8Array {
    return Uint8Array.from(this.#committedRoot);
  }

  #enqueue(mutation: () => Promise<void>): Promise<void> {
    const result = this.#writeQueue.then(mutation);
    this.#writeQueue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async #apply(operations: readonly PageTrieBatchOperation[]): Promise<void> {
    if (operations.length === 0) return;

    const stagedPages = new Map<string, StagedPage>();
    for (const operation of operations) {
      const pageKey = computePageKey(operation.key);
      const mapKey = bytesToHex(pageKey);
      let staged = stagedPages.get(mapKey);
      if (!staged) {
        staged = {
          key: pageKey,
          page: this.#pages.get(mapKey)?.slice() ?? new Uint8Array(PAGE_SIZE),
        };
        stagedPages.set(mapKey, staged);
      }

      const start = computeSlotOffset(operation.key) * SLOT_SIZE;
      if (operation.type === "del" || isZero(operation.value)) {
        staged.page.fill(0, start, start + SLOT_SIZE);
      } else {
        staged.page.set(operation.value, start);
      }
    }

    const changes: PageChange[] = [];
    for (const [mapKey, staged] of stagedPages) {
      const current = this.#pages.get(mapKey);
      const empty = isZero(staged.page);
      if (
        (current === undefined && empty) ||
        (current && equalBytes(current, staged.page))
      ) {
        continue;
      }
      changes.push({ ...staged, mapKey, empty });
    }
    if (changes.length === 0) return;

    this.#trie.checkpoint();
    try {
      for (const change of changes) {
        if (change.empty) {
          await this.#trie.del(change.key);
        } else {
          await this.#trie.put(change.key, toMptValue(pageCommit(change.page)));
        }
      }
      await this.#trie.commit();
    } catch (error) {
      if (this.#trie.hasCheckpoints()) await this.#trie.revert();
      throw error;
    }

    for (const change of changes) {
      if (change.empty) this.#pages.delete(change.mapKey);
      else this.#pages.set(change.mapKey, change.page);
    }
    this.#committedRoot = Uint8Array.from(this.#trie.root());
  }
}

/** Creates a new empty in-memory page trie for one contract's storage. */
export async function createPageTrie(): Promise<PageTrie> {
  const trie = await createMPT({
    cacheSize: 0,
    useKeyHashing: true,
    useRootPersistence: false,
  });
  return new MemoryPageTrie(trie);
}
