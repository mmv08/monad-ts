import { createMPT } from "@ethereumjs/mpt";

import {
  assertBytes,
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

function bytesToMapKey(bytes: Uint8Array): string {
  let key = "";
  for (const byte of bytes) key += byte.toString(16).padStart(2, "0");
  return key;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function copyKey(value: unknown, name: string): Uint8Array {
  assertBytes(value, SLOT_SIZE, name);
  return Uint8Array.from(value);
}

function copyOperation(
  operation: unknown,
  index: number,
): PageTrieBatchOperation {
  if (typeof operation !== "object" || operation === null) {
    throw new TypeError(`operations[${index}] must be an object`);
  }

  const candidate = operation as {
    type?: unknown;
    key?: unknown;
    value?: unknown;
  };
  const key = copyKey(candidate.key, `operations[${index}].key`);
  if (candidate.type === "del") return { type: "del", key };
  if (candidate.type === "put") {
    assertBytes(candidate.value, SLOT_SIZE, `operations[${index}].value`);
    return { type: "put", key, value: Uint8Array.from(candidate.value) };
  }
  throw new TypeError(`operations[${index}].type must be "put" or "del"`);
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
    const copiedKey = copyKey(key, "key");
    const pendingWrites = this.#writeQueue;
    await pendingWrites;

    const pageKey = computePageKey(copiedKey);
    const page = this.#pages.get(bytesToMapKey(pageKey));
    if (!page) return null;

    const start = computeSlotOffset(copiedKey) * SLOT_SIZE;
    if (isZero(page, start, SLOT_SIZE)) return null;
    return page.slice(start, start + SLOT_SIZE);
  }

  async put(key: Uint8Array, value: Uint8Array): Promise<void> {
    const copiedKey = copyKey(key, "key");
    assertBytes(value, SLOT_SIZE, "value");
    const copiedValue = Uint8Array.from(value);
    await this.#enqueue(() =>
      this.#apply([{ type: "put", key: copiedKey, value: copiedValue }]),
    );
  }

  async del(key: Uint8Array): Promise<void> {
    const copiedKey = copyKey(key, "key");
    await this.#enqueue(() => this.#apply([{ type: "del", key: copiedKey }]));
  }

  async batch(operations: readonly PageTrieBatchOperation[]): Promise<void> {
    if (!Array.isArray(operations)) {
      throw new TypeError("operations must be an array");
    }
    const copiedOperations = operations.map(copyOperation);
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
      const mapKey = bytesToMapKey(pageKey);
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
    changes.sort((left, right) =>
      left.mapKey < right.mapKey ? -1 : left.mapKey > right.mapKey ? 1 : 0,
    );

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
    useNodePruning: false,
    useRootPersistence: false,
  });
  return new MemoryPageTrie(trie);
}
