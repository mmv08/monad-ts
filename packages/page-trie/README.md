# @monad-crypto/page-trie

A minimal, in-memory implementation of one contract's [MIP-8](https://github.com/monad-crypto/MIPs/blob/6e78a6ac39547882f9905fba86d2c794eb1768ef/MIPs/MIP-8.md) storage page trie.

> **Warning:** This package is experimental and has not been audited. It implements consensus-critical hashing and should be independently verified before production use.

## Install

```bash
bun add @monad-crypto/page-trie
```

Node.js 20.19 or newer is required.

## Usage

```ts
import { createPageTrie } from "@monad-crypto/page-trie"

const trie = await createPageTrie()
const slot = new Uint8Array(32)
const value = new Uint8Array(32)
value[31] = 1

await trie.put(slot, value)

const stored = await trie.get(slot)
const root = trie.root()

await trie.del(slot)
```

All slot keys and values are exactly 32 bytes. `get()` returns `null` for an absent or zero slot, and writing a zero word is equivalent to deleting it. Inputs and returned byte arrays are defensively copied.

Mutations are serialized in submission order. A batch is validated before it is queued, applies duplicate slots in order, and commits atomically:

```ts
await trie.batch([
  { type: "put", key: firstSlot, value: firstValue },
  { type: "del", key: secondSlot },
])
```

## Page primitives

```ts
import {
  PAGE_SIZE,
  PAGE_SLOTS,
  SLOT_SIZE,
  computePageKey,
  computeSlotOffset,
  pageCommit,
} from "@monad-crypto/page-trie"
```

- `computePageKey(slot)` computes the 256-bit big-endian `slot >> 7`.
- `computeSlotOffset(slot)` computes `slot & 0x7f`.
- `pageCommit(page)` computes the MIP-8 ISMC commitment for one dense 4096-byte page.
- `SLOT_SIZE`, `PAGE_SLOTS`, and `PAGE_SIZE` are `32`, `128`, and `4096`.

Invalid byte-array types throw `TypeError`; invalid lengths throw `RangeError`.

## Scope

This first version models one contract's storage trie in memory. It does not provide persistence, root restoration, checkpoints, proofs, world-state composition, iteration, pruning, or gas accounting.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for consensus-critical invariants and security boundaries.

## License

MIT
