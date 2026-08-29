# Architecture — Security Review Guide

This document describes the security and consensus boundaries of `@monad-crypto/page-trie`. Usage is documented in [README.md](./README.md).

## 1. Scope

The package implements the in-memory MIP-8 storage trie for one contract:

- 32-byte storage slots are grouped into dense 4096-byte pages.
- Each non-empty page is committed with MIP-8 ISMC.
- Page commitments are stored in a secure Ethereum Merkle Patricia Trie (MPT).
- The package exposes reads, writes, deletion, atomic batches, roots, and page primitives.

There is no persistence or API for restoring from an existing root. A new trie is always empty. Proofs, public checkpoints, world-state composition, iteration, pruning, and gas accounting are outside this package's security scope.

## 2. Consensus-Critical Invariants

| Invariant | Definition |
| --- | --- |
| Slot size | 32 bytes |
| Slots per page | 128 |
| Dense page size | 4096 bytes |
| Page key | 256-bit big-endian `slot >> 7` |
| Slot offset | `slot & 0x7f` |
| Empty slots | All-zero 32-byte words |
| Empty pages | Never inserted into the MPT |
| MPT key | Unhashed 32-byte page key passed to an MPT configured with secure key hashing |
| MPT value | `0xa0 || pageCommit(page)`; the MPT then applies its normal outer RLP encoding |
| Empty root | `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421` |

Changing any item in this table changes roots or storage semantics and requires new conformance fixtures and an architecture review.

## 3. ISMC Page Commitment

`src/page.ts` is a clean-room implementation of the algorithm in the pinned [Final MIP-8 specification](https://github.com/monad-crypto/MIPs/blob/6e78a6ac39547882f9905fba86d2c794eb1768ef/MIPs/MIP-8.md):

1. Build a 128-bit bitmap where bit `i` marks a non-zero slot.
2. Hash every active 64-byte slot pair with the specialized bare BLAKE3 leaf compression.
3. Merge active nodes bottom-up with the specialized bare BLAKE3 parent compression. Singleton nodes carry upward unchanged.
4. Seal the little-endian 16-byte bitmap and optional 32-byte induced-tree root with full BLAKE3 from `@noble/hashes`.

The empty-page commitment is the full BLAKE3 hash of a zero 16-byte bitmap. It is a valid result from `pageCommit()`, but `PageTrie` deletes rather than inserts an empty page.

The specialized compression fixes the BLAKE3 counter to zero, the block length to 64, and the flags exactly as specified. It must not be replaced by a general-purpose BLAKE3 hash call.

## 4. MPT Composition

`src/PageTrie.ts` creates `@ethereumjs/mpt` with:

- `useKeyHashing: true`
- `cacheSize: 0`
- root persistence disabled
- node pruning left at the `@ethereumjs/mpt` default

The page key is passed to the MPT before hashing. The stored raw value begins with the RLP short-string prefix `0xa0`, followed by the 32-byte page commitment. EthereumJS then RLP-encodes that 33-byte value as part of the MPT leaf. Removing the explicit `0xa0` changes every non-empty root.

## 5. Mutation and Rollback Model

Mutations share one promise queue, so writes and batches execute in submission order. Reads capture the queue at call time and wait for all mutations submitted before them. `root()` is synchronous and returns the most recently committed root.

A batch is handled as follows:

1. Validate and copy every operation before it enters the queue.
2. Apply operations in order to private copies of affected pages.
3. Collapse changes by page and update each affected MPT leaf once.
4. Run the MPT updates inside an internal checkpoint.
5. Commit the MPT checkpoint, then publish staged pages and the new root.
6. On failure, revert the checkpoint and leave published pages and root unchanged.

Caching is disabled because rollback correctness relies on the MPT checkpoint being the only mutable staging layer.

## 6. Input and Memory Boundaries

- Public slot keys and values must be `Uint8Array` instances of exactly 32 bytes.
- `pageCommit()` accepts only a 4096-byte `Uint8Array`.
- Type violations throw `TypeError`; size violations throw `RangeError`.
- Batch structure is enforced by the TypeScript types. An exhaustive runtime switch rejects unsupported operation tags, while byte-array instances and exact lengths are validated before queuing.
- Mutation inputs are copied before asynchronous work is queued.
- Values returned by `get()` and `root()` are copies.
- Dense pages and the page map are private and are published only after a successful MPT commit.

The package uses no filesystem, environment variables, network access, Node.js buffers, secrets, or dynamic code execution.

## 7. Dependencies

| Dependency | Version | Purpose |
| --- | --- | --- |
| `@ethereumjs/mpt` | `10.1.2` | Secure in-memory Merkle Patricia Trie |
| `@noble/hashes` | `2.2.0` | Final full BLAKE3 seal hash |

Both versions are exact pins. Dependency upgrades require rerunning all commitment and root fixtures, rollback tests, audit, and package-content checks.

## 8. Source and Conformance Boundary

The implementation is derived from the CC0 MIP and the official BLAKE3 specification. No GPL implementation code is included. Tests mirror all four fixed-output vectors published by the official client's pinned [Python reference](https://github.com/category-labs/monad/blob/68d444b6937592d43db1013161a6c2b7b3f55be5/scripts/page_commit_reference.py) and [C++ cross-check](https://github.com/category-labs/monad/blob/68d444b6937592d43db1013161a6c2b7b3f55be5/category/execution/monad/db/test_storage_page.cpp). Additional merge-schedule outputs were generated from the same pinned Python reference.

Root fixtures additionally cover the standard empty MPT root and independently composed single-page and multi-page MPT roots, including whole-page deletion and branch collapse. These detect changes to page grouping, secure-key hashing, the explicit value prefix, or outer MPT RLP encoding.

## 9. Review Checklist

Before changing consensus-sensitive code:

- Confirm the pinned MIP revision and BLAKE3 constants, flags, word endianness, and message schedule.
- Preserve big-endian slot grouping and little-endian bitmap sealing.
- Preserve induced-tree singleton carrying.
- Preserve secure MPT key hashing and `0xa0` value prefixing.
- Keep empty pages out of the MPT.
- Verify validation happens before queuing and page publication happens after commit.
- Run package tests, typecheck, build, coverage, Biome, dependency audit, and package dry-run.
