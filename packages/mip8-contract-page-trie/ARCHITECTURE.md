# Architecture — Security Review Guide

This document describes the security and consensus boundaries of `@monad-crypto/mip8-contract-page-trie`. Usage is documented in [README.md](./README.md).

## 1. Scope

The package implements the in-memory MIP-8 storage trie for one contract:

- 32-byte storage slots are grouped into dense 4096-byte pages.
- Each non-empty page is committed with MIP-8 ISMC.
- Page commitments are folded into a secure Ethereum Merkle Patricia Trie (MPT) when a root is requested.
- The package exposes reads, writes, deletion, roots, and page primitives.

There is no persistence or API for restoring from an existing root. A new trie is always empty. Proofs, public checkpoints, world-state composition, iteration, pruning, gas accounting, and production or high-performance use are outside this package's security scope.

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
| MPT key | Unhashed 32-byte page key; the MPT keccak-hashes the key before traversal |
| MPT value | `0xa0 || computePageCommitment(page)`; the MPT then applies its normal outer RLP encoding |
| Empty root | `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421` |

Changing any item in this table changes roots or storage semantics and requires new conformance fixtures and an architecture review.

## 3. ISMC Page Commitment

`src/page.ts` implements the induced-tree algorithm in the pinned [Final MIP-8 specification](https://github.com/monad-crypto/MIPs/blob/6e78a6ac39547882f9905fba86d2c794eb1768ef/MIPs/MIP-8.md):

1. Build a 128-bit bitmap where bit `i` marks a non-zero slot.
2. Hash every active 64-byte slot pair with the specialized bare BLAKE3 leaf compression.
3. Merge active nodes bottom-up with the specialized bare BLAKE3 parent compression. Singleton nodes carry upward unchanged.
4. Seal the little-endian 16-byte bitmap and optional 32-byte induced-tree root with full BLAKE3 from `@noble/hashes`.

The empty-page commitment is the full BLAKE3 hash of a zero 16-byte bitmap. It is a valid result from `computePageCommitment()`, but `PageTrie` deletes rather than inserts an empty page.

`src/ismcHash.ts` isolates the specialized compression adapter. It fixes the BLAKE3 counter to zero, validates the 32-byte chaining value and 64-byte block, fixes the block length at 64 bytes, and applies the flags exactly as specified. The adapter assembles that state and delegates only the seven standard ARX rounds to `@noble/hashes`' exported BLAKE compression core. Noble exposes this shared BLAKE2/BLAKE3 core from `blake2.js`; this package does not use the BLAKE2 hash function. The compression must not be replaced by a general-purpose BLAKE3 hash call.

## 4. MPT Composition

`src/mpt.ts` is a minimal Ethereum MPT builder. It hashes a complete set of leaves into a root. It does not get, delete, prove, persist, or incrementally update nodes.

For every uncached `root()` call, `src/PageTrie.ts` keccak-hashes each page key and passes `(keccak(pageKey), 0xa0 || commitment)` leaves to `mptRoot`. “Secure MPT” means that Keccak hashes the key before trie traversal. It is not an audit claim. `mptRoot` itself does not hash keys.

The stored raw value begins with the RLP short-string prefix `0xa0`, followed by the 32-byte page commitment. The MPT then RLP-encodes that 33-byte value as part of the leaf. The prefix is encoding rather than domain separation, and removing it changes every non-empty root.

A node is replaced by `keccak(RLP(node))` when it is the trie root or when its RLP encoding is at least 32 bytes. Shorter non-root nodes are inlined into the parent. MIP-8's 33-byte values never inline; inlining is required for Ethereum TrieTests with short values and must be preserved.

Hex-prefix (compact) nibble encoding follows the Ethereum Yellow Paper: a terminator flag distinguishes leaf from extension, and an odd-length nibble path packs the first nibble into the flag byte.

## 5. State and Root Model

The private dense-page map is the only long-lived state. The public storage behavior is documented in [README.md](./README.md).

`root()` is synchronous. It rebuilds the MPT from the current non-empty pages, copies the result, and caches that copy until the next state-changing mutation. Rewriting a slot with its current value, or deleting an already-zero slot, is a no-op and leaves the cache valid.

An uncached root rebuild scales with the total number of non-empty pages. Repeated root reads without a mutation use the cache. This tradeoff intentionally favors a small, auditable correctness implementation over incremental-update performance.

## 6. Input and Memory Boundaries

- Public slot keys and values must be `Uint8Array` instances of exactly 32 bytes.
- `computePageCommitment()` accepts only a 4096-byte `Uint8Array`.
- Type violations throw `TypeError`; size violations throw `RangeError`.
- Byte-array instances and exact lengths are validated at each public operation boundary by `@noble/hashes`' byte assertion.
- Slot keys are reduced to page keys synchronously, and values are copied into private dense pages, so later mutation of caller-owned inputs cannot change stored state.
- Values returned by `get()` and `root()` are copies.
- Dense pages and the page map are private. Root construction reads those private pages synchronously.

The package uses no filesystem, environment variables, network access, Node.js buffers, secrets, or dynamic code execution.

## 7. Dependencies

| Dependency | Version | Purpose |
| --- | --- | --- |
| `@noble/hashes` | `2.2.0` | BLAKE compression rounds, full BLAKE3 seals, keccak for the MPT, and byte utilities |

The version is an exact pin. Dependency upgrades require rerunning all commitment, root, and official TrieTests fixtures, and an audit.

## 8. Source and Conformance Boundary

The MIP-specific implementation is derived from the CC0 MIP and the official BLAKE3 specification. The standard ARX rounds, keccak, and byte utilities come from the exact-pinned MIT-licensed `@noble/hashes`; no GPL implementation code is included. Tests mirror all four fixed-output vectors published by the official client's pinned [Python reference](https://github.com/category-labs/monad/blob/68d444b6937592d43db1013161a6c2b7b3f55be5/scripts/page_commit_reference.py) and [C++ cross-check](https://github.com/category-labs/monad/blob/68d444b6937592d43db1013161a6c2b7b3f55be5/category/execution/monad/db/test_storage_page.cpp). Additional sparse merge-schedule outputs and five deterministic pseudorandom page commitments were generated from the same pinned Python reference.

Root fixtures additionally cover the standard empty MPT root and fixed single-page and multi-page MPT roots, including whole-page deletion and branch collapse. Their page commitments are cross-checked against the pinned [Python reference](https://github.com/category-labs/monad/blob/68d444b6937592d43db1013161a6c2b7b3f55be5/scripts/page_commit_reference.py), and their MPT composition follows the pinned [MIP-8 specification](https://github.com/monad-crypto/MIPs/blob/6e78a6ac39547882f9905fba86d2c794eb1768ef/MIPs/MIP-8.md). These fixtures detect changes to page grouping, secure-key hashing, the explicit value prefix, or outer MPT RLP encoding.

MPT encoding is further checked against the official Ethereum [TrieTests](https://github.com/ethereum/tests/tree/c67e485ff8b5be9abc8ad15345ec21aa22e290d9/TrieTests), including hashed and unhashed suites and sequential inserts that delete keys. Sequential files are folded into a map (`null` deletes) before hashing so the builder can remain insert-all.

## 9. Review Checklist

Before changing consensus-sensitive code:

- Confirm the pinned MIP revision and BLAKE3 constants, flags, word endianness, and message schedule.
- Preserve the exact-pinned Noble compression-core boundary and rerun every conformance fixture after dependency changes.
- Preserve big-endian slot grouping and little-endian bitmap sealing.
- Preserve induced-tree singleton carrying.
- Preserve secure MPT key hashing, hex-prefix encoding, the 32-byte inline threshold, and `0xa0` value prefixing.
- Keep empty pages out of the MPT.
- Cache a completed root only until the next state-changing mutation.
- Run package tests, typecheck, build, coverage, Biome, and dependency audit.
