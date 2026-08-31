# Floor-design proof of concept

This is the smallest MIP-8 page trie we could build: a map of dense pages,
and a `root()` that folds every page into a fresh MPT on demand. It exists
to test the claim that the shipped `MemoryPageTrie` is the simplest design
that meets the requirements. It is not exported from the package and is not
published.

## What it proves

- [FloorPageTrie.ts](./FloorPageTrie.ts) produces byte-identical roots: it
  passes the same root fixtures as `MemoryPageTrie` and matches it on a
  200-operation deterministic differential run.
- Rebuilding on demand deletes all four insurance layers at once. Mutations
  become synchronous map writes, so there is no write queue, no checkpoint
  or rollback, no no-op filter, and no async window that defensive input
  copies would guard.

## What it loses

`root()` rebuilds the whole MPT, so its cost grows with total state while
the incremental design pays only for the touched page (`bun poc/bench.ts`,
median of 5 runs on this machine):

| pages | floor write+root | incremental write+root |
| ----: | ---------------: | ---------------------: |
|    16 |          3.40 ms |                0.13 ms |
|    64 |          4.85 ms |                0.11 ms |
|   256 |         11.72 ms |                0.06 ms |
|  1024 |         39.42 ms |                0.06 ms |

It also changes the contract: `root()` becomes async, and a batch is no
longer validated up front, so an invalid operation mid-batch leaves earlier
operations applied.

## Verdict

The floor design is fine for tiny state and throwaway tests. Once roots are
needed per block over growing state, linear-cost roots are unacceptable, and
meeting that requirement forces the incremental design — with the queue,
checkpointing, and staging that make it safe.
