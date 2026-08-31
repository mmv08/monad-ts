import { bytesToHex } from "@noble/hashes/utils.js";

import { createPageTrie, type PageTrieBatchOperation } from "../src/index.js";
import { uint256 } from "../testing/utils.js";
import { FloorPageTrie } from "./FloorPageTrie.js";

// Measures the cost of one slot write followed by a fresh root, after the
// trie already holds N pages. The floor design rebuilds the whole MPT in
// root(), so this cost grows with N; the incremental design pays only for
// the touched page.

const PAGE_COUNTS = [16, 64, 256, 1024];
const RUNS = 5;

function median(samples: number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function preloadEntries(pages: number): PageTrieBatchOperation[] {
  return Array.from({ length: pages }, (_, i) => ({
    type: "put",
    key: uint256(BigInt(i) * 128n),
    value: uint256(BigInt(i) + 1n),
  }));
}

console.log("write+root cost after preloading N pages (median of 5 runs)\n");
console.log("pages | floor write+root | incremental write+root");

for (const pages of PAGE_COUNTS) {
  const floor = new FloorPageTrie();
  floor.batch(preloadEntries(pages));
  const floorSamples: number[] = [];
  let floorRoot: Uint8Array = new Uint8Array(32);
  for (let run = 0; run < RUNS; run++) {
    const start = performance.now();
    floor.put(uint256(5n), uint256(BigInt(run) + 1000n));
    floorRoot = await floor.root();
    floorSamples.push(performance.now() - start);
  }

  const incremental = await createPageTrie();
  await incremental.batch(preloadEntries(pages));
  const incrementalSamples: number[] = [];
  let incrementalRoot: Uint8Array = new Uint8Array(32);
  for (let run = 0; run < RUNS; run++) {
    const start = performance.now();
    await incremental.put(uint256(5n), uint256(BigInt(run) + 1000n));
    incrementalRoot = incremental.root();
    incrementalSamples.push(performance.now() - start);
  }

  if (bytesToHex(floorRoot) !== bytesToHex(incrementalRoot)) {
    throw new Error(`root mismatch at ${pages} pages`);
  }
  const floorMs = median(floorSamples).toFixed(2).padStart(13);
  const incrementalMs = median(incrementalSamples).toFixed(2).padStart(19);
  console.log(
    `${String(pages).padStart(5)} | ${floorMs} ms | ${incrementalMs} ms`,
  );
}
