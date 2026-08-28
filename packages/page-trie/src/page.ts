import { blake3 } from "@noble/hashes/blake3.js";

/** Size of a storage slot in bytes. */
export const SLOT_SIZE = 32;
/** Number of storage slots in a MIP-8 page. */
export const PAGE_SLOTS = 128;
/** Size of a dense MIP-8 page in bytes. */
export const PAGE_SIZE = SLOT_SIZE * PAGE_SLOTS;

const PAIR_SIZE = SLOT_SIZE * 2;
const PAGE_PAIRS = PAGE_SLOTS / 2;

// BLAKE3 compression flags: they tag what a block is (start or end of a
// chunk, key derivation) so different uses of the same bytes hash differently.
const CHUNK_START = 1;
const CHUNK_END = 2;
const DERIVE_KEY_MATERIAL = 64;

// Fixed starting state from the BLAKE3 spec, inherited from SHA-256 (the
// fractional parts of the square roots of the first eight primes).
const BLAKE3_IV = Uint32Array.of(
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
);

// Fixed order, from the BLAKE3 spec, in which the 16 message words are
// reshuffled between compression rounds.
const MESSAGE_PERMUTATION = Uint8Array.of(
  2,
  6,
  3,
  10,
  7,
  0,
  4,
  13,
  1,
  11,
  12,
  5,
  9,
  14,
  15,
  8,
);

export function assertBytes(
  value: unknown,
  length: number,
  name: string,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
  if (value.length !== length) {
    throw new RangeError(`${name} must be exactly ${length} bytes`);
  }
}

export function isZero(
  bytes: Uint8Array,
  start = 0,
  length = bytes.length - start,
): boolean {
  const end = start + length;
  for (let i = start; i < end; i++) {
    if (bytes[i] !== 0) return false;
  }
  return true;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/** Computes the 32-byte page key (`slot >> 7`) for a big-endian storage slot. */
export function computePageKey(slot: Uint8Array): Uint8Array {
  assertBytes(slot, SLOT_SIZE, "slot");

  const pageKey = new Uint8Array(SLOT_SIZE);
  let carry = 0;
  for (let i = 0; i < slot.length; i++) {
    const byte = slot[i];
    pageKey[i] = carry | (byte >>> 7);
    carry = (byte & 0x7f) << 1;
  }
  return pageKey;
}

/** Computes the slot's zero-based offset (`slot & 0x7f`) within its page. */
export function computeSlotOffset(slot: Uint8Array): number {
  assertBytes(slot, SLOT_SIZE, "slot");
  return slot[SLOT_SIZE - 1] & 0x7f;
}

function rotateRight(word: number, shift: number): number {
  return ((word >>> shift) | (word << (32 - shift))) >>> 0;
}

function mix(
  state: Uint32Array,
  a: number,
  b: number,
  c: number,
  d: number,
  messageX: number,
  messageY: number,
): void {
  state[a] = (state[a] + state[b] + messageX) >>> 0;
  state[d] = rotateRight(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateRight(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + messageY) >>> 0;
  state[d] = rotateRight(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateRight(state[b] ^ state[c], 7);
}

function round(state: Uint32Array, message: Uint32Array): void {
  mix(state, 0, 4, 8, 12, message[0], message[1]);
  mix(state, 1, 5, 9, 13, message[2], message[3]);
  mix(state, 2, 6, 10, 14, message[4], message[5]);
  mix(state, 3, 7, 11, 15, message[6], message[7]);
  mix(state, 0, 5, 10, 15, message[8], message[9]);
  mix(state, 1, 6, 11, 12, message[10], message[11]);
  mix(state, 2, 7, 8, 13, message[12], message[13]);
  mix(state, 3, 4, 9, 14, message[14], message[15]);
}

function permute(message: Uint32Array): Uint32Array {
  const permuted = new Uint32Array(message.length);
  for (let i = 0; i < message.length; i++) {
    permuted[i] = message[MESSAGE_PERMUTATION[i]];
  }
  return permuted;
}

function bytesToWords(bytes: Uint8Array): Uint32Array {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const words = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < words.length; i++) {
    words[i] = view.getUint32(i * 4, true);
  }
  return words;
}

function wordsToBytes(words: Uint32Array): Uint8Array {
  const bytes = new Uint8Array(words.length * 4);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < words.length; i++) {
    view.setUint32(i * 4, words[i], true);
  }
  return bytes;
}

function compress(
  chainingValue: Uint32Array,
  block: Uint8Array,
  flags: number,
): Uint32Array {
  const state = new Uint32Array(16);
  state.set(chainingValue, 0);
  state.set(BLAKE3_IV.subarray(0, 4), 8);
  state[14] = block.length;
  state[15] = flags;

  let message = bytesToWords(block);
  for (let i = 0; i < 7; i++) {
    round(state, message);
    if (i < 6) message = permute(message);
  }

  const output = new Uint32Array(8);
  for (let i = 0; i < output.length; i++) {
    output[i] = state[i] ^ state[i + 8];
  }
  return output;
}

const leafDomainBlock = new Uint8Array(PAIR_SIZE);
leafDomainBlock.set(
  new TextEncoder().encode("ultra_merkle_pair_leaf_domain___"),
);
const LEAF_IV = compress(BLAKE3_IV, leafDomainBlock, DERIVE_KEY_MATERIAL);

function hashLeaf(pair: Uint8Array): Uint8Array {
  return wordsToBytes(compress(LEAF_IV, pair, DERIVE_KEY_MATERIAL));
}

function hashParent(left: Uint8Array, right: Uint8Array): Uint8Array {
  const block = new Uint8Array(PAIR_SIZE);
  block.set(left);
  block.set(right, left.length);
  return wordsToBytes(compress(BLAKE3_IV, block, CHUNK_START | CHUNK_END));
}

type ActiveNode = {
  index: number;
  value: Uint8Array;
};

/** Computes the MIP-8 ISMC commitment for a dense 4096-byte page. */
export function pageCommit(page: Uint8Array): Uint8Array {
  assertBytes(page, PAGE_SIZE, "page");

  const bitmapBytes = new Uint8Array(PAGE_SLOTS / 8);
  const activeSlots: boolean[] = [];
  let anyActive = false;
  for (let i = 0; i < PAGE_SLOTS; i++) {
    const active = !isZero(page, i * SLOT_SIZE, SLOT_SIZE);
    activeSlots.push(active);
    if (active) {
      bitmapBytes[i >> 3] |= 1 << (i & 7);
      anyActive = true;
    }
  }
  if (!anyActive) return Uint8Array.from(blake3(bitmapBytes));

  let activeNodes: ActiveNode[] = [];
  for (let i = 0; i < PAGE_PAIRS; i++) {
    if (activeSlots[i * 2] || activeSlots[i * 2 + 1]) {
      activeNodes.push({
        index: i,
        value: hashLeaf(page.subarray(i * PAIR_SIZE, (i + 1) * PAIR_SIZE)),
      });
    }
  }

  for (let level = 0; activeNodes.length > 1; level++) {
    const nextLevel: ActiveNode[] = [];
    for (let i = 0; i < activeNodes.length; ) {
      const current = activeNodes[i];
      const next = activeNodes[i + 1];
      if (next && current.index >> (level + 1) === next.index >> (level + 1)) {
        nextLevel.push({
          index: current.index,
          value: hashParent(current.value, next.value),
        });
        i += 2;
      } else {
        nextLevel.push(current);
        i += 1;
      }
    }
    activeNodes = nextLevel;
  }

  const seal = new Uint8Array(48);
  seal.set(bitmapBytes);
  seal.set(activeNodes[0].value, bitmapBytes.length);
  return Uint8Array.from(blake3(seal));
}
