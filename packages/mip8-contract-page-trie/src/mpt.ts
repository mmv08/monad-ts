// Minimal Ethereum Merkle Patricia Trie that hashes a complete set of leaves.
// It is not a mutable, persistent, or proof-producing trie.
// Encoding: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
import { keccak_256 } from "@noble/hashes/sha3.js";

import { concatBytes } from "./bytes.js";

type Rlp = Uint8Array | Rlp[];
type Leaf = { nibbles: number[]; value: Uint8Array };

const EMPTY = new Uint8Array();

function rlpLengthPrefix(length: number, offset: number): Uint8Array {
  if (length < 56) return Uint8Array.of(offset + length);
  const lenBytes: number[] = [];
  for (let remaining = length; remaining > 0; remaining >>= 8) {
    lenBytes.unshift(remaining & 0xff);
  }
  return Uint8Array.of(offset + 55 + lenBytes.length, ...lenBytes);
}

function rlpEncode(item: Rlp): Uint8Array {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concatBytes(rlpLengthPrefix(item.length, 0x80), item);
  }
  const encoded = item.map(rlpEncode);
  let payloadLength = 0;
  for (const bytes of encoded) payloadLength += bytes.length;
  return concatBytes(rlpLengthPrefix(payloadLength, 0xc0), ...encoded);
}

function bytesToNibbles(bytes: Uint8Array): number[] {
  const nibbles = new Array<number>(bytes.length * 2);
  for (let i = 0; i < bytes.length; i++) {
    nibbles[i * 2] = bytes[i] >> 4;
    nibbles[i * 2 + 1] = bytes[i] & 0xf;
  }
  return nibbles;
}

function hexPrefix(nibbles: number[], terminator: boolean): Uint8Array {
  const odd = nibbles.length & 1;
  const bytes = new Uint8Array((nibbles.length + 2 - odd) >> 1);
  bytes[0] = ((terminator ? 2 : 0) | odd) << 4;
  let nibbleIndex = 0;
  if (odd) bytes[0] |= nibbles[nibbleIndex++];
  for (let i = 1; nibbleIndex < nibbles.length; i++, nibbleIndex += 2) {
    bytes[i] = (nibbles[nibbleIndex] << 4) | nibbles[nibbleIndex + 1];
  }
  return bytes;
}

function commonPrefixLength(items: Leaf[]): number {
  const first = items[0].nibbles;
  let length = first.length;
  for (let i = 1; i < items.length; i++) {
    const other = items[i].nibbles;
    let shared = 0;
    while (
      shared < length &&
      shared < other.length &&
      first[shared] === other[shared]
    ) {
      shared++;
    }
    length = shared;
  }
  return length;
}

function commit(node: Rlp, isRoot: boolean): Rlp {
  const encoded = rlpEncode(node);
  if (encoded.length >= 32 || isRoot) return keccak_256(encoded);
  return node;
}

function build(items: Leaf[], isRoot: boolean): Rlp {
  if (items.length === 1) {
    return commit([hexPrefix(items[0].nibbles, true), items[0].value], isRoot);
  }

  const prefix = commonPrefixLength(items);
  if (prefix > 0) {
    const stripped = items.map((item) => ({
      nibbles: item.nibbles.slice(prefix),
      value: item.value,
    }));
    return commit(
      [
        hexPrefix(items[0].nibbles.slice(0, prefix), false),
        build(stripped, false),
      ],
      isRoot,
    );
  }

  const groups: Leaf[][] = Array.from({ length: 16 }, () => []);
  let value: Uint8Array = EMPTY;
  for (const item of items) {
    if (item.nibbles.length === 0) {
      value = item.value;
    } else {
      groups[item.nibbles[0]].push({
        nibbles: item.nibbles.slice(1),
        value: item.value,
      });
    }
  }
  const branch: Rlp[] = groups.map((group) =>
    group.length === 0 ? EMPTY : build(group, false),
  );
  branch.push(value);
  return commit(branch, isRoot);
}

/** Returns the Ethereum MPT root for `pairs`. */
function mptRoot(
  pairs: Iterable<readonly [Uint8Array, Uint8Array]>,
): Uint8Array {
  const items: Leaf[] = [];
  for (const [key, value] of pairs) {
    items.push({ nibbles: bytesToNibbles(key), value });
  }
  if (items.length === 0) return commit(EMPTY, true) as Uint8Array;
  return build(items, true) as Uint8Array;
}

export { mptRoot };
