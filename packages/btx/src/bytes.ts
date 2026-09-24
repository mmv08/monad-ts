import {
  bytesToNumberBE,
  equalBytes,
  numberToBytesBE,
} from "@noble/curves/utils.js";
import {
  abytes,
  concatBytes,
  randomBytes,
  utf8ToBytes,
} from "@noble/hashes/utils.js";

/** Encodes an integer as 4 big-endian bytes. */
function u32be(value: number): Uint8Array {
  return numberToBytesBE(BigInt(value), 4);
}

/** Encodes an integer as 8 big-endian bytes. */
function u64be(value: number): Uint8Array {
  return numberToBytesBE(BigInt(value), 8);
}

/** Reads 4 big-endian bytes at `offset` as an integer. */
function readU32be(bytes: Uint8Array, offset: number): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset);
}

/** XORs two equal-length byte arrays into a new array. */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  return xorInto(Uint8Array.from(a), b);
}

/** XORs equal-length byte arrays into the first, owned buffer. The mask must not overlap it. */
function xorInto(a: Uint8Array, b: Uint8Array): Uint8Array {
  for (let i = 0; i < a.length; i++) a[i] ^= b[i];
  return a;
}

export {
  abytes,
  bytesToNumberBE,
  concatBytes,
  equalBytes,
  numberToBytesBE,
  randomBytes,
  readU32be,
  u32be,
  u64be,
  utf8ToBytes,
  xorBytes,
  xorInto,
};
