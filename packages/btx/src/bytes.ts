import {
  bytesToNumberBE,
  equalBytes,
  numberToBytesBE,
} from "@noble/curves/utils.js";
import {
  abytes,
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from "@noble/hashes/utils.js";

/** Encodes an integer as 4 big-endian bytes. */
function u32be(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

/** Encodes an integer as 8 big-endian bytes. */
function u64be(value: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
  return bytes;
}

/** Reads 4 big-endian bytes at `offset` as an integer. */
function readU32be(bytes: Uint8Array, offset: number): number {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(offset);
}

/** XORs two equal-length byte arrays into a new array. */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  abytes(b, a.length);
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export {
  abytes,
  bytesToHex,
  bytesToNumberBE,
  concatBytes,
  equalBytes,
  hexToBytes,
  numberToBytesBE,
  randomBytes,
  readU32be,
  u32be,
  u64be,
  utf8ToBytes,
  xorBytes,
};
