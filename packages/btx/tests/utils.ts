import { expect } from "bun:test";
import {
  abytes,
  bytesToHex,
  hexToBytes,
  numberToBytesBE,
  utf8ToBytes,
} from "../src/bytes.js";
import { SCALAR_ENTROPY_SIZE } from "../src/curve.js";
import { BtxError } from "../src/error.js";

/** Bytes 0, 1, 2, … modulo 251, so no two in-range positions repeat within a page of them. */
function pattern(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => i % 251);
}

/** A `randomBytes` stand-in that hands out the given buffers in order. */
function scriptedRandom(
  ...buffers: readonly Uint8Array[]
): (byteLength: number) => Uint8Array {
  const queue = [...buffers];
  return (byteLength) => abytes(queue.shift() ?? new Uint8Array(), byteLength);
}

/** Supplies the entropy that yields the given seed and nonzero proof nonce. */
function fixedRandom(
  seed: Uint8Array,
  nonce: bigint,
): (byteLength: number) => Uint8Array {
  // Noble maps the entropy to (value mod (q - 1)) + 1.
  return scriptedRandom(seed, numberToBytesBE(nonce - 1n, SCALAR_ENTROPY_SIZE));
}

function expectBtxError(fn: () => unknown, code: BtxError["code"]): void {
  let error: unknown;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  expect(error).toBeInstanceOf(BtxError);
  expect(error).toHaveProperty("code", code);
}

export {
  bytesToHex,
  expectBtxError,
  fixedRandom,
  hexToBytes,
  pattern,
  scriptedRandom,
  utf8ToBytes,
};
