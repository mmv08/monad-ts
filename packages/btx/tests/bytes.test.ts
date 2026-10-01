import { expect, test } from "bun:test";
import { u32be, u64be } from "../src/bytes.js";

test("integer encoders preserve big-endian widths and reject overflow", () => {
  expect(u32be(0x01020304)).toEqual(Uint8Array.of(1, 2, 3, 4));
  expect(u32be(0xffffffff)).toEqual(new Uint8Array(4).fill(255));
  expect(u64be(0x01020304)).toEqual(Uint8Array.of(0, 0, 0, 0, 1, 2, 3, 4));
  expect(() => u32be(2 ** 32)).toThrow(RangeError);
  expect(() => u64be(2 ** 64)).toThrow(RangeError);
  expect(() => u32be(-1)).toThrow(RangeError);
  expect(() => u64be(-1)).toThrow(RangeError);
});
