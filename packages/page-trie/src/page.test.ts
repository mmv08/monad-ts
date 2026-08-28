import { describe, expect, test } from "bun:test";

import {
  computePageKey,
  computeSlotOffset,
  PAGE_SIZE,
  pageCommit,
  SLOT_SIZE,
} from "./page.js";

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function uint256(value: bigint): Uint8Array {
  const bytes = new Uint8Array(SLOT_SIZE);
  for (let i = bytes.length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function setWord(page: Uint8Array, index: number, value: bigint): void {
  page.set(uint256(value), index * SLOT_SIZE);
}

describe("page addressing", () => {
  test.each([
    [0n, 0n, 0],
    [127n, 0n, 127],
    [128n, 1n, 0],
    [255n, 1n, 127],
  ] as const)("maps slot %s to its page and offset", (slot, page, offset) => {
    expect(computePageKey(uint256(slot))).toEqual(uint256(page));
    expect(computeSlotOffset(uint256(slot))).toBe(offset);
  });

  test("maps the maximum 256-bit slot", () => {
    const slot = new Uint8Array(SLOT_SIZE).fill(0xff);
    const expectedPageKey = new Uint8Array(SLOT_SIZE).fill(0xff);
    expectedPageKey[0] = 0x01;

    expect(computePageKey(slot)).toEqual(expectedPageKey);
    expect(computeSlotOffset(slot)).toBe(127);
  });

  test("returns a defensive page-key copy", () => {
    const slot = uint256(128n);
    const pageKey = computePageKey(slot);
    slot.fill(0xff);

    expect(pageKey).toEqual(uint256(1n));
  });

  test.each([
    computePageKey,
    computeSlotOffset,
  ])("rejects invalid slot inputs", (compute) => {
    expect(() => compute([] as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => compute(new Uint8Array(SLOT_SIZE - 1))).toThrow(RangeError);
    expect(() => compute(new Uint8Array(SLOT_SIZE + 1))).toThrow(RangeError);
  });
});

describe("pageCommit", () => {
  test.each([
    [
      "zero page",
      new Uint8Array(PAGE_SIZE),
      "e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e",
    ],
    [
      "slot 0",
      (() => {
        const page = new Uint8Array(PAGE_SIZE);
        setWord(page, 0, 1n);
        return page;
      })(),
      "80218c63919cd8c68aa9a5c0117bb8b46eb02099a7ce0b47a36e7b21658cc9f9",
    ],
    [
      "slot 127",
      (() => {
        const page = new Uint8Array(PAGE_SIZE);
        setWord(page, 127, 1n);
        return page;
      })(),
      "39a2175f8fac8fbf447383b46ff40e03673b388c05c87e50ed7b3f1a810c98d8",
    ],
    [
      "full page",
      (() => {
        const page = new Uint8Array(PAGE_SIZE);
        for (let i = 0; i < 128; i++) setWord(page, i, BigInt(i + 1));
        return page;
      })(),
      "e5a642261a2c2dedebd68ebd42237f2210d1eee94553d677d425dc3a46c7a687",
    ],
  ])("matches the canonical %s vector", (_name, page, commitment) => {
    expect(bytesToHex(pageCommit(page))).toBe(commitment);
  });

  test("commits both words of an asymmetric pair", () => {
    const page = new Uint8Array(PAGE_SIZE);
    setWord(page, 0, 1n);
    setWord(page, 1, 2n);

    expect(bytesToHex(pageCommit(page))).toBe(
      "46906319c63bef972eab21b85ebaadda0b3d1648c8cd333be15f61b7dbc96e4e",
    );

    const swapped = new Uint8Array(PAGE_SIZE);
    setWord(swapped, 0, 2n);
    setWord(swapped, 1, 1n);
    expect(pageCommit(swapped)).not.toEqual(pageCommit(page));
  });

  test.each([
    [
      [0, 2, 4, 6, 8, 10, 12, 14],
      "269df22ad2b88e875e36642ecad514b9f0c9bd23b8a4cef135f3783ecd2a2db3",
    ],
    [
      [0, 1, 2, 3, 31, 32, 63, 64, 95, 126, 127],
      "6471fe6431c1c4c9ce129bf6a2a14328220e8d10f1767b279c3ab55488797268",
    ],
    [
      [1, 7, 19, 42, 76, 99, 121],
      "e48df95a4a642d309e3f900b77ef5838a2403069ce981c98ef8734380e1b5a0b",
    ],
  ])("matches a canonical sparse or dense merge schedule", (indices, commitment) => {
    const page = new Uint8Array(PAGE_SIZE);
    for (const index of indices) setWord(page, index, BigInt(index + 1));

    expect(bytesToHex(pageCommit(page))).toBe(commitment);
  });

  test("does not mutate its input", () => {
    const page = new Uint8Array(PAGE_SIZE);
    setWord(page, 64, 42n);
    const before = page.slice();

    pageCommit(page);

    expect(page).toEqual(before);
  });

  test("rejects invalid page inputs", () => {
    expect(() => pageCommit([] as unknown as Uint8Array)).toThrow(TypeError);
    expect(() => pageCommit(new Uint8Array(PAGE_SIZE - 1))).toThrow(RangeError);
    expect(() => pageCommit(new Uint8Array(PAGE_SIZE + 1))).toThrow(RangeError);
  });
});
