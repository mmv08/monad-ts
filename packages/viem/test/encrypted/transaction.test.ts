import { describe, expect, test } from "bun:test";
import { IntegerOutOfRangeError, InvalidChainIdError, zeroAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  associatedData,
  conceal,
  type Envelope,
  encodePayload,
  maskFor,
  selectedFields,
  serializeEnvelope,
} from "../../src/encrypted/codec.js";
import { EncryptedTransactionError } from "../../src/encrypted/index.js";
import { buildVector } from "./fixtures.js";

const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const target = "0x1111111111111111111111111111111111111111";
const payload = {
  to: target,
  value: 123n,
  data: "0x123400",
  accessList: [
    { address: target, storageKeys: [`0x${"01".repeat(32)}` as const] },
  ],
} as const;
const base: Envelope = {
  type: "encrypted",
  chainId: 1337,
  nonce: 0,
  gas: 100_000n,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
  epoch: 1n,
  encryptedFields: 15,
  ciphertext: "0x",
  ...conceal(payload, 15),
};

describe("type-8 codec", () => {
  test("the field bits follow the PDF table", () => {
    // Explicit PDF bit assignments, independent of the codec's field table.
    for (const [mask, selection] of [
      [1, ["to"]],
      [2, ["value"]],
      [3, ["to", "value"]],
      [4, ["data"]],
      [5, ["to", "data"]],
      [6, ["value", "data"]],
      [7, ["to", "value", "data"]],
      [8, ["accessList"]],
      [9, ["to", "accessList"]],
      [10, ["value", "accessList"]],
      [11, ["to", "value", "accessList"]],
      [12, ["data", "accessList"]],
      [13, ["to", "data", "accessList"]],
      [14, ["value", "data", "accessList"]],
      [15, ["to", "value", "data", "accessList"]],
    ] as const) {
      expect(selectedFields(mask)).toEqual([...selection]);
      expect(maskFor(selection)).toBe(mask);
    }
  });

  test("a partial mask encodes the selected fields and leaves placeholders", () => {
    const address = "11".repeat(20);
    const storageKey = "01".repeat(32);
    // RLP([to, data]) and RLP([value, accessList]), written out by hand.
    expect(encodePayload(payload, 5)).toBe(`0xd994${address}83123400`);
    expect(conceal(payload, 5)).toEqual({
      ...payload,
      to: zeroAddress,
      data: "0x",
    });
    expect(encodePayload(payload, 10)).toBe(
      `0xf83b7bf838f794${address}e1a0${storageKey}`,
    );
    expect(conceal(payload, 10)).toEqual({
      ...payload,
      value: 0n,
      accessList: [],
    });
  });

  test("an empty or unknown field selection is rejected, never sent in the clear", () => {
    expect(() => maskFor([])).toThrow(EncryptedTransactionError);
    // @ts-expect-error JavaScript callers may use the RPC's name for data.
    expect(() => maskFor(["to", "input"])).toThrow(EncryptedTransactionError);
  });

  test("committed wire, signing and binding regression vector", async () => {
    const stored: unknown = await Bun.file(
      new URL("./vector.json", import.meta.url),
    ).json();
    expect(stored).toEqual(await buildVector());
  });

  test("contract creation and a zero-address recipient encode differently", () => {
    const empty = { value: 0n, data: "0x", accessList: [] } as const;
    expect(encodePayload({ ...empty, to: null }, 15)).toBe("0xc4808080c0");
    expect(encodePayload({ ...empty, to: zeroAddress }, 15)).toBe(
      `0xd894${"00".repeat(20)}8080c0`,
    );
  });

  test("the associated data binds the sender and every field but the ciphertext", () => {
    const ad = associatedData(base, account.address);
    for (const changed of [
      { chainId: 1338 },
      { nonce: 1 },
      { gas: 100_001n },
      { maxFeePerGas: 4n },
      { maxPriorityFeePerGas: 2n },
      { to: target },
      { value: 1n },
      { data: "0x12" },
      { accessList: payload.accessList },
      { epoch: 2n },
      { encryptedFields: 14 },
    ] as const)
      expect(associatedData({ ...base, ...changed }, account.address)).not.toBe(
        ad,
      );
    expect(associatedData(base, target)).not.toBe(ad);
    expect(
      associatedData({ ...base, ciphertext: "0x1234" }, account.address),
    ).toBe(ad);
  });

  test("serialization makes the checks of viem's EIP-1559 serializer", () => {
    expect(() => serializeEnvelope({ ...base, chainId: 0 })).toThrow(
      InvalidChainIdError,
    );
    expect(() =>
      serializeEnvelope({ ...base, nonce: Number.MAX_SAFE_INTEGER + 1 }),
    ).toThrow(IntegerOutOfRangeError);
  });
});
