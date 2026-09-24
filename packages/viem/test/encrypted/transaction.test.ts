import { describe, expect, test } from "bun:test";
import {
  admitCiphertext,
  encrypt,
  serializeCiphertext,
} from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";
import * as Rlp from "ox/Rlp";
import {
  bytesToHex,
  hexToBytes,
  keccak256,
  recoverAddress,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  associatedData,
  conceal,
  type Envelope,
  encodePayload,
  maskFor,
  selectedFields,
  serializeEnvelope,
  serializeTransaction,
} from "../../src/encrypted/codec.js";
import { buildVector } from "./fixtures.js";
import { decodePayload, parseEnvelope } from "./mock.js";

export const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
export const target = "0x1111111111111111111111111111111111111111";
const key = createTestKey({ trapdoor: 42n });
const payload = {
  to: target,
  value: 123n,
  data: "0x123400",
  accessList: [
    { address: target, storageKeys: [`0x${"01".repeat(32)}` as const] },
  ],
} as const;
export const base: Envelope = {
  type: "encrypted",
  chainId: 1337n,
  nonce: 0n,
  gas: 100_000n,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
  epoch: 1n,
  encryptedFields: 15,
  ciphertext: "0x",
  ...conceal(payload, 15),
};

describe("type-8 codec", () => {
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
  ] as const)
    test(`mask ${mask}: PDF selection, payload and placeholders`, () => {
      const selected = new Set<string>(selection);
      const wireValues = {
        to: target,
        value: "0x7b",
        data: "0x123400",
        accessList: [[target, [`0x${"01".repeat(32)}`]]],
      } as const;
      const placeholders = {
        to: selected.has("to") ? zeroAddress : target,
        value: selected.has("value") ? 0n : 123n,
        data: selected.has("data") ? "0x" : "0x123400",
        accessList: selected.has("accessList") ? [] : payload.accessList,
      } as const;
      expect(selectedFields(mask)).toEqual([...selection]);
      expect(maskFor(selection)).toBe(mask);
      expect(conceal(payload, mask)).toEqual(placeholders);
      const envelope = {
        ...base,
        ...placeholders,
        encryptedFields: mask,
      };
      const plaintext = encodePayload(payload, mask);
      expect(plaintext).toBe(
        Rlp.fromHex(selection.map((field) => wireValues[field])),
      );
      expect(decodePayload(plaintext, envelope)).toEqual(payload);
    });

  test("committed wire, signing and binding regression vector", async () => {
    const stored: unknown = await Bun.file(
      new URL("./vector.json", import.meta.url),
    ).json();
    expect(stored).toEqual(await buildVector());
  });

  test("ordinary serialization delegates to viem", async () => {
    const raw = await account.signTransaction(
      {
        type: "eip1559",
        chainId: 1337,
        nonce: 0,
        to: target,
        gas: 21_000n,
        maxFeePerGas: 3n,
        maxPriorityFeePerGas: 1n,
      },
      { serializer: serializeTransaction },
    );
    expect(raw.startsWith("0x02")).toBe(true);
  });

  test("encrypted envelope signs, recovers and decrypts", async () => {
    const envelope = { ...base };
    const plaintext = encodePayload(payload, 15);
    const ad = associatedData(envelope, account.address);
    envelope.ciphertext = bytesToHex(
      serializeCiphertext(
        encrypt({
          plaintext: hexToBytes(plaintext),
          associatedData: hexToBytes(ad),
          encryptionKey: key.encryptionKey,
        }),
      ),
    );
    const raw = await account.signTransaction(envelope, {
      serializer: serializeTransaction,
    });
    const parsed = parseEnvelope(raw);
    expect(parsed.envelope).toEqual(envelope);
    expect(
      await recoverAddress({
        hash: keccak256(serializeEnvelope(envelope)),
        signature: parsed.signature,
      }),
    ).toBe(account.address);
    const decrypted = key.decrypt(
      hexToBytes(envelope.ciphertext),
      hexToBytes(ad),
    );
    expect(decrypted).not.toBeNull();
    if (!decrypted) throw new Error("Expected plaintext");
    expect(decodePayload(bytesToHex(decrypted.plaintext), envelope)).toEqual(
      payload,
    );
  });

  test("payload decoding rejects wrong arity and never restores only some fields", () => {
    const original = structuredClone(base);
    expect(() => decodePayload(Rlp.fromHex([]), base)).toThrow("field count");
    // The recipient decodes first; the nested list is invalid as a value.
    expect(() =>
      decodePayload(Rlp.fromHex([target, [], "0x", []]), base),
    ).toThrow("Expected RLP bytes");
    expect(base).toEqual(original);
  });

  test("creation and legitimate placeholders are distinct", () => {
    for (const to of [null, zeroAddress]) {
      const actual = { to, value: 0n, data: "0x" as const, accessList: [] };
      expect(decodePayload(encodePayload(actual, 15), base)).toEqual(actual);
    }
    expect(
      encodePayload({ to: null, value: 0n, data: "0x", accessList: [] }, 15),
    ).toBe("0xc4808080c0");
  });

  test("every public field and sender binds the proof", () => {
    const envelope = {
      ...base,
      ...payload,
      data: "0x" as const,
      encryptedFields: 4,
    };
    const ad = associatedData(envelope, account.address);
    const ciphertext = serializeCiphertext(
      encrypt({
        plaintext: new Uint8Array(),
        associatedData: hexToBytes(ad),
        encryptionKey: key.encryptionKey,
      }),
    );
    for (const field of [
      "chainId",
      "nonce",
      "gas",
      "maxFeePerGas",
      "maxPriorityFeePerGas",
      "epoch",
    ] as const) {
      expect(() =>
        admitCiphertext(
          ciphertext,
          hexToBytes(
            associatedData(
              { ...envelope, [field]: envelope[field] + 1n },
              account.address,
            ),
          ),
        ),
      ).toThrow();
    }
    expect(() =>
      admitCiphertext(ciphertext, hexToBytes(associatedData(envelope, target))),
    ).toThrow();
    for (const changed of [
      { ...envelope, encryptedFields: 5 },
      { ...envelope, to: zeroAddress },
      { ...envelope, value: 124n },
      { ...envelope, accessList: [] },
    ])
      expect(() =>
        admitCiphertext(
          ciphertext,
          hexToBytes(associatedData(changed, account.address)),
        ),
      ).toThrow();

    const exposedData = { ...base, ...payload, value: 0n, encryptedFields: 2 };
    const dataCiphertext = serializeCiphertext(
      encrypt({
        plaintext: hexToBytes(encodePayload(payload, 2)),
        associatedData: hexToBytes(
          associatedData(exposedData, account.address),
        ),
        encryptionKey: key.encryptionKey,
      }),
    );
    expect(() =>
      admitCiphertext(
        dataCiphertext,
        hexToBytes(
          associatedData({ ...exposedData, data: "0x5678" }, account.address),
        ),
      ),
    ).toThrow();
  });

  test("rejects invalid masks and wire integer widths", () => {
    for (const mask of [0, 16, -1, 1.5])
      expect(() => selectedFields(mask)).toThrow();
    expect(() => maskFor(["to", "to"])).toThrow();
    expect(() => serializeEnvelope({ ...base, nonce: 1n << 64n })).toThrow();
    expect(() =>
      serializeEnvelope({ ...base, maxFeePerGas: 1n << 128n }),
    ).toThrow();
    expect(() =>
      encodePayload({ ...payload, value: 1n << 256n }, 15),
    ).toThrow();
  });

  test("mock parser rejects malformed and noncanonical envelopes", async () => {
    const raw = await account.signTransaction(base, {
      serializer: serializeTransaction,
    });
    for (const invalid of [
      `${raw}00`,
      "0x08c0",
      "0x02c0",
      "0x08f80180",
      `0x08${"c1".repeat(10)}80`,
    ] as const)
      expect(() => parseEnvelope(invalid)).toThrow();
    const parsed = parseEnvelope(raw);
    expect(() =>
      parseEnvelope(
        serializeEnvelope({ ...base, to: target }, parsed.signature),
      ),
    ).toThrow();
    expect(() =>
      decodePayload("0xc100", { ...base, encryptedFields: 2 }),
    ).toThrow();
    // Ox decodes these aliases/trailing bytes; the ETX wire boundary rejects them.
    for (const encoded of [
      "0xf80180",
      "0xf9000180",
      "0xc28101",
      "0xc18000",
    ] as const) {
      expect(() =>
        decodePayload(encoded, { ...base, encryptedFields: 2 }),
      ).toThrow();
    }
  });
});
