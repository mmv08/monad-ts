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
  decodePayload,
  type Envelope,
  encodePayload,
  maskFor,
  parseEnvelope,
  selectedFields,
  serializeEnvelope,
  serializeTransaction,
} from "../../src/encrypted/codec.js";

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
  for (let mask = 1; mask < 16; mask++)
    test(`mask ${mask}: encryption, signed bytes, recovery, all-or-nothing restoration`, async () => {
      const envelope = {
        ...base,
        ...conceal(payload, mask),
        encryptedFields: mask,
      };
      const plaintext = encodePayload(payload, mask);
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
      expect(() => decodePayload(Rlp.fromHex([]), envelope)).toThrow();
      expect(maskFor(selectedFields(mask))).toBe(mask);
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
    const ad = associatedData(base, account.address);
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
              { ...base, [field]: base[field] + 1n },
              account.address,
            ),
          ),
        ),
      ).toThrow();
    }
    expect(() =>
      admitCiphertext(ciphertext, hexToBytes(associatedData(base, target))),
    ).toThrow();
  });

  test("rejects invalid masks, values, lengths and signatures", async () => {
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
      serializeEnvelope(base, {
        ...parsed.signature,
        s: `0x${"ff".repeat(32)}`,
      }),
    ).not.toThrow();
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
