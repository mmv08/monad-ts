import { describe, expect, test } from "bun:test";
import { encryptWithRandom } from "../src/btx.js";
import { serializeCiphertext } from "../src/index.js";
import { createTestKey } from "../src/testing.js";
import vectors from "./fixtures/vectors.json" with { type: "json" };
import { bytesToHex, hexToBytes, scriptedRandom } from "./utils.js";

describe("fixture vectors", () => {
  test.each(vectors.map((v) => [v.name, v] as const))("%s", (_, vector) => {
    const associatedData = hexToBytes(vector.associatedData);
    const key = createTestKey({
      trapdoor: BigInt(`0x${vector.trapdoor}`),
      maxBatchSize: vector.maxBatchSize,
    });
    expect(bytesToHex(key.encryptionKey)).toBe(vector.encryptionKey);

    const plaintext = hexToBytes(vector.plaintext);
    const seed = hexToBytes(vector.seed);
    const ciphertext = encryptWithRandom(
      {
        plaintext,
        encryptionKey: key.encryptionKey,
        associatedData,
        paddedLength: vector.paddedLength ?? undefined,
      },
      scriptedRandom(seed),
      () => BigInt(`0x${vector.nonce}`),
    );
    expect(bytesToHex(serializeCiphertext(ciphertext))).toBe(vector.ciphertext);

    const wire = hexToBytes(vector.ciphertext);
    const decrypted = key.decrypt(wire, associatedData);
    expect(decrypted && bytesToHex(decrypted.plaintext)).toBe(vector.plaintext);
    expect(decrypted && bytesToHex(decrypted.seed)).toBe(vector.seed);
  });
});
