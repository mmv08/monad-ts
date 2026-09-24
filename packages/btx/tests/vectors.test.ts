import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { encryptWithRandom, pad } from "../src/btx.js";
import {
  decodeEncryptionKey,
  encodeGt,
  encodeScalar,
  Gt,
} from "../src/curve.js";
import { expandR, hRho } from "../src/hash.js";
import { admitCiphertext, serializeCiphertext } from "../src/index.js";
import { createTestKey } from "../src/testing.js";
import type { Vector } from "./fixtures/vectors.js";
import { bytesToHex, fixedRandom, hexToBytes } from "./utils.js";

const vectorsFile = readFileSync(
  new URL("./fixtures/vectors.json", import.meta.url),
  "utf8",
);
const vectors = JSON.parse(vectorsFile) as Vector[];

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
    const padded = pad(plaintext, vector.paddedLength);
    expect(bytesToHex(padded)).toBe(vector.paddedPlaintext);

    const r = expandR(hRho(associatedData, padded, seed));
    expect(bytesToHex(encodeScalar(r))).toBe(vector.r);
    const padElement = Gt.pow(decodeEncryptionKey(key.encryptionKey), r);
    expect(bytesToHex(encodeGt(padElement))).toBe(vector.pad);

    const ciphertext = encryptWithRandom(
      {
        plaintext,
        encryptionKey: key.encryptionKey,
        associatedData,
        paddedLength: vector.paddedLength,
      },
      fixedRandom(seed, BigInt(`0x${vector.nonce}`)),
    );
    expect(bytesToHex(ciphertext.commitment)).toBe(vector.commitment);
    expect(bytesToHex(ciphertext.maskedSeed)).toBe(vector.maskedSeed);
    expect(bytesToHex(ciphertext.maskedPayload)).toBe(vector.maskedPayload);
    expect(bytesToHex(ciphertext.proof)).toBe(
      vector.challenge + vector.response,
    );
    expect(bytesToHex(serializeCiphertext(ciphertext))).toBe(vector.ciphertext);

    const wire = hexToBytes(vector.ciphertext);
    expect(serializeCiphertext(admitCiphertext(wire, associatedData))).toEqual(
      wire,
    );
    const decrypted = key.decrypt(wire, associatedData);
    expect(decrypted && bytesToHex(decrypted.plaintext)).toBe(vector.plaintext);
    expect(decrypted && bytesToHex(decrypted.seed)).toBe(vector.seed);
  });
});
