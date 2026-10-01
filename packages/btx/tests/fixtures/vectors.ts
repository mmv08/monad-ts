import { encryptWithRandom } from "../../src/btx.js";
import { bytesToNumberBE } from "../../src/bytes.js";
import { serializeCiphertext } from "../../src/ciphertext.js";
import { encodeScalar, Fr } from "../../src/curve.js";
import { createTestKey } from "../../src/testing.js";
import {
  bytesToHex,
  hexToBytes,
  pattern,
  scriptedRandom,
  utf8ToBytes,
} from "../utils.js";

/** One deterministic BTX vector. Every byte field is lowercase hex without a prefix. */
type Vector = {
  readonly name: string;
  /** Inputs that fix the vector. */
  readonly trapdoor: string;
  readonly maxBatchSize: number;
  readonly seed: string;
  readonly nonce: string;
  readonly associatedData: string;
  readonly plaintext: string;
  /** Null asks encryption to select its default padding. */
  readonly paddedLength: number | null;
  /** Values a conforming implementation must reproduce. */
  readonly encryptionKey: string;
  readonly ciphertext: string;
};

type Case = {
  readonly name: string;
  readonly trapdoor: bigint;
  readonly maxBatchSize?: number;
  readonly seed: Uint8Array;
  readonly nonce: bigint;
  readonly associatedData: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly paddedLength?: number;
};

const SMALL_TRAPDOOR = 0x2an;
const LARGE_TRAPDOOR = Fr.create(bytesToNumberBE(pattern(64)));
const SEED_A = hexToBytes("000102030405060708090a0b0c0d0e0f");
const SEED_B = hexToBytes("f0e1d2c3b4a5968778695a4b3c2d1e0f");
const NONCE_A = 0x0123456789abcdefn;
const NONCE_B = Fr.create(bytesToNumberBE(pattern(64).reverse()));

const CASES: readonly Case[] = [
  {
    name: "empty plaintext, exact fit, empty associated data",
    trapdoor: SMALL_TRAPDOOR,
    seed: SEED_A,
    nonce: NONCE_A,
    associatedData: new Uint8Array(0),
    plaintext: new Uint8Array(0),
    paddedLength: 0,
  },
  {
    name: "empty plaintext, default padding",
    trapdoor: SMALL_TRAPDOOR,
    seed: SEED_B,
    nonce: NONCE_B,
    associatedData: utf8ToBytes("btx"),
    plaintext: new Uint8Array(0),
  },
  {
    name: "short plaintext padded to 32",
    trapdoor: LARGE_TRAPDOOR,
    seed: SEED_A,
    nonce: NONCE_B,
    associatedData: utf8ToBytes("associated data"),
    plaintext: utf8ToBytes("hello"),
    paddedLength: 32,
  },
  {
    name: "plaintext with trailing zeroes, exact fit",
    trapdoor: LARGE_TRAPDOOR,
    seed: SEED_B,
    nonce: NONCE_A,
    associatedData: utf8ToBytes("associated data"),
    plaintext: hexToBytes("deadbeef000000"),
    paddedLength: 7,
  },
  {
    name: "256-byte plaintext, default padding is an exact fit",
    trapdoor: LARGE_TRAPDOOR,
    seed: SEED_A,
    nonce: NONCE_A,
    associatedData: pattern(32),
    plaintext: pattern(256),
  },
  {
    name: "257-byte plaintext, default padding rounds up to 512",
    trapdoor: LARGE_TRAPDOOR,
    seed: SEED_B,
    nonce: NONCE_B,
    associatedData: pattern(32),
    plaintext: pattern(257),
  },
  {
    name: "long associated data",
    trapdoor: SMALL_TRAPDOOR,
    seed: SEED_A,
    nonce: NONCE_B,
    associatedData: pattern(1000),
    plaintext: utf8ToBytes("short"),
  },
  {
    name: "small batch size changes the encryption key",
    trapdoor: SMALL_TRAPDOOR,
    maxBatchSize: 4,
    seed: SEED_A,
    nonce: NONCE_A,
    associatedData: utf8ToBytes("B_max = 4"),
    plaintext: utf8ToBytes("same trapdoor, different key"),
  },
];

/** Computes every vector from its inputs with the library itself. */
function buildVectors(): Vector[] {
  return CASES.map((c) => {
    const key = createTestKey({
      trapdoor: c.trapdoor,
      maxBatchSize: c.maxBatchSize,
    });
    const ciphertext = encryptWithRandom(
      {
        plaintext: c.plaintext,
        encryptionKey: key.encryptionKey,
        associatedData: c.associatedData,
        paddedLength: c.paddedLength,
      },
      scriptedRandom(c.seed),
      () => c.nonce,
    );
    return {
      name: c.name,
      trapdoor: bytesToHex(encodeScalar(c.trapdoor)),
      maxBatchSize: key.maxBatchSize,
      seed: bytesToHex(c.seed),
      nonce: bytesToHex(encodeScalar(c.nonce)),
      associatedData: bytesToHex(c.associatedData),
      plaintext: bytesToHex(c.plaintext),
      paddedLength: c.paddedLength ?? null,
      encryptionKey: bytesToHex(key.encryptionKey),
      ciphertext: bytesToHex(serializeCiphertext(ciphertext)),
    };
  });
}

/** The vectors file, as `generate.ts` writes it. */
function renderVectors(): string {
  return `${JSON.stringify(buildVectors(), null, 2)}\n`;
}

export type { Vector };
export { renderVectors };
