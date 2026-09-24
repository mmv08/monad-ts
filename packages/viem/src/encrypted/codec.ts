import * as Rlp from "ox/Rlp";
import {
  type AccessList,
  type Address,
  concatHex,
  type Hex,
  keccak256,
  type Signature,
  serializeTransaction as serializeViemTransaction,
  type TransactionSerializable,
  zeroAddress,
} from "viem";
import { assertInput } from "./errors.js";
import type { EncryptedField } from "./types.js";

// TODO(spec): The PDF leaves the total transaction limit to chain policy.
// This finite limit is the internal reference backend's policy, not a mainnet claim.
export const MAX_TRANSACTION_BYTES = 128 * 1024;
export const fields = ["to", "value", "data", "accessList"] as const;
const secp256k1Order =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

export type Payload = {
  to: Address | null;
  value: bigint;
  data: Hex;
  accessList: AccessList;
};

export type Envelope = Payload & {
  type: "encrypted";
  chainId: bigint;
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gas: bigint;
  epoch: bigint;
  encryptedFields: number;
  ciphertext: Hex;
};

type RlpValue = Hex | readonly RlpValue[];

export function hex(value: unknown, bytes?: number): asserts value is Hex {
  assertInput(
    typeof value === "string" && /^0x(?:[\da-fA-F]{2})*$/.test(value),
    "Expected even-length hex bytes.",
  );
  assertInput(
    bytes === undefined || value.length === 2 + bytes * 2,
    "Incorrect byte width.",
  );
}

export function uint(value: unknown, bits: number): asserts value is bigint {
  assertInput(
    typeof value === "bigint" && value >= 0n && value < 1n << BigInt(bits),
    `Expected an unsigned ${bits}-bit integer.`,
  );
}

export function safeInteger(value: unknown): asserts value is number {
  assertInput(
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0,
    "Expected a nonnegative safe integer.",
  );
}

export function maskFor(selection: readonly EncryptedField[] = fields): number {
  assertInput(
    Array.isArray(selection) && selection.length > 0,
    "Select at least one encrypted field.",
  );
  let mask = 0;
  for (const field of selection) {
    const index = fields.indexOf(field);
    assertInput(
      index >= 0 && !(mask & (1 << index)),
      "Unknown or duplicate encrypted field.",
    );
    mask |= 1 << index;
  }
  return mask;
}

export function selectedFields(mask: number): EncryptedField[] {
  assertInput(
    Number.isInteger(mask) && mask > 0 && mask < 16,
    "Invalid encrypted field mask.",
  );
  return fields.filter((_, index) => mask & (1 << index));
}

function integer(value: bigint): Hex {
  if (value === 0n) return "0x";
  const digits = value.toString(16);
  return `0x${digits.length % 2 ? "0" : ""}${digits}`;
}

function accessListValues(accessList: AccessList): RlpValue[] {
  assertInput(Array.isArray(accessList), "Invalid access list.");
  return accessList.map(({ address, storageKeys }) => {
    hex(address, 20);
    assertInput(Array.isArray(storageKeys), "Invalid storage keys.");
    for (const key of storageKeys) hex(key, 32);
    return [address, [...storageKeys]];
  });
}

export function payloadValues(payload: Payload): RlpValue[] {
  if (payload.to !== null) hex(payload.to, 20);
  uint(payload.value, 256);
  hex(payload.data);
  return [
    payload.to ?? "0x",
    integer(payload.value),
    payload.data,
    accessListValues(payload.accessList),
  ];
}

export function encodePayload(payload: Payload, mask: number): Hex {
  selectedFields(mask);
  return Rlp.fromHex(
    payloadValues(payload).filter((_, index) => mask & (1 << index)),
  );
}

export function conceal(payload: Payload, mask: number): Payload {
  return {
    to: mask & 1 ? zeroAddress : payload.to,
    value: mask & 2 ? 0n : payload.value,
    data: mask & 4 ? "0x" : payload.data,
    accessList: mask & 8 ? [] : payload.accessList,
  };
}

function list(value: RlpValue, length?: number): readonly RlpValue[] {
  assertInput(
    Array.isArray(value) && (length === undefined || value.length === length),
    "Invalid RLP list.",
  );
  return value;
}

function bytes(value: RlpValue): Hex {
  assertInput(typeof value === "string", "Expected RLP bytes.");
  return value;
}

function decodeInteger(value: RlpValue, bits: number): bigint {
  const raw = bytes(value);
  assertInput(
    raw === "0x" || !raw.startsWith("0x00"),
    "Noncanonical RLP integer.",
  );
  const result = raw === "0x" ? 0n : BigInt(raw);
  uint(result, bits);
  return result;
}

function decodeTo(value: RlpValue): Address | null {
  const raw = bytes(value);
  if (raw === "0x") return null;
  hex(raw, 20);
  return raw;
}

function decodeAccessList(value: RlpValue): AccessList {
  return list(value).map((entry) => {
    const [address, keys] = list(entry, 2);
    const decodedAddress = bytes(address);
    hex(decodedAddress, 20);
    return {
      address: decodedAddress,
      storageKeys: list(keys).map((key) => {
        const decodedKey = bytes(key);
        hex(decodedKey, 32);
        return decodedKey;
      }),
    };
  });
}

function decodeList(raw: Hex): readonly RlpValue[] {
  hex(raw);
  assertInput(
    raw.length / 2 - 1 <= MAX_TRANSACTION_BYTES,
    "Transaction exceeds the reference size limit.",
  );
  // Bound nesting before passing hostile data to Ox's recursive decoder.
  let depth = 0;
  const ends: number[] = [];
  // Scan RLP lengths iteratively; the actual value decoding remains Ox's job.
  const input = raw.slice(2);
  const size = input.length / 2;
  const byte = (offset: number) =>
    Number.parseInt(input.slice(offset * 2, offset * 2 + 2), 16);
  for (let offset = 0; offset < size; ) {
    while (ends.length && offset === ends[ends.length - 1]) {
      ends.pop();
      depth--;
    }
    const prefix = byte(offset++);
    if (prefix < 0x80) continue;
    const isList = prefix >= 0xc0;
    const base = isList ? 0xc0 : 0x80;
    let length = prefix - base;
    if (length > 55) {
      const width = length - 55;
      assertInput(
        width <= 4 && offset + width <= size && byte(offset) !== 0,
        "Invalid RLP length.",
      );
      length = 0;
      for (let i = 0; i < width; i++) length = length * 256 + byte(offset++);
      assertInput(length >= 56, "Noncanonical RLP length.");
    }
    const end = offset + length;
    assertInput(
      end <= (ends[ends.length - 1] ?? size),
      "RLP length exceeds its container.",
    );
    if (isList) {
      assertInput(++depth <= 4, "RLP nesting exceeds the transaction shape.");
      ends.push(end);
    } else offset = end;
  }
  const result = list(Rlp.toHex(raw));
  assertInput(
    Rlp.fromHex(result).toLowerCase() === raw.toLowerCase(),
    "Noncanonical RLP encoding.",
  );
  return result;
}

export function decodePayload(raw: Hex, envelope: Envelope): Payload {
  const values = decodeList(raw);
  const selection = selectedFields(envelope.encryptedFields);
  assertInput(
    values.length === selection.length,
    "Incorrect encrypted payload field count.",
  );
  const restored: Payload = {
    to: envelope.to,
    value: envelope.value,
    data: envelope.data,
    accessList: envelope.accessList,
  };
  selection.forEach((field, index) => {
    const value = values[index];
    if (field === "to") restored.to = decodeTo(value);
    else if (field === "value") restored.value = decodeInteger(value, 256);
    else if (field === "data") restored.data = bytes(value);
    else restored.accessList = decodeAccessList(value);
  });
  return restored;
}

function envelopeValues(envelope: Envelope): RlpValue[] {
  for (const value of [
    envelope.chainId,
    envelope.nonce,
    envelope.gas,
    envelope.epoch,
  ])
    uint(value, 64);
  uint(envelope.maxPriorityFeePerGas, 128);
  uint(envelope.maxFeePerGas, 128);
  assertInput(
    envelope.chainId > 0n &&
      envelope.maxPriorityFeePerGas <= envelope.maxFeePerGas,
    "Invalid chain ID or fee caps.",
  );
  selectedFields(envelope.encryptedFields);
  hex(envelope.ciphertext);
  const placeholders = conceal(envelope, envelope.encryptedFields);
  assertInput(
    envelope.to?.toLowerCase() === placeholders.to?.toLowerCase() &&
      envelope.value === placeholders.value &&
      envelope.data === placeholders.data &&
      (!(envelope.encryptedFields & 8) || envelope.accessList.length === 0),
    "Concealed fields must use their placeholders.",
  );
  return [
    integer(envelope.chainId),
    integer(envelope.nonce),
    integer(envelope.maxPriorityFeePerGas),
    integer(envelope.maxFeePerGas),
    integer(envelope.gas),
    ...payloadValues(envelope),
    integer(envelope.epoch),
    integer(BigInt(envelope.encryptedFields)),
    envelope.ciphertext,
  ];
}

function signatureValues(signature: Signature): Hex[] {
  const r = BigInt(signature.r);
  const s = BigInt(signature.s);
  assertInput(
    (signature.yParity === 0 || signature.yParity === 1) &&
      r > 0n &&
      r < secp256k1Order &&
      s > 0n &&
      s <= secp256k1Order / 2n,
    "Invalid transaction signature.",
  );
  return [integer(BigInt(signature.yParity)), integer(r), integer(s)];
}

// TODO(spec): Ethereum typed-envelope RLP/signature suffix is the reference wire interpretation.
export function serializeEnvelope(
  envelope: Envelope,
  signature?: Signature,
): Hex {
  const raw = concatHex([
    "0x08",
    Rlp.fromHex([
      ...envelopeValues(envelope),
      ...(signature ? signatureValues(signature) : []),
    ]),
  ]);
  assertInput(
    raw.length / 2 - 1 <= MAX_TRANSACTION_BYTES,
    "Transaction exceeds the reference size limit.",
  );
  return raw;
}

/** The ordinary union is required by viem's local-account serializer contract. */
export function serializeTransaction(
  transaction: TransactionSerializable | Envelope,
  signature?: Signature,
): Hex {
  return transaction.type === "encrypted"
    ? serializeEnvelope(transaction, signature)
    : serializeViemTransaction(transaction, signature);
}

export function associatedData(envelope: Envelope, sender: Address): Hex {
  hex(sender, 20);
  const digest = keccak256(
    serializeEnvelope({ ...envelope, ciphertext: "0x" }),
  );
  return keccak256(concatHex(["0x01", sender, digest]));
}

export function parseEnvelope(raw: Hex): {
  envelope: Envelope;
  signature: Signature;
} {
  hex(raw);
  assertInput(
    raw.length / 2 - 1 <= MAX_TRANSACTION_BYTES,
    "Transaction exceeds the reference size limit.",
  );
  assertInput(raw.startsWith("0x08"), "Expected a type-8 transaction.");
  const values = list(decodeList(`0x${raw.slice(4)}`), 15);
  const envelope: Envelope = {
    type: "encrypted",
    chainId: decodeInteger(values[0], 64),
    nonce: decodeInteger(values[1], 64),
    maxPriorityFeePerGas: decodeInteger(values[2], 128),
    maxFeePerGas: decodeInteger(values[3], 128),
    gas: decodeInteger(values[4], 64),
    to: decodeTo(values[5]),
    value: decodeInteger(values[6], 256),
    data: bytes(values[7]),
    accessList: decodeAccessList(values[8]),
    epoch: decodeInteger(values[9], 64),
    encryptedFields: Number(decodeInteger(values[10], 8)),
    ciphertext: bytes(values[11]),
  };
  const parity = decodeInteger(values[12], 8);
  assertInput(parity === 0n || parity === 1n, "Invalid signature parity.");
  const signature: Signature = {
    yParity: parity === 0n ? 0 : 1,
    r: `0x${decodeInteger(values[13], 256).toString(16).padStart(64, "0")}`,
    s: `0x${decodeInteger(values[14], 256).toString(16).padStart(64, "0")}`,
  };
  assertInput(
    serializeEnvelope(envelope, signature).toLowerCase() === raw.toLowerCase(),
    "Noncanonical transaction.",
  );
  return { envelope, signature };
}
