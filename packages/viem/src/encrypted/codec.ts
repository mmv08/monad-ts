import * as Rlp from "ox/Rlp";
import * as SignatureEncoding from "ox/Signature";
import {
  type AccessList,
  type Address,
  concatHex,
  type Hex,
  keccak256,
  type Signature,
  serializeAccessList,
  serializeTransaction as serializeViemTransaction,
  type TransactionSerializable,
  toHex,
  trim,
  zeroAddress,
} from "viem";
import { assertInput } from "./errors.js";
import type { EncryptedField } from "./types.js";

// TODO(spec): The PDF leaves the total transaction limit to chain policy.
// This finite limit is the internal reference backend's policy, not a mainnet claim.
export const MAX_TRANSACTION_BYTES = 128 * 1024;
export const fields = ["to", "value", "data", "accessList"] as const;

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

function integer(value: bigint, size: number): Hex {
  // Viem enforces unsigned width; RLP uses minimal bytes and empty for zero.
  const encoded = trim(toHex(value, { size }));
  return encoded === "0x00" ? "0x" : encoded;
}

function payloadValues(payload: Payload): RlpValue[] {
  return [
    payload.to ?? "0x",
    integer(payload.value, 32),
    payload.data,
    serializeAccessList(payload.accessList),
  ];
}

export function encodePayload(payload: Payload, mask: number): Hex {
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

function envelopeValues(envelope: Envelope): RlpValue[] {
  return [
    integer(envelope.chainId, 8),
    integer(envelope.nonce, 8),
    integer(envelope.maxPriorityFeePerGas, 16),
    integer(envelope.maxFeePerGas, 16),
    integer(envelope.gas, 8),
    ...payloadValues(envelope),
    integer(envelope.epoch, 8),
    integer(BigInt(envelope.encryptedFields), 1),
    envelope.ciphertext,
  ];
}

// TODO(spec): Ethereum typed-envelope RLP/signature suffix is the reference wire interpretation.
export function serializeEnvelope(
  envelope: Envelope,
  signature?: Signature,
): Hex {
  return concatHex([
    "0x08",
    Rlp.fromHex([
      ...envelopeValues(envelope),
      ...(signature
        ? SignatureEncoding.toTuple({
            r: BigInt(signature.r),
            s: BigInt(signature.s),
            yParity:
              signature.yParity ??
              (signature.v === 1n || signature.v === 28n ? 1 : 0),
          })
        : []),
    ]),
  ]);
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
  const digest = keccak256(
    serializeEnvelope({ ...envelope, ciphertext: "0x" }),
  );
  return keccak256(concatHex(["0x01", sender, digest]));
}
