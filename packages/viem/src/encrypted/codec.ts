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
import { EncryptedTransactionError } from "./errors.js";
import type { EncryptedField } from "./types.js";

export const fields = ["to", "value", "data", "accessList"] as const;

export type Payload = {
  to: Address | null;
  value: bigint;
  data: Hex;
  accessList: AccessList;
};

export type Envelope = Payload & {
  type: "encrypted";
  chainId: number;
  nonce: number;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gas: bigint;
  epoch: bigint;
  encryptedFields: number;
  ciphertext: Hex;
};

type RlpValue = Hex | readonly RlpValue[];

export function maskFor(selection: readonly EncryptedField[] = fields): number {
  let mask = 0;
  for (const field of selection) mask |= 1 << fields.indexOf(field);
  // An unknown name shifts by -1, which sets the sign bit. Both it and an
  // empty selection would otherwise send the payload in the clear.
  if (mask <= 0)
    throw new EncryptedTransactionError(
      "invalidInput",
      "Encrypt one or more of: to, value, data, accessList.",
    );
  return mask;
}

export function selectedFields(mask: number): EncryptedField[] {
  return fields.filter((_, index) => mask & (1 << index));
}

function integer(value: bigint | number, size: number): Hex {
  // Viem enforces the unsigned width; RLP uses minimal bytes and empty for zero.
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
    integer(envelope.encryptedFields, 1),
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
              SignatureEncoding.vToYParity(Number(signature.v)),
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
