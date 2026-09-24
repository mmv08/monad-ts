import * as Rlp from "ox/Rlp";
import * as SignatureEncoding from "ox/Signature";
import {
  type AccessList,
  type Address,
  assertTransactionEIP1559,
  concatHex,
  type Hex,
  keccak256,
  numberToHex,
  type Signature,
  serializeAccessList,
  serializeTransaction as serializeViemTransaction,
  type TransactionSerializable,
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
  // An empty selection or an unknown name would send the payload in the clear.
  if (!selection.length || selection.some((field) => !fields.includes(field)))
    throw new EncryptedTransactionError(
      "invalidInput",
      "Encrypt one or more of: to, value, data, accessList.",
    );
  let mask = 0;
  for (const field of selection) mask |= 1 << fields.indexOf(field);
  return mask;
}

export function selectedFields(mask: number): EncryptedField[] {
  return fields.filter((_, index) => mask & (1 << index));
}

// As in viem's serializers: minimal bytes, empty for zero, and viem's own range check.
function quantity(value: bigint | number): Hex {
  return value ? numberToHex(value) : "0x";
}

function payloadValues(payload: Payload): RlpValue[] {
  return [
    payload.to ?? "0x",
    quantity(payload.value),
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
    quantity(envelope.chainId),
    quantity(envelope.nonce),
    quantity(envelope.maxPriorityFeePerGas),
    quantity(envelope.maxFeePerGas),
    quantity(envelope.gas),
    ...payloadValues(envelope),
    quantity(envelope.epoch),
    quantity(envelope.encryptedFields),
    envelope.ciphertext,
  ];
}

// TODO(spec): Ethereum typed-envelope RLP/signature suffix is the reference wire interpretation.
export function serializeEnvelope(
  envelope: Envelope,
  signature?: Signature,
): Hex {
  // Viem's EIP-1559 serializer makes this check; type 8 shares those fields.
  assertTransactionEIP1559({ ...envelope, type: "eip1559" });
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
