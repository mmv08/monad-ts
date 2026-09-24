import {
  formatBlock,
  formatTransaction,
  formatTransactionReceipt,
  type RpcBlock,
  type RpcTransaction,
  type RpcTransactionReceipt,
  type Transaction,
  type TransactionReceipt,
} from "viem";
import { hex, selectedFields } from "./codec.js";
import { quantity } from "./context.js";
import { EncryptedTransactionError } from "./errors.js";
import type {
  DecryptionStatus,
  EncryptedTransaction,
  EncryptedTransactionReceipt,
} from "./types.js";

type RpcEncryptedTransaction = Omit<
  Extract<RpcTransaction, { type: "0x2" }>,
  "type"
> & {
  type: "0x8";
  epoch: unknown;
  encryptedFields: unknown;
  ciphertext: unknown;
  encrypted?: unknown;
  concealedFields?: unknown;
  decryptionStatus?: unknown;
};
type RpcEncryptedReceipt = Omit<RpcTransactionReceipt, "type"> & {
  type: "0x8";
  decryptionStatus?: unknown;
  failureReason?: unknown;
};

function status(value: unknown): DecryptionStatus {
  if (value === undefined) return "unknown";
  if (value === "pending" || value === "succeeded" || value === "failed")
    return value;
  throw new EncryptedTransactionError(
    "invalidResponse",
    "Invalid decryption status.",
  );
}

function transaction(
  rpc: RpcTransaction | RpcEncryptedTransaction,
): Transaction | EncryptedTransaction {
  if (rpc.type !== "0x8") return formatTransaction(rpc);
  try {
    const epoch = quantity(rpc.epoch, 64);
    const encryptedFields = Number(quantity(rpc.encryptedFields, 8));
    const concealedFields = selectedFields(encryptedFields);
    hex(rpc.ciphertext);
    if (rpc.encrypted !== undefined && rpc.encrypted !== true)
      throw new EncryptedTransactionError(
        "invalidResponse",
        "Invalid encrypted transaction marker.",
      );
    if (
      rpc.concealedFields !== undefined &&
      (!Array.isArray(rpc.concealedFields) ||
        rpc.concealedFields.length !== concealedFields.length ||
        !rpc.concealedFields.every(
          (field, index) =>
            field === concealedFields[index] ||
            (field === "input" && concealedFields[index] === "data"),
        ))
    )
      throw new EncryptedTransactionError(
        "invalidResponse",
        "Concealed fields do not match the mask.",
      );
    // Viem returns the entire Transaction union even for a literal 0x2 input.
    // Narrow that known mapping, without revalidating viem's output at runtime.
    const formatted = formatTransaction({ ...rpc, type: "0x2" }) as Extract<
      Transaction,
      { type: "eip1559" }
    >;
    const decryptionStatus = status(rpc.decryptionStatus);
    return {
      ...formatted,
      type: "encrypted",
      typeHex: "0x8",
      encrypted: true,
      epoch,
      encryptedFields,
      ciphertext: rpc.ciphertext,
      concealedFields,
      decryptionStatus,
    };
  } catch (cause) {
    if (
      cause instanceof EncryptedTransactionError &&
      cause.code === "invalidInput"
    )
      throw new EncryptedTransactionError(
        "invalidResponse",
        cause.shortMessage,
        { cause },
      );
    throw cause;
  }
}

type OrdinaryReceipt = TransactionReceipt & {
  decryptionStatus?: undefined;
  failureReason?: undefined;
};

function receipt(
  rpc: RpcTransactionReceipt | RpcEncryptedReceipt,
): OrdinaryReceipt | EncryptedTransactionReceipt {
  if (rpc.type !== "0x8") {
    return {
      ...formatTransactionReceipt(rpc),
      decryptionStatus: undefined,
      failureReason: undefined,
    };
  }
  const formatted = formatTransactionReceipt({ ...rpc, type: "0x2" });
  const decryptionStatus = status(
    "decryptionStatus" in rpc ? rpc.decryptionStatus : undefined,
  );
  const failureReason = "failureReason" in rpc ? rpc.failureReason : undefined;
  if (
    decryptionStatus === "pending" ||
    (failureReason !== undefined && typeof failureReason !== "string")
  )
    throw new EncryptedTransactionError(
      "invalidResponse",
      "Invalid encrypted receipt metadata.",
    );
  if (decryptionStatus === "failed") {
    if (formatted.status !== "reverted" || !failureReason)
      throw new EncryptedTransactionError(
        "invalidResponse",
        "Invalid failed-decryption receipt.",
      );
    return {
      ...formatted,
      type: "encrypted",
      decryptionStatus,
      failureReason,
      status: "reverted",
    };
  }
  return { ...formatted, type: "encrypted", decryptionStatus, failureReason };
}

/** Use with viem's defineChain to retain ETX types in ordinary query actions. */
export const encryptedFormatters = {
  transaction: { type: "transaction", exclude: [], format: transaction },
  transactionReceipt: {
    type: "transactionReceipt",
    exclude: [],
    format: receipt,
  },
  block: {
    type: "block",
    exclude: [],
    format(
      rpc: Omit<RpcBlock, "transactions"> & {
        transactions: (
          | RpcTransaction
          | RpcEncryptedTransaction
          | `0x${string}`
        )[];
      },
    ) {
      return {
        ...formatBlock({ ...rpc, transactions: [] }),
        transactions: rpc.transactions.map((value) =>
          typeof value === "string" ? value : transaction(value),
        ),
      };
    },
  },
} as const;
