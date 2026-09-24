import {
  formatBlock,
  formatTransaction,
  formatTransactionReceipt,
  type RpcBlock,
  type RpcTransaction,
  type RpcTransactionReceipt,
  type Transaction,
  type TransactionReceipt,
  zeroAddress,
} from "viem";
import { hex, payloadValues, safeInteger, selectedFields } from "./codec.js";
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
  const epoch = quantity(rpc.epoch, 64);
  const encryptedFields = Number(quantity(rpc.encryptedFields, 8));
  const concealedFields = selectedFields(encryptedFields);
  hex(rpc.ciphertext);
  hex(rpc.hash, 32);
  hex(rpc.from, 20);
  hex(rpc.r, 32);
  hex(rpc.s, 32);
  const chainId = quantity(rpc.chainId, 64);
  const nonce = quantity(rpc.nonce, 64);
  safeInteger(Number(chainId));
  safeInteger(Number(nonce));
  quantity(rpc.gas, 64);
  const maxFeePerGas = quantity(rpc.maxFeePerGas, 128);
  const priorityFee = quantity(rpc.maxPriorityFeePerGas, 128);
  if (priorityFee > maxFeePerGas || chainId === 0n)
    throw new EncryptedTransactionError(
      "invalidResponse",
      "Invalid public transaction fields.",
    );
  payloadValues({
    to: rpc.to,
    value: quantity(rpc.value, 256),
    data: rpc.input,
    accessList: rpc.accessList,
  });
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
  const formatted = formatTransaction({ ...rpc, type: "0x2" });
  // Narrow viem's ordinary union before replacing its discriminator.
  if (formatted.type !== "eip1559")
    throw new EncryptedTransactionError(
      "invalidResponse",
      "Invalid fee-market transaction.",
    );
  const decryptionStatus = status(rpc.decryptionStatus);
  if (decryptionStatus === "pending" || decryptionStatus === "failed") {
    if (
      (encryptedFields & 1 && formatted.to?.toLowerCase() !== zeroAddress) ||
      (encryptedFields & 2 && formatted.value !== 0n) ||
      (encryptedFields & 4 && formatted.input !== "0x") ||
      (encryptedFields & 8 && formatted.accessList?.length !== 0)
    )
      throw new EncryptedTransactionError(
        "invalidResponse",
        "Concealed fields are not placeholders.",
      );
  }
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
}

type OrdinaryReceipt = Omit<TransactionReceipt, "type"> & {
  type: Transaction["type"];
};

function receipt(
  rpc: RpcTransactionReceipt | RpcEncryptedReceipt,
): OrdinaryReceipt | EncryptedTransactionReceipt {
  if (rpc.type !== "0x8") {
    const formatted = formatTransactionReceipt(rpc);
    const type =
      formatted.type === "legacy"
        ? "legacy"
        : formatted.type === "eip2930"
          ? "eip2930"
          : formatted.type === "eip1559"
            ? "eip1559"
            : formatted.type === "eip4844"
              ? "eip4844"
              : formatted.type === "eip7702"
                ? "eip7702"
                : undefined;
    if (!type)
      throw new EncryptedTransactionError(
        "invalidResponse",
        "Unsupported receipt transaction type.",
      );
    return { ...formatted, type };
  }
  const formatted = formatTransactionReceipt({ ...rpc, type: "0x2" });
  if (formatted.status !== "success" && formatted.status !== "reverted")
    throw new EncryptedTransactionError(
      "invalidResponse",
      "Invalid receipt status.",
    );
  hex(rpc.transactionHash, 32);
  hex(rpc.blockHash, 32);
  quantity(rpc.blockNumber, 64);
  quantity(rpc.gasUsed, 64);
  quantity(rpc.effectiveGasPrice, 128);
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
    if (
      formatted.status !== "reverted" ||
      !failureReason ||
      formatted.logs.length ||
      formatted.contractAddress
    )
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
