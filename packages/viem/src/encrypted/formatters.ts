import {
  formatBlock,
  formatTransaction,
  formatTransactionReceipt,
  type Hex,
  type RpcBlock,
  type RpcTransaction,
  type RpcTransactionReceipt,
  type Transaction,
  type TransactionReceipt,
} from "viem";
import { selectedFields } from "./codec.js";
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
  epoch: Hex;
  encryptedFields: Hex;
  ciphertext: Hex;
  decryptionStatus?: DecryptionStatus;
};
// Receipt `type` is an open string in viem, so one receipt type covers both kinds.
type RpcReceipt = RpcTransactionReceipt & {
  decryptionStatus?: "succeeded" | "failed";
  failureReason?: string;
};
// For the same reason, ordinary receipts declare the ETX keys absent.
type OrdinaryReceipt = TransactionReceipt & {
  decryptionStatus?: undefined;
  failureReason?: undefined;
};

// Like viem's own formatters, these convert fields and do not validate them.
function transaction(
  rpc: RpcTransaction | RpcEncryptedTransaction,
): Transaction | EncryptedTransaction {
  if (rpc.type !== "0x8") return formatTransaction(rpc);
  // Viem returns the entire Transaction union even for a literal 0x2 input.
  const formatted = formatTransaction({ ...rpc, type: "0x2" }) as Extract<
    Transaction,
    { type: "eip1559" }
  >;
  const encryptedFields = Number(rpc.encryptedFields);
  return {
    ...formatted,
    type: "encrypted",
    typeHex: "0x8",
    epoch: BigInt(rpc.epoch),
    encryptedFields,
    ciphertext: rpc.ciphertext,
    concealedFields: selectedFields(encryptedFields),
    decryptionStatus: rpc.decryptionStatus,
  };
}

function receipt(
  rpc: RpcReceipt,
): OrdinaryReceipt | EncryptedTransactionReceipt {
  if (rpc.type !== "0x8") return formatTransactionReceipt(rpc);
  return {
    ...formatTransactionReceipt(rpc),
    type: "encrypted",
    decryptionStatus: rpc.decryptionStatus,
    failureReason: rpc.failureReason,
  };
}

/** Use with viem's defineChain to retain ETX types in ordinary query actions. */
export const encryptedFormatters = {
  // `exclude: []` gives each formatter the shape viem's defineFormatter returns.
  // Without a key beyond `type` and `format`, viem ignores these return types.
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
        transactions: (RpcTransaction | RpcEncryptedTransaction | Hex)[];
      },
    ) {
      // Viem's block formatter calls its own transaction formatter, so map full transactions here.
      return {
        ...formatBlock({ ...rpc, transactions: [] }),
        transactions: rpc.transactions.map((value) =>
          typeof value === "string" ? value : transaction(value),
        ),
      };
    },
  },
} as const;
