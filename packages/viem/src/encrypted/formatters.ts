import {
  type Block,
  defineBlock,
  defineTransaction,
  defineTransactionReceipt,
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

// As for viem's OP Stack deposits, viem's formatter runs first and keeps the
// keys it does not know, so this adds only the ETX conversions. Like viem's
// formatters, these convert fields and do not validate them.
const transaction = /*#__PURE__*/ defineTransaction({
  format(
    rpc: RpcTransaction | RpcEncryptedTransaction,
  ): Transaction | EncryptedTransaction {
    const etx = {} as EncryptedTransaction;
    if (rpc.type === "0x8") {
      etx.type = "encrypted";
      etx.epoch = BigInt(rpc.epoch);
      etx.encryptedFields = Number(rpc.encryptedFields);
      etx.concealedFields = selectedFields(etx.encryptedFields);
    }
    return etx;
  },
});

/** Use with viem's defineChain to retain ETX types in ordinary query actions. */
export const encryptedFormatters = {
  block: /*#__PURE__*/ defineBlock({
    format(
      rpc: Omit<RpcBlock, "transactions"> & {
        transactions: (RpcTransaction | RpcEncryptedTransaction | Hex)[];
      },
    ): Block {
      // Viem's block formatter calls its own transaction formatter.
      return {
        transactions: rpc.transactions.map((value) =>
          typeof value === "string" ? value : transaction.format(value),
        ),
      } as Block;
    },
  }),
  transaction,
  transactionReceipt: /*#__PURE__*/ defineTransactionReceipt({
    format(rpc: RpcReceipt): OrdinaryReceipt | EncryptedTransactionReceipt {
      return (
        rpc.type === "0x8" ? { type: "encrypted" } : {}
      ) as EncryptedTransactionReceipt;
    },
  }),
} as const;
