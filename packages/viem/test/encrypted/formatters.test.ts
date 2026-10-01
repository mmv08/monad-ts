import { expect, test } from "bun:test";
import {
  formatTransaction,
  formatTransactionReceipt,
  type RpcTransactionReceipt,
  zeroAddress,
} from "viem";
import { encryptedFormatters } from "../../src/encrypted/index.js";

const hash = `0x${"00".repeat(32)}` as const;
const rpc = {
  hash,
  type: "0x2" as const,
  from: zeroAddress,
  to: zeroAddress,
  value: "0x0" as const,
  input: "0x" as const,
  accessList: [],
  chainId: "0x539" as const,
  nonce: "0x0" as const,
  gas: "0x5208" as const,
  maxFeePerGas: "0x3" as const,
  maxPriorityFeePerGas: "0x1" as const,
  r: hash,
  s: hash,
  v: "0x0" as const,
  yParity: "0x0" as const,
  blockHash: null,
  blockNumber: null,
  transactionIndex: null,
};
const rpcReceipt: RpcTransactionReceipt = {
  transactionHash: hash,
  transactionIndex: "0x0",
  blockHash: hash,
  blockNumber: "0x1",
  from: zeroAddress,
  to: zeroAddress,
  type: "0x2",
  cumulativeGasUsed: "0x5208",
  gasUsed: "0x5208",
  effectiveGasPrice: "0x2",
  status: "0x1",
  contractAddress: null,
  logs: [],
  logsBloom: `0x${"00".repeat(256)}`,
};

test("ordinary transactions and receipts get viem's own formatting", () => {
  expect(encryptedFormatters.transaction.format(rpc)).toEqual(
    formatTransaction(rpc),
  );
  expect(encryptedFormatters.transactionReceipt.format(rpcReceipt)).toEqual(
    formatTransactionReceipt(rpcReceipt),
  );
});
