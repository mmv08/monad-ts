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
test("ordinary transaction and receipt fields use viem formatting", () => {
  expect(encryptedFormatters.transaction.format(rpc)).toEqual(
    formatTransaction(rpc),
  );
  for (const type of ["0x0", "0x1", "0x2", "0x3", "0x4", "0x9"] as const) {
    const receipt = { ...rpcReceipt, type };
    expect(encryptedFormatters.transactionReceipt.format(receipt)).toEqual({
      ...formatTransactionReceipt(receipt),
      decryptionStatus: undefined,
      failureReason: undefined,
    });
  }
});

test("ETX transaction metadata failures report invalidResponse", () => {
  const transaction = (overrides: Record<string, unknown>) =>
    encryptedFormatters.transaction.format({
      ...rpc,
      type: "0x8",
      epoch: "0x1",
      encryptedFields: "0xf",
      ciphertext: "0x",
      decryptionStatus: "pending",
      ...overrides,
    });
  for (const overrides of [
    { encrypted: false },
    { concealedFields: [] },
    { concealedFields: ["to", "value", "nonce", "accessList"] },
    { epoch: "0x01" },
    { encryptedFields: "0x0" },
    { ciphertext: "0xgg" },
    { decryptionStatus: "invalid" },
  ])
    expect(() => transaction(overrides)).toThrow(
      expect.objectContaining({ code: "invalidResponse" }),
    );
  expect(transaction({ decryptionStatus: undefined })).toMatchObject({
    decryptionStatus: "unknown",
  });
  expect(
    transaction({
      concealedFields: ["to", "value", "input", "accessList"],
    }),
  ).toMatchObject({ concealedFields: ["to", "value", "data", "accessList"] });
  // Ordinary fields are formatted, not checked against admission rules.
  expect(
    transaction({
      value: "0x1",
      maxFeePerGas: "0x0",
    }),
  ).toMatchObject({ value: 1n, maxFeePerGas: 0n });
});

test("ETX receipt metadata keeps decryption and execution status separate", () => {
  const receipt = (overrides: Record<string, unknown>) =>
    encryptedFormatters.transactionReceipt.format({
      ...rpcReceipt,
      type: "0x8",
      decryptionStatus: "succeeded",
      ...overrides,
    });
  for (const overrides of [
    { decryptionStatus: "pending" },
    { failureReason: 1 },
    { decryptionStatus: "failed", failureReason: "decryptionFailed" },
    { decryptionStatus: "failed", status: "0x0" },
  ])
    expect(() => receipt(overrides)).toThrow(
      expect.objectContaining({ code: "invalidResponse" }),
    );
  expect(receipt({ decryptionStatus: undefined })).toMatchObject({
    decryptionStatus: "unknown",
  });
});
