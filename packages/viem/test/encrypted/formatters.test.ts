import { expect, test } from "bun:test";
import { createPublicClient, createWalletClient, custom } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sendEncryptedTransaction } from "../../src/encrypted/index.js";
import { chain, createMock } from "./mock.js";

test("malformed query metadata never becomes a typed valid result", async () => {
  const mock = createMock();
  const wallet = createWalletClient({
    chain,
    transport: mock.transport,
    account: privateKeyToAccount(`0x${"01".repeat(32)}`),
  });
  const hash = await sendEncryptedTransaction(wallet, {
    to: "0x1111111111111111111111111111111111111111",
    gas: 21_000n,
  });
  const rpc = mock.transaction(hash);
  const transactionClient = (overrides: Record<string, unknown>) =>
    createPublicClient({
      chain,
      transport: custom({ request: async () => ({ ...rpc, ...overrides }) }),
    });
  for (const overrides of [
    { encrypted: false },
    { concealedFields: [] },
    { concealedFields: ["to", "value", "nonce", "accessList"] },
    { to: "0x1111111111111111111111111111111111111111" },
    { value: "0x1" },
    { input: "0x1234" },
    { chainId: "0x20000000000000" },
    { epoch: "0x01" },
    { maxFeePerGas: "0x0" },
  ])
    await expect(
      transactionClient(overrides).getTransaction({ hash }),
    ).rejects.toThrow();
  expect(
    await transactionClient({ decryptionStatus: undefined }).getTransaction({
      hash,
    }),
  ).toMatchObject({ decryptionStatus: "unknown" });
  expect(
    await transactionClient({
      concealedFields: ["to", "value", "input", "accessList"],
    }).getTransaction({ hash }),
  ).toMatchObject({ concealedFields: ["to", "value", "data", "accessList"] });

  mock.include(hash);
  const receipt = mock.receipt(hash);
  const receiptClient = (overrides: Record<string, unknown>) =>
    createPublicClient({
      chain,
      transport: custom({
        request: async () => ({ ...receipt, ...overrides }),
      }),
    });
  for (const overrides of [
    { type: "0x9" },
    { status: "0x3" },
    { decryptionStatus: "pending" },
    { failureReason: 1 },
    { decryptionStatus: "failed", failureReason: "decryptionFailed" },
    { decryptionStatus: "failed", status: "0x0" },
    {
      decryptionStatus: "failed",
      status: "0x0",
      failureReason: "decryptionFailed",
      contractAddress: "0x1111111111111111111111111111111111111111",
    },
  ])
    await expect(
      receiptClient(overrides).getTransactionReceipt({ hash }),
    ).rejects.toThrow();
  expect(
    await receiptClient({ decryptionStatus: undefined }).getTransactionReceipt({
      hash,
    }),
  ).toMatchObject({ decryptionStatus: "unknown" });
});
