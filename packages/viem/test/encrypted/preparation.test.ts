import { expect, spyOn, test } from "bun:test";
import { CIPHERTEXT_OVERHEAD } from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";
import { bytesToHex, createWalletClient, nonceManager } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { MAX_TRANSACTION_BYTES } from "../../src/encrypted/codec.js";
import { parseContext } from "../../src/encrypted/context.js";
import {
  encryptedWalletActions,
  sendEncryptedTransaction,
} from "../../src/encrypted/index.js";
import { chain, createMock } from "./mock.js";

const to = "0x1111111111111111111111111111111111111111";
const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const request = {
  to,
  gas: 21_000n,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
} as const;

test("context validates shape and legacy numeric epochs", () => {
  const key = bytesToHex(createTestKey({ trapdoor: 42n }).encryptionKey);
  expect(
    parseContext({ available: true, epoch: 1, encryptionKey: key }).epoch,
  ).toBe(1n);
  for (const value of [
    null,
    {},
    { available: true, epoch: Number.MAX_SAFE_INTEGER + 1, encryptionKey: key },
    { available: true, epoch: "0x01", encryptionKey: key },
    { available: false, epoch: 1n, encryptionKey: key },
    { available: true, epoch: 1n, encryptionKey: "0x" },
  ])
    expect(() => parseContext(value)).toThrow();
});

test("managed nonces, overrides and viem's trusted local-signer convention", async () => {
  const mock = createMock();
  const managed = privateKeyToAccount(`0x${"02".repeat(32)}`, { nonceManager });
  const wallet = createWalletClient({
    chain,
    account: managed,
    transport: mock.transport,
  }).extend(encryptedWalletActions());
  const hashes = await Promise.all([
    wallet.sendEncryptedTransaction(request),
    wallet.sendEncryptedTransaction(request),
  ]);
  expect(hashes.map((hash) => mock.transaction(hash)?.nonce).sort()).toEqual([
    "0x0",
    "0x1",
  ]);
  const hash = await wallet.sendEncryptedTransaction({
    ...request,
    account,
    nonce: 10,
  });
  expect(mock.transaction(hash)?.nonce).toBe("0xa");
  const raw = mock.raw(hash);
  if (!raw) throw new Error("Expected signed bytes");
  const customSigner = { ...account, signTransaction: async () => raw };
  expect(
    await wallet.sendEncryptedTransaction({
      ...request,
      account: customSigner,
      nonce: 11,
    }),
  ).toBe(hash);
});

test("JSON-RPC account fails at runtime and malformed JS fields fail locally", async () => {
  const mock = createMock();
  const wallet = createWalletClient({
    chain,
    account: to,
    transport: mock.transport,
  }).extend(encryptedWalletActions());
  // @ts-expect-error Exercise an untyped JavaScript consumer's unsupported signer.
  await expect(wallet.sendEncryptedTransaction(request)).rejects.toMatchObject({
    code: "unsupportedSigner",
  });
  const local = createWalletClient({
    chain,
    account,
    transport: mock.transport,
  }).extend(encryptedWalletActions());
  await expect(
    // @ts-expect-error Exercise a wider JavaScript request with unsupported fields.
    local.sendEncryptedTransaction({ ...request, gasPrice: 1n }),
  ).rejects.toThrow();
  await expect(
    // @ts-expect-error Missing recipient must never imply contract creation.
    local.sendEncryptedTransaction({ gas: 21_000n }),
  ).rejects.toThrow();
  expect(mock.calls).toHaveLength(0);
});

test.each([
  ["negative gas", { gas: -1n }, { name: "IntegerOutOfRangeError" }],
  ["overflowing gas", { gas: 1n << 64n }, { name: "IntegerOutOfRangeError" }],
  ["undersized padding", { paddedLength: 0 }, { code: "InvalidLength" }],
  [
    "storage key width",
    { accessList: [{ address: to, storageKeys: ["0x01"] }] },
    { name: "InvalidStorageKeySizeError" },
  ],
  [
    "padding size cap",
    { paddedLength: MAX_TRANSACTION_BYTES },
    {
      code: "invalidInput",
      shortMessage: "Padding exceeds the reference size limit.",
    },
  ],
] as const)("%s fails before signing or submission", async (_, overrides, error) => {
  const mock = createMock();
  const signer = { ...account };
  const sign = spyOn(signer, "signTransaction");
  const wallet = createWalletClient({
    chain,
    account: signer,
    transport: mock.transport,
  });
  try {
    await expect(
      sendEncryptedTransaction(wallet, { ...request, ...overrides }),
    ).rejects.toMatchObject(error);
    expect(sign).not.toHaveBeenCalled();
    expect(
      mock.calls.filter(({ method }) => method === "eth_sendRawTransaction"),
    ).toHaveLength(0);
  } finally {
    sign.mockRestore();
  }
});

test("final size cap includes envelope and signature overhead", async () => {
  const mock = createMock();
  const signer = { ...account };
  const sign = spyOn(signer, "signTransaction");
  const wallet = createWalletClient({
    chain,
    account: signer,
    transport: mock.transport,
  });
  try {
    // Ciphertext alone fits exactly; the complete signed envelope does not.
    await expect(
      sendEncryptedTransaction(wallet, {
        ...request,
        paddedLength: MAX_TRANSACTION_BYTES - CIPHERTEXT_OVERHEAD - 4,
      }),
    ).rejects.toMatchObject({
      code: "invalidInput",
      shortMessage: "Transaction exceeds the reference size limit.",
    });
    expect(sign).toHaveBeenCalledTimes(1);
    expect(
      mock.calls.filter(({ method }) => method === "eth_sendRawTransaction"),
    ).toHaveLength(0);
  } finally {
    sign.mockRestore();
  }
});
