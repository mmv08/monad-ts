import { expect, test } from "bun:test";
import { createTestKey } from "@monad-crypto/btx/testing";
import {
  BaseError,
  bytesToHex,
  createWalletClient,
  custom,
  type Hex,
  InvalidChainIdError,
  keccak256,
  publicActions,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  EncryptedTransactionError,
  sendEncryptedTransaction,
} from "../../src/encrypted/index.js";
import { chain } from "./mock.js";

const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const encryptionKey = bytesToHex(
  createTestKey({ trapdoor: 42n }).encryptionKey,
);
const request = {
  to: "0x1111111111111111111111111111111111111111",
  gas: 21_000n,
  nonce: 0,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
} as const;

test.each([
  ["transient", -32005, 3],
  ["deterministic", -32601, 1],
] as const)("%s read errors override transport retries", async (_, code, expectedCalls) => {
  let calls = 0;
  const wallet = createWalletClient({
    account,
    chain,
    transport: custom(
      {
        request: async () => {
          calls++;
          throw Object.assign(new Error("Read failed"), { code });
        },
      },
      { retryCount: 5, retryDelay: 1 },
    ),
  });
  await expect(sendEncryptedTransaction(wallet, request)).rejects.toMatchObject(
    { code },
  );
  expect(calls).toBe(expectedCalls);
});

test("transient reads can recover within the retry budget", async () => {
  let calls = 0;
  const wallet = createWalletClient({
    account,
    transport: custom(
      {
        request: async ({ method }) => {
          expect(method).toBe("eth_chainId");
          if (++calls < 3)
            throw Object.assign(new Error("Rate limited"), { code: -32005 });
          return "0x0";
        },
      },
      { retryCount: 5, retryDelay: 1 },
    ),
  });
  // A decoded chain error proves the third response reached the action.
  await expect(
    sendEncryptedTransaction(wallet, request),
  ).rejects.toBeInstanceOf(InvalidChainIdError);
  expect(calls).toBe(3);
});

test("fee reads on an extended client use the bounded reader", async () => {
  let calls = 0;
  const wallet = createWalletClient({
    account,
    chain,
    transport: custom(
      {
        request: async ({ method }) => {
          if (method === "eth_chainId") return "0x539";
          expect(method).toBe("eth_getBlockByNumber");
          calls++;
          throw Object.assign(new Error("Rate limited"), { code: -32005 });
        },
      },
      { retryCount: 5, retryDelay: 1 },
    ),
  }).extend(publicActions);
  await expect(
    sendEncryptedTransaction(wallet, {
      ...request,
      maxFeePerGas: undefined,
    }),
  ).rejects.toMatchObject({ code: -32005 });
  expect(calls).toBe(3);
});

test.each([
  ["poolFull", "rejected"],
  ["expiredEpoch", "expiredEpoch"],
  ["futureBackendReason", "unknownOutcome"],
] as const)("submission reason %s preserves its cause and submits once", async (reason, code) => {
  const original = Object.assign(new Error("Backend refused this request"), {
    code: -32000,
    data: { reason, detail: "test detail" },
  });
  let sends = 0;
  let sent: Hex | undefined;
  const wallet = createWalletClient({
    account,
    chain,
    transport: custom(
      {
        request: async ({ method, params }) => {
          if (method === "eth_chainId") return "0x539";
          if (method === "eth_sendRawTransaction") {
            sends++;
            sent = params[0];
            throw original;
          }
          throw new Error(`Unexpected RPC: ${method}`);
        },
      },
      { retryCount: 5, retryDelay: 1 },
    ),
  });
  // Error classification needs no mock admission or decryption.
  const error = await sendEncryptedTransaction(wallet, request, {
    contextProvider: async () => ({
      epoch: 1n,
      available: true,
      encryptionKey,
    }),
  }).catch((error: unknown) => error);
  expect(error).toBeInstanceOf(EncryptedTransactionError);
  if (!(error instanceof EncryptedTransactionError))
    throw new Error("Expected ETX error");
  expect(error.code).toBe(code);
  expect(sent).toBeDefined();
  if (!sent) throw new Error("Expected submitted bytes");
  expect(error.hash).toBe(keccak256(sent));
  expect(error.cause).toBeInstanceOf(BaseError);
  if (!(error.cause instanceof BaseError))
    throw new Error("Expected viem cause");
  expect(error.cause.walk()).toBe(original);
  expect(error.cause.walk()).toMatchObject({
    code: -32000,
    message: "Backend refused this request",
    data: { reason, detail: "test detail" },
  });
  expect(sends).toBe(1);
});
