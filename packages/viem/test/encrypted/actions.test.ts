import { expect, test } from "bun:test";
import { createTestKey } from "@monad-crypto/btx/testing";
import {
  bytesToHex,
  createPublicClient,
  createWalletClient,
  custom,
  encodeFunctionData,
  erc20Abi,
  fallback,
  type Hash,
  type Hex,
  InvalidAddressError,
  zeroAddress,
} from "viem";
import { mnemonicToAccount, privateKeyToAccount } from "viem/accounts";
import {
  EncryptedTransactionError,
  encryptedWalletActions,
  sendEncryptedTransaction,
} from "../../src/encrypted/index.js";
import { chain, createMock } from "./mock.js";

const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const to = "0x1111111111111111111111111111111111111111";
const request = { to, value: 1n, gas: 100_000n } as const;

function setup() {
  const mock = createMock();
  const wallet = createWalletClient({
    account,
    chain,
    transport: mock.transport,
  }).extend(encryptedWalletActions());
  const publicClient = createPublicClient({
    chain,
    transport: mock.transport,
    pollingInterval: 5,
  });
  return { mock, wallet, publicClient };
}

test("send, pending query, decryption, full block and ordinary receipt polling", async () => {
  const { mock, wallet, publicClient } = setup();
  const data = encodeFunctionData({
    abi: erc20Abi,
    functionName: "transfer",
    args: [to, 100n],
  });
  const storageKey = `0x${"ab".repeat(32)}` as const;
  const accessAddress = "0x2222222222222222222222222222222222222222";
  const hash = await wallet.sendEncryptedTransaction({
    ...request,
    data,
    accessList: [{ address: accessAddress, storageKeys: [storageKey] }],
  });
  const preparationCalls = [...mock.calls];
  const pending = await publicClient.getTransaction({ hash });
  expect(pending.type).toBe("encrypted");
  if (pending.type !== "encrypted") throw new Error("Expected ETX");
  expect(pending.epoch).toBe(1n);
  expect(pending.input).toBe("0x");
  expect(pending.to).toBe(zeroAddress);
  expect(pending.decryptionStatus).toBe("pending");
  expect(mock.receipt(hash)).toBeNull();
  const waiting = publicClient.waitForTransactionReceipt({
    hash,
    retryCount: 2,
    timeout: 3000,
  });
  mock.include(hash);
  const receipt = await waiting;
  expect(receipt.status).toBe("success");
  if (receipt.type !== "encrypted") throw new Error("Expected ETX receipt");
  expect(receipt.decryptionStatus).toBe("succeeded");
  const restored = await publicClient.getTransaction({ hash });
  expect(restored.input).toBe(data);
  expect(restored.hash).toBe(hash);
  expect(restored.from.toLowerCase()).toBe(account.address.toLowerCase());
  expect(
    (await publicClient.getBlock({ includeTransactions: true })).transactions[0]
      ?.type,
  ).toBe("encrypted");
  const methods = preparationCalls.map((call) => call.method);
  expect(
    methods.filter((method) => method === "eth_sendRawTransaction"),
  ).toHaveLength(1);
  const allowed = new Set([
    "eth_chainId",
    "eth_getBlockByNumber",
    "eth_maxPriorityFeePerGas",
    "monad_getEncryptionContext",
    "eth_getTransactionCount",
    "eth_sendRawTransaction",
  ]);
  for (const call of preparationCalls) {
    expect(allowed.has(call.method)).toBe(true);
    for (const concealed of [to, data, accessAddress, storageKey])
      expect(JSON.stringify(call)).not.toContain(concealed.slice(2));
  }
});

test("unavailable context and invalid local input never submit", async () => {
  const { mock, wallet } = setup();
  mock.available = false;
  await expect(wallet.sendEncryptedTransaction(request)).rejects.toMatchObject({
    code: "unavailable",
  });
  mock.calls.length = 0;
  await expect(
    // @ts-expect-error An untyped caller must not trigger automatic estimation.
    wallet.sendEncryptedTransaction({ ...request, gas: undefined }),
  ).rejects.toMatchObject({ code: "invalidInput" });
  expect(mock.calls).toHaveLength(0);
});

test("wrong epoch rejects; accepted epoch expires before inclusion", async () => {
  const { mock, wallet, publicClient } = setup();
  const hash = await wallet.sendEncryptedTransaction(request);
  mock.epoch++;
  mock.include(hash);
  expect(mock.dropped.get(hash)).toBe("expiredEpoch");
  expect(mock.receipt(hash)).toBeNull();
  await expect(publicClient.getTransaction({ hash })).rejects.toThrow();
  await expect(
    sendEncryptedTransaction(wallet, request, {
      contextProvider: async () => ({
        available: true,
        epoch: 1n,
        encryptionKey: bytesToHex(mock.key.encryptionKey),
      }),
    }),
  ).rejects.toMatchObject({ code: "expiredEpoch" });
});

test("wrong valid key fails decryption, not admission", async () => {
  const { mock, wallet, publicClient } = setup();
  const other = createTestKey({ trapdoor: 43n });
  const hash = await sendEncryptedTransaction(wallet, request, {
    contextProvider: async () => ({
      available: true,
      epoch: 1n,
      encryptionKey: bytesToHex(other.encryptionKey),
    }),
  });
  mock.include(hash);
  const receipt = await publicClient.getTransactionReceipt({ hash });
  expect(receipt).toMatchObject({
    status: "reverted",
    decryptionStatus: "failed",
    failureReason: "decryptionFailed",
    gasUsed: request.gas,
  });
});

test("zero-valued payload succeeds and EVM failure stays separate", async () => {
  const { mock, wallet, publicClient } = setup();
  const hash = await wallet.sendEncryptedTransaction({
    to: zeroAddress,
    gas: 21_000n,
  });
  mock.include(hash, "reverted");
  expect(await publicClient.getTransactionReceipt({ hash })).toMatchObject({
    status: "reverted",
    decryptionStatus: "succeeded",
    failureReason: "reverted",
  });
});

test("unknown send outcome retains hash, never retries", async () => {
  for (const fault of ["timeoutAfterAccept", "wrongHash"] as const) {
    const { mock, wallet } = setup();
    mock[fault] = true;
    let hash: Hash | undefined;
    try {
      await wallet.sendEncryptedTransaction(request);
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptedTransactionError);
      if (!(error instanceof EncryptedTransactionError)) throw error;
      expect(error.code).toBe("unknownOutcome");
      hash = error.hash;
    }
    expect(hash).toBeDefined();
    expect(mock.transaction(hash)).not.toBeNull();
    expect(
      mock.calls.filter((call) => call.method === "eth_sendRawTransaction"),
    ).toHaveLength(1);
  }
});

test("fallback submission is rejected before sending", async () => {
  const mock = createMock();
  const wallet = createWalletClient({
    account,
    chain,
    transport: fallback([mock.transport, mock.transport]),
  }).extend(encryptedWalletActions());
  await expect(wallet.sendEncryptedTransaction(request)).rejects.toMatchObject({
    code: "unsupportedTransport",
  });
  expect(mock.calls).toHaveLength(0);
});

test("snapshot restores pending bytes, key context and outcomes", async () => {
  const { mock, wallet } = setup();
  const hash = await wallet.sendEncryptedTransaction(request);
  const raw = mock.raw(hash);
  const key = mock.key;
  const restore = mock.snapshot();
  mock.include(hash);
  mock.key = createTestKey({ trapdoor: 43n });
  mock.epoch = 2n;
  mock.available = false;
  restore();
  expect(mock.raw(hash)).toBe(raw);
  expect(mock.key).toBe(key);
  expect(mock.epoch).toBe(1n);
  expect(mock.available).toBe(true);
  expect(mock.receipt(hash)).toBeNull();
  expect(mock.transaction(hash)?.decryptionStatus).toBe("pending");
});

test("read retry budget is bounded", async () => {
  let calls = 0;
  const wallet = createWalletClient({
    account,
    chain,
    transport: custom(
      {
        request: async () => {
          calls++;
          throw Object.assign(new Error("Unavailable"), { code: -32005 });
        },
      },
      { retryCount: 0 },
    ),
  }).extend(encryptedWalletActions());
  await expect(wallet.sendEncryptedTransaction(request)).rejects.toThrow();
  expect(calls).toBe(3);
});

test("HD signer, exact padding, public subset and creation", async () => {
  const { mock, wallet } = setup();
  const hd = mnemonicToAccount(
    "test test test test test test test test test test test junk",
  );
  const hash = await wallet.sendEncryptedTransaction({
    account: hd,
    to: null,
    data: "0x6000",
    gas: 100_000n,
    encryptedFields: ["data"],
    paddedLength: 4, // RLP([0x6000]) is four bytes.
  });
  expect(mock.transaction(hash)?.to).toBeNull();
  mock.include(hash, "executionValidationFailed");
  expect(mock.receipt(hash)).toMatchObject({
    decryptionStatus: "succeeded",
    failureReason: "executionValidationFailed",
  });
});

test("input mutation during context lookup cannot change the signed intent", async () => {
  const { mock, wallet } = setup();
  const storageKeys: Hex[] = [`0x${"01".repeat(32)}`];
  const accessList = [{ address: to, storageKeys } as const];
  const expected = structuredClone(accessList);
  const hash = await sendEncryptedTransaction(
    wallet,
    { ...request, accessList, encryptedFields: ["data"] },
    {
      contextProvider: async () => {
        storageKeys[0] = `0x${"02".repeat(32)}`;
        accessList.length = 0;
        return {
          available: true,
          epoch: mock.epoch,
          encryptionKey: bytesToHex(mock.key.encryptionKey),
        };
      },
    },
  );
  expect(mock.transaction(hash)?.accessList).toEqual(expected);
});

test("fee and chain errors fail before submission", async () => {
  const { mock, wallet } = setup();
  await expect(
    wallet.sendEncryptedTransaction({
      ...request,
      maxFeePerGas: 1n,
      maxPriorityFeePerGas: 2n,
    }),
  ).rejects.toThrow();
  await expect(
    wallet.sendEncryptedTransaction({ ...request, chainId: 1 }),
  ).rejects.toThrow();
  expect(
    mock.calls.some(({ method }) => method === "eth_sendRawTransaction"),
  ).toBe(false);
});

test("recipient validation follows viem and absent forbidden fields are accepted", async () => {
  const { mock, wallet } = setup();
  await expect(
    wallet.sendEncryptedTransaction({
      ...request,
      to: "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf",
    }),
  ).rejects.toBeInstanceOf(InvalidAddressError);
  expect(mock.calls).toHaveLength(0);
  const hash = await wallet.sendEncryptedTransaction({
    ...request,
    gasPrice: undefined,
    type: undefined,
    chain: undefined,
  });
  expect(mock.transaction(hash)).not.toBeNull();
});

test("partial fee caps follow viem and fee hooks receive only public fields", async () => {
  const { mock, wallet } = setup();
  for (const [fees, expected] of [
    [
      { maxPriorityFeePerGas: 10n },
      { maxFeePerGas: "0xb", maxPriorityFeePerGas: "0xa" },
    ],
    [
      { maxFeePerGas: 10n },
      { maxFeePerGas: "0xa", maxPriorityFeePerGas: "0x1" },
    ],
  ] as const) {
    const hash = await wallet.sendEncryptedTransaction({ ...request, ...fees });
    expect(mock.transaction(hash)).toMatchObject(expected);
  }
  const hooked = createWalletClient({
    account,
    transport: mock.transport,
    chain: {
      ...chain,
      fees: {
        estimateFeesPerGas: async ({ request: publicRequest }) => {
          expect(publicRequest).toEqual({
            chainId: chain.id,
            gas: request.gas,
            maxFeePerGas: undefined,
            maxPriorityFeePerGas: 10n,
          });
          return { maxFeePerGas: 20n, maxPriorityFeePerGas: 10n };
        },
      },
    },
  });
  const hash = await sendEncryptedTransaction(hooked, {
    ...request,
    data: "0x1234",
    maxPriorityFeePerGas: 10n,
  });
  expect(mock.transaction(hash)?.maxFeePerGas).toBe("0x14");
});
