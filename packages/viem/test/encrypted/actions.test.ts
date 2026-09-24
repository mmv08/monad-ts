import { expect, test } from "bun:test";
import {
  bytesToHex,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  erc20Abi,
  type Hash,
  InvalidAddressError,
  MaxFeePerGasTooLowError,
  nonceManager,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
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

function sends(mock: ReturnType<typeof createMock>) {
  return mock.calls.filter(({ method }) => method === "eth_sendRawTransaction")
    .length;
}

async function sendError(send: Promise<unknown>) {
  const error = await send.catch((error: unknown) => error);
  if (!(error instanceof EncryptedTransactionError))
    throw new Error("Expected an EncryptedTransactionError");
  return error;
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
  const accessList = [
    { address: accessAddress, storageKeys: [storageKey] },
  ] as const;
  const hash = await wallet.sendEncryptedTransaction({
    ...request,
    data,
    accessList,
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
  // Every concealed field comes back, and the identity stays.
  const restored = await publicClient.getTransaction({ hash });
  expect(restored).toMatchObject({
    hash,
    to,
    value: request.value,
    input: data,
    accessList,
  });
  expect(restored.from.toLowerCase()).toBe(account.address.toLowerCase());
  expect(
    (await publicClient.getBlock({ includeTransactions: true })).transactions[0]
      ?.type,
  ).toBe("encrypted");
  expect(sends(mock)).toBe(1);
  // Preparation reads public state only and never sends the plaintext.
  const allowed = new Set([
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

test("unavailable encryption fails before the nonce, signing or sending", async () => {
  const { mock, wallet } = setup();
  mock.available = false;
  await expect(wallet.sendEncryptedTransaction(request)).rejects.toMatchObject({
    code: "unavailable",
  });
  expect(mock.calls.map(({ method }) => method)).not.toContain(
    "eth_getTransactionCount",
  );
  expect(sends(mock)).toBe(0);
});

test("a stale epoch is rejected, with a decorator's contextProvider as the default", async () => {
  const mock = createMock();
  mock.epoch = 2n;
  const wallet = createWalletClient({
    account,
    chain,
    transport: mock.transport,
  }).extend(
    encryptedWalletActions({
      contextProvider: async () => ({
        available: true,
        epoch: 1n,
        encryptionKey: bytesToHex(mock.key.encryptionKey),
      }),
    }),
  );
  const error = await sendError(wallet.sendEncryptedTransaction(request));
  expect(error.code).toBe("rejected");
  expect(error.walk()).toMatchObject({ data: { reason: "expiredEpoch" } });
});

test("failed submissions keep the hash and cause, and send once", async () => {
  // The transport retries by default; the action must still send once.
  const { mock, wallet } = setup();
  mock.timeoutAfterAccept = true;
  const uncertain = await sendError(wallet.sendEncryptedTransaction(request));
  expect(uncertain.code).toBe("unknownOutcome");
  expect(uncertain.walk()).toMatchObject({
    message: "Connection lost after acceptance",
  });
  // The mock accepted these bytes, so the reported hash finds them.
  expect(mock.transaction(uncertain.hash)).not.toBeNull();
  expect(sends(mock)).toBe(1);
  // A structured reason proves rejection: here a signer other than the
  // sender bound into the proof.
  const other = privateKeyToAccount(`0x${"02".repeat(32)}`);
  const rejecting = createMock();
  const rejected = await sendError(
    sendEncryptedTransaction(
      createWalletClient({ account, chain, transport: rejecting.transport }),
      {
        ...request,
        account: { ...account, signTransaction: other.signTransaction },
      },
    ),
  );
  expect(rejected.code).toBe("rejected");
  expect(rejected.hash).toMatch(/^0x[\da-f]{64}$/);
  expect(rejected.walk()).toMatchObject({ data: { reason: "invalidProof" } });
  expect(sends(rejecting)).toBe(1);
});

test("managed nonces: concurrent sends, explicit override, no gap after any failure", async () => {
  const mock = createMock();
  const wallet = createWalletClient({
    account: privateKeyToAccount(`0x${"02".repeat(32)}`, { nonceManager }),
    chain,
    transport: mock.transport,
  }).extend(encryptedWalletActions());
  const nonceOf = (hash: Hash) => mock.transaction(hash)?.nonce;
  const concurrent = await Promise.all([
    wallet.sendEncryptedTransaction(request),
    wallet.sendEncryptedTransaction(request),
  ]);
  expect(concurrent.map(nonceOf).sort()).toEqual(["0x0", "0x1"]);
  // BTX rejects this padding after the nonce is taken; the nonce goes back.
  await expect(
    wallet.sendEncryptedTransaction({ ...request, paddedLength: 0 }),
  ).rejects.toMatchObject({ code: "InvalidLength" });
  expect(nonceOf(await wallet.sendEncryptedTransaction(request))).toBe("0x2");
  // After an epoch change the backend rejects a stale context; a fresh send
  // reuses the rejected nonce.
  mock.epoch++;
  await expect(
    wallet.sendEncryptedTransaction({
      ...request,
      contextProvider: async () => ({
        available: true,
        epoch: 1n,
        encryptionKey: bytesToHex(mock.key.encryptionKey),
      }),
    }),
  ).rejects.toMatchObject({ code: "rejected" });
  expect(nonceOf(await wallet.sendEncryptedTransaction(request))).toBe("0x3");
  expect(
    nonceOf(await wallet.sendEncryptedTransaction({ ...request, nonce: 10 })),
  ).toBe("0xa");
});

test("requires a local account and a valid, explicit recipient", async () => {
  const { mock, wallet } = setup();
  const jsonRpc = createWalletClient({
    account: to,
    chain,
    transport: mock.transport,
  }).extend(encryptedWalletActions());
  // @ts-expect-error JavaScript callers can reach the action with a JSON-RPC account.
  await expect(jsonRpc.sendEncryptedTransaction(request)).rejects.toMatchObject(
    {
      code: "unsupportedSigner",
    },
  );
  await expect(
    // @ts-expect-error A missing recipient must never imply contract creation.
    wallet.sendEncryptedTransaction({ gas: 21_000n }),
  ).rejects.toBeInstanceOf(InvalidAddressError);
  await expect(
    wallet.sendEncryptedTransaction({
      ...request,
      to: "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf",
    }),
  ).rejects.toBeInstanceOf(InvalidAddressError);
  expect(mock.calls).toHaveLength(0);
});

test("fees follow viem: partial caps, fee hooks get the block and public fields only", async () => {
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
  let seen: { block?: unknown; request?: unknown } = {};
  const hooked = createWalletClient({
    account,
    transport: mock.transport,
    chain: {
      ...chain,
      fees: {
        estimateFeesPerGas: async ({ block, request }) => {
          seen = { block, request };
          return {
            maxFeePerGas: request?.maxFeePerGas ?? 20n,
            maxPriorityFeePerGas: 10n,
          };
        },
      },
    },
  });
  const hash = await sendEncryptedTransaction(hooked, {
    ...request,
    data: "0x1234",
    maxPriorityFeePerGas: 10n,
  });
  // As in viem, the hook gets the latest block. The request carries public
  // fields only: no recipient, value or calldata.
  expect(seen.block).toMatchObject({ baseFeePerGas: 1n });
  expect(seen.request).toEqual({
    chainId: chain.id,
    gas: request.gas,
    maxFeePerGas: undefined,
    maxPriorityFeePerGas: 10n,
  });
  expect(mock.transaction(hash)?.maxFeePerGas).toBe("0x14");
  await expect(
    sendEncryptedTransaction(hooked, { ...request, maxFeePerGas: 5n }),
  ).rejects.toBeInstanceOf(MaxFeePerGasTooLowError);
});

test("contract creation can stay public while its initcode is encrypted", async () => {
  const { mock, wallet } = setup();
  const hash = await wallet.sendEncryptedTransaction({
    to: null,
    data: "0x6000",
    gas: 100_000n,
    encryptedFields: ["data"],
  });
  expect(mock.transaction(hash)).toMatchObject({
    to: null,
    input: "0x",
    encryptedFields: "0x4",
  });
});
