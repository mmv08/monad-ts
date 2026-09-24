import { expect, test } from "bun:test";
import { encrypt, serializeCiphertext } from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";
import {
  bytesToHex,
  createPublicClient,
  createWalletClient,
  custom,
  hexToBytes,
  keccak256,
  nonceManager,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  associatedData,
  conceal,
  type Envelope,
  hex,
  serializeTransaction,
} from "../../src/encrypted/codec.js";
import { parseContext } from "../../src/encrypted/context.js";
import {
  encryptedFormatters,
  encryptedWalletActions,
  sendEncryptedTransaction,
} from "../../src/encrypted/index.js";
import { buildVector } from "./fixtures.js";
import { chain, createMock } from "./mock.js";

const to = "0x1111111111111111111111111111111111111111";
const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const request = {
  to,
  gas: 21_000n,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
} as const;

test("committed wire, signing and binding regression vector", async () => {
  const stored: unknown = await Bun.file(
    new URL("./vector.json", import.meta.url),
  ).json();
  expect(stored).toEqual(await buildVector());
});

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

test("managed nonces, overrides and malformed signer output", async () => {
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
  const broken = { ...account, signTransaction: async () => raw };
  await expect(
    wallet.sendEncryptedTransaction({ ...request, account: broken, nonce: 11 }),
  ).rejects.toMatchObject({ code: "unsupportedSigner" });
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

test("proof-valid malformed payload is an included failure", async () => {
  const mock = createMock();
  const envelope: Envelope = {
    type: "encrypted",
    chainId: 1337n,
    nonce: 0n,
    gas: 21_000n,
    maxFeePerGas: 3n,
    maxPriorityFeePerGas: 1n,
    epoch: 1n,
    encryptedFields: 15,
    ciphertext: "0x",
    ...conceal({ to, value: 0n, data: "0x", accessList: [] }, 15),
  };
  const ad = associatedData(envelope, account.address);
  envelope.ciphertext = bytesToHex(
    serializeCiphertext(
      encrypt({
        plaintext: hexToBytes("0xc0"),
        associatedData: hexToBytes(ad),
        encryptionKey: mock.key.encryptionKey,
      }),
    ),
  );
  const raw = await account.signTransaction(envelope, {
    serializer: serializeTransaction,
  });
  await mock.request({ method: "eth_sendRawTransaction", params: [raw] });
  const hash = keccak256(raw);
  mock.include(hash);
  expect(mock.receipt(hash)).toMatchObject({
    status: "0x0",
    decryptionStatus: "failed",
    failureReason: "malformedPayload",
  });
});

test("ordinary serialization and formatting still work", async () => {
  const raw = await account.signTransaction(
    {
      type: "eip1559",
      chainId: 1337,
      nonce: 0,
      to,
      gas: 21_000n,
      maxFeePerGas: 3n,
      maxPriorityFeePerGas: 1n,
    },
    { serializer: serializeTransaction },
  );
  expect(raw.startsWith("0x02")).toBe(true);
  const mock = createMock();
  const wallet = createWalletClient({
    account,
    chain,
    transport: mock.transport,
  });
  const hash = await sendEncryptedTransaction(wallet, request);
  const rpc = mock.transaction(hash);
  if (!rpc) throw new Error("Expected transaction");
  // Test RPC responses enter as unknown data at runtime; validate the shared hex fields first.
  hex(rpc.hash, 32);
  const ordinary = {
    ...rpc,
    hash: rpc.hash,
    transactionIndex: null,
    type: "0x2" as const,
  };
  expect(encryptedFormatters.transaction.format(ordinary).type).toBe("eip1559");
  mock.include(hash);
  const response = mock.receipt(hash);
  if (!response) throw new Error("Expected receipt");
  hex(response.transactionHash, 32);
  for (const type of ["0x0", "0x1", "0x2", "0x3", "0x4"] as const) {
    const client = createPublicClient({
      chain,
      transport: custom({ request: async () => ({ ...response, type }) }),
    });
    expect((await client.getTransactionReceipt({ hash })).type).not.toBe(
      "encrypted",
    );
  }
  const client = createPublicClient({
    chain,
    transport: custom({
      request: async () => ({ ...rpc, decryptionStatus: "invalid" }),
    }),
  });
  await expect(client.getTransaction({ hash })).rejects.toThrow();
});
