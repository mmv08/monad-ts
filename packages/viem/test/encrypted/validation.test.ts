import { expect, test } from "bun:test";
import { encrypt, serializeCiphertext } from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";
import { noble as secp256k1 } from "ox/Secp256k1";
import {
  bytesToHex,
  createWalletClient,
  hexToBytes,
  keccak256,
  nonceManager,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  associatedData,
  conceal,
  type Envelope,
  serializeEnvelope,
  serializeTransaction,
} from "../../src/encrypted/codec.js";
import { parseContext } from "../../src/encrypted/context.js";
import {
  encryptedWalletActions,
  sendEncryptedTransaction,
} from "../../src/encrypted/index.js";
import { buildVector } from "./fixtures.js";
import { chain, createMock, parseEnvelope } from "./mock.js";

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

test("ordinary serialization delegates to viem", async () => {
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
});

test("serialization accepts signature bytes; mock admission enforces secp256k1 and low-s", async () => {
  const mock = createMock();
  const wallet = createWalletClient({
    chain,
    account,
    transport: mock.transport,
  });
  const hash = await sendEncryptedTransaction(wallet, request);
  const raw = mock.raw(hash);
  if (!raw) throw new Error("Expected signed bytes");
  const { envelope, signature } = parseEnvelope(raw);
  const highS = secp256k1.CURVE.n - BigInt(signature.s);
  for (const invalidSignature of [
    { ...signature, r: toHex(0n, { size: 32 }) },
    { ...signature, r: toHex(secp256k1.CURVE.n, { size: 32 }) },
    { ...signature, s: toHex(0n, { size: 32 }) },
    {
      ...signature,
      s: toHex(highS, { size: 32 }),
      yParity: signature.yParity === 0 ? (1 as const) : (0 as const),
    },
  ]) {
    const encoded = serializeEnvelope(envelope, invalidSignature);
    expect(parseEnvelope(encoded).signature).toEqual(invalidSignature);
    await expect(
      mock.request({ method: "eth_sendRawTransaction", params: [encoded] }),
    ).rejects.toThrow();
  }
});

test("invalid gas, access lists, and padding never reach the signer or submission", async () => {
  const mock = createMock();
  let signingCalls = 0;
  const wallet = createWalletClient({
    chain,
    account: {
      ...account,
      signTransaction: async () => {
        signingCalls++;
        throw new Error("Unexpected signing");
      },
    },
    transport: mock.transport,
  });
  for (const parameters of [
    { ...request, gas: -1n },
    { ...request, gas: 1n << 64n },
    { ...request, paddedLength: -1 },
    { ...request, paddedLength: 1.5 },
    { ...request, paddedLength: 0 },
    {
      ...request,
      accessList: [{ address: to, storageKeys: ["0x01"] }] as const,
    },
  ])
    await expect(
      sendEncryptedTransaction(wallet, parameters),
    ).rejects.toThrow();
  expect(signingCalls).toBe(0);
  expect(
    mock.calls.some(({ method }) => method === "eth_sendRawTransaction"),
  ).toBe(false);
});
