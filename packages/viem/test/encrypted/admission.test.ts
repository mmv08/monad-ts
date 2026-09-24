import { expect, test } from "bun:test";
import { encrypt, serializeCiphertext } from "@monad-crypto/btx";
import { noble as secp256k1 } from "ox/Secp256k1";
import {
  bytesToHex,
  createWalletClient,
  hexToBytes,
  keccak256,
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
import { sendEncryptedTransaction } from "../../src/encrypted/index.js";
import { chain, createMock, parseEnvelope } from "./mock.js";

const to = "0x1111111111111111111111111111111111111111";
const account = privateKeyToAccount(`0x${"01".repeat(32)}`);
const request = {
  to,
  gas: 21_000n,
  maxFeePerGas: 3n,
  maxPriorityFeePerGas: 1n,
} as const;

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
