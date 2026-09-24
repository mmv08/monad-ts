import { admitCiphertext } from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";
import * as Rlp from "ox/Rlp";
import { noble as secp256k1 } from "ox/Secp256k1";
import {
  type AccessList,
  type Address,
  bytesToHex,
  custom,
  defineChain,
  fromRlp,
  type Hex,
  hexToBytes,
  keccak256,
  type Signature,
  toHex,
} from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  associatedData,
  conceal,
  type Envelope,
  hex,
  MAX_TRANSACTION_BYTES,
  type Payload,
  selectedFields,
  serializeEnvelope,
  uint,
} from "../../src/encrypted/codec.js";
import { assertInput } from "../../src/encrypted/errors.js";
import { encryptedFormatters } from "../../src/encrypted/index.js";

export const chain = defineChain({
  id: 1337,
  name: "ETX mock (no EVM execution)",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1:8545"] } },
  formatters: encryptedFormatters,
  supportsTransactionReplacementDetection: false,
});

const zeroHash = `0x${"00".repeat(32)}` as const;
const bloom = `0x${"00".repeat(256)}` as const;
type Entry = {
  raw: Hex;
  envelope: Envelope;
  signature: ReturnType<typeof parseEnvelope>["signature"];
  sender: Hex;
  ad: Hex;
  status: "pending" | "succeeded" | "failed";
  payload?: Payload;
  block?: bigint;
  failureReason?: string;
};

export function rpcError(reason: string) {
  return Object.assign(new Error("ETX rejected"), {
    code: -32000,
    data: { reason },
  });
}

// Received-byte decoding belongs to this test backend, not the sender library.
type RlpValue = Hex | readonly RlpValue[];

function list(value: RlpValue, length?: number): readonly RlpValue[] {
  assertInput(
    Array.isArray(value) && (length === undefined || value.length === length),
    "Invalid RLP list.",
  );
  return value;
}

function bytes(value: RlpValue): Hex {
  assertInput(typeof value === "string", "Expected RLP bytes.");
  return value;
}

function decodeInteger(value: RlpValue, bits: number): bigint {
  const raw = bytes(value);
  assertInput(
    raw === "0x" || !raw.startsWith("0x00"),
    "Noncanonical RLP integer.",
  );
  const result = raw === "0x" ? 0n : BigInt(raw);
  uint(result, bits);
  return result;
}

function decodeTo(value: RlpValue): Address | null {
  const raw = bytes(value);
  if (raw === "0x") return null;
  hex(raw, 20);
  return raw;
}

function decodeAccessList(value: RlpValue): AccessList {
  return list(value).map((entry) => {
    const [address, keys] = list(entry, 2);
    const decodedAddress = bytes(address);
    hex(decodedAddress, 20);
    return {
      address: decodedAddress,
      storageKeys: list(keys).map((key) => {
        const decodedKey = bytes(key);
        hex(decodedKey, 32);
        return decodedKey;
      }),
    };
  });
}

function decodeList(raw: Hex): readonly RlpValue[] {
  assertInput(
    raw.length / 2 - 1 <= MAX_TRANSACTION_BYTES,
    "Transaction exceeds the reference size limit.",
  );
  // Viem bounds recursion and rejects trailing bytes and list-boundary overruns.
  const result = list(fromRlp(raw));
  assertInput(
    Rlp.fromHex(result).toLowerCase() === raw.toLowerCase(),
    "Noncanonical RLP encoding.",
  );
  return result;
}

export function decodePayload(raw: Hex, envelope: Envelope): Payload {
  const values = decodeList(raw);
  const selection = selectedFields(envelope.encryptedFields);
  assertInput(
    values.length === selection.length,
    "Incorrect encrypted payload field count.",
  );
  const restored: Payload = {
    to: envelope.to,
    value: envelope.value,
    data: envelope.data,
    accessList: envelope.accessList,
  };
  selection.forEach((field, index) => {
    const value = values[index];
    if (field === "to") restored.to = decodeTo(value);
    else if (field === "value") restored.value = decodeInteger(value, 256);
    else if (field === "data") restored.data = bytes(value);
    else restored.accessList = decodeAccessList(value);
  });
  return restored;
}

export function parseEnvelope(raw: Hex): {
  envelope: Envelope;
  signature: Signature;
} {
  assertInput(
    raw.length / 2 - 1 <= MAX_TRANSACTION_BYTES,
    "Transaction exceeds the reference size limit.",
  );
  assertInput(raw.startsWith("0x08"), "Expected a type-8 transaction.");
  const values = list(decodeList(`0x${raw.slice(4)}`), 15);
  const envelope: Envelope = {
    type: "encrypted",
    chainId: decodeInteger(values[0], 64),
    nonce: decodeInteger(values[1], 64),
    maxPriorityFeePerGas: decodeInteger(values[2], 128),
    maxFeePerGas: decodeInteger(values[3], 128),
    gas: decodeInteger(values[4], 64),
    to: decodeTo(values[5]),
    value: decodeInteger(values[6], 256),
    data: bytes(values[7]),
    accessList: decodeAccessList(values[8]),
    epoch: decodeInteger(values[9], 64),
    encryptedFields: Number(decodeInteger(values[10], 8)),
    ciphertext: bytes(values[11]),
  };
  selectedFields(envelope.encryptedFields);
  assertInput(
    envelope.chainId > 0n &&
      envelope.maxPriorityFeePerGas <= envelope.maxFeePerGas,
    "Invalid chain ID or fee caps.",
  );
  const placeholders = conceal(envelope, envelope.encryptedFields);
  assertInput(
    envelope.to === placeholders.to &&
      envelope.value === placeholders.value &&
      envelope.data === placeholders.data &&
      (!(envelope.encryptedFields & 8) || envelope.accessList.length === 0),
    "Concealed fields must use their placeholders.",
  );
  const parity = decodeInteger(values[12], 8);
  assertInput(parity === 0n || parity === 1n, "Invalid signature parity.");
  const signature: Signature = {
    yParity: parity === 0n ? 0 : 1,
    r: toHex(decodeInteger(values[13], 256), { size: 32 }),
    s: toHex(decodeInteger(values[14], 256), { size: 32 }),
  };
  return { envelope, signature };
}

/** Test-only, single-trapdoor backend. Receipts are scripted, never EVM execution. */
export function createMock() {
  let entries = new Map<Hex, Entry>();
  let nonces = new Map<string, bigint>();
  let height = 0n;
  const mock = {
    key: createTestKey({ trapdoor: 42n }),
    epoch: 1n,
    available: true,
    timeoutAfterAccept: false,
    wrongHash: false,
    calls: [] as { method: string; params?: unknown }[],
    dropped: new Map<Hex, string>(),
    async request({
      method,
      params,
    }: {
      method: string;
      params?: unknown;
    }): Promise<unknown> {
      mock.calls.push({ method, params });
      const args = Array.isArray(params) ? params : [];
      switch (method) {
        case "eth_chainId":
          return toHex(chain.id);
        case "monad_getEncryptionContext":
          return {
            epoch: toHex(mock.epoch),
            available: mock.available,
            encryptionKey: mock.available
              ? bytesToHex(mock.key.encryptionKey)
              : null,
          };
        case "eth_getTransactionCount": {
          const address = String(args[0]).toLowerCase();
          let nonce = nonces.get(address) ?? 0n;
          if (args[1] === "pending")
            for (const entry of entries.values())
              if (
                entry.sender.toLowerCase() === address &&
                entry.status === "pending" &&
                entry.envelope.nonce >= nonce
              )
                nonce = entry.envelope.nonce + 1n;
          return toHex(nonce);
        }
        case "eth_maxPriorityFeePerGas":
          return "0x1";
        case "eth_gasPrice":
          return "0x3";
        case "eth_blockNumber":
          return toHex(height);
        case "eth_sendRawTransaction": {
          const raw = args[0];
          if (typeof raw !== "string" || !raw.startsWith("0x"))
            throw rpcError("invalidEnvelope");
          // The decoder validates these untrusted bytes, not the transport's type annotation.
          const signed = parseEnvelope(raw as Hex);
          const { envelope, signature } = signed;
          // Admission, not serialization, enforces scalar ranges and EIP-2.
          const curveSignature = new secp256k1.Signature(
            BigInt(signature.r),
            BigInt(signature.s),
          );
          if (curveSignature.hasHighS()) throw rpcError("invalidSignature");
          if (envelope.chainId !== BigInt(chain.id))
            throw rpcError("chainIdMismatch");
          if (!mock.available) throw rpcError("unavailable");
          if (envelope.epoch !== mock.epoch) throw rpcError("expiredEpoch");
          if (envelope.gas > 30_000_000n || envelope.maxFeePerGas < 1n)
            throw rpcError("publicValidationFailed");
          const publicKey = curveSignature
            .addRecoveryBit(signature.yParity ?? 0)
            .recoverPublicKey(keccak256(serializeEnvelope(envelope)).slice(2));
          const sender = publicKeyToAddress(`0x${publicKey.toHex(false)}`);
          if (envelope.nonce < (nonces.get(sender.toLowerCase()) ?? 0n))
            throw rpcError("nonceTooLow");
          // Fixture accounts have a fixed reserve; concealed value is not checked here.
          if (envelope.gas * envelope.maxFeePerGas > 10n ** 24n)
            throw rpcError("insufficientReserve");
          const ad = associatedData(envelope, sender);
          admitCiphertext(hexToBytes(envelope.ciphertext), hexToBytes(ad), {
            maxMaskedPayloadLength: MAX_TRANSACTION_BYTES,
          });
          const hash = keccak256(raw as Hex);
          if (!entries.has(hash))
            entries.set(hash, {
              raw: raw as Hex,
              envelope,
              signature,
              sender,
              ad,
              status: "pending",
            });
          if (mock.timeoutAfterAccept)
            throw new Error("Connection lost after acceptance");
          return mock.wrongHash ? zeroHash : hash;
        }
        case "eth_getTransactionByHash":
          return mock.transaction(args[0]);
        case "eth_getTransactionReceipt":
          return mock.receipt(args[0]);
        case "eth_getTransactionByBlockNumberAndIndex":
        case "eth_getTransactionByBlockHashAndIndex":
          return mock.transaction(
            [...entries].filter(([, entry]) => entry.block !== undefined)[
              Number(BigInt(args[1]))
            ]?.[0],
          );
        case "eth_getBlockByNumber":
        case "eth_getBlockByHash":
          return {
            hash: zeroHash,
            parentHash: zeroHash,
            number: toHex(height),
            timestamp: "0x1",
            baseFeePerGas: "0x1",
            gasLimit: "0x1c9c380",
            gasUsed: "0x0",
            miner: "0x0000000000000000000000000000000000000000",
            difficulty: "0x0",
            extraData: "0x",
            logsBloom: bloom,
            transactions: [...entries]
              .filter(([, entry]) => entry.block === height)
              .map(([hash]) => (args[1] ? mock.transaction(hash) : hash)),
          };
        default:
          throw Object.assign(new Error(`Unsupported mock method: ${method}`), {
            code: -32601,
          });
      }
    },
    transaction(hash: unknown) {
      const entry =
        typeof hash === "string" ? entries.get(hash as Hex) : undefined;
      if (!entry) return null;
      const { envelope: tx, signature, payload } = entry;
      return {
        hash,
        type: "0x8",
        from: entry.sender,
        to: payload ? payload.to : tx.to,
        value: toHex(payload?.value ?? tx.value),
        input: payload?.data ?? tx.data,
        accessList: payload?.accessList ?? tx.accessList,
        chainId: toHex(tx.chainId),
        nonce: toHex(tx.nonce),
        gas: toHex(tx.gas),
        maxPriorityFeePerGas: toHex(tx.maxPriorityFeePerGas),
        maxFeePerGas: toHex(tx.maxFeePerGas),
        epoch: toHex(tx.epoch),
        encryptedFields: toHex(tx.encryptedFields),
        ciphertext: tx.ciphertext,
        encrypted: true,
        concealedFields: selectedFields(tx.encryptedFields),
        decryptionStatus: entry.status,
        r: signature.r,
        s: signature.s,
        yParity: toHex(signature.yParity ?? 0),
        v: toHex(signature.yParity ?? 0),
        blockHash: entry.block === undefined ? null : zeroHash,
        blockNumber: entry.block === undefined ? null : toHex(entry.block),
        transactionIndex: entry.block === undefined ? null : "0x0",
      };
    },
    receipt(hash: unknown) {
      const entry =
        typeof hash === "string" ? entries.get(hash as Hex) : undefined;
      if (!entry || entry.block === undefined) return null;
      return {
        transactionHash: hash,
        transactionIndex: "0x0",
        blockHash: zeroHash,
        blockNumber: toHex(entry.block),
        from: entry.sender,
        to: entry.payload ? entry.payload.to : entry.envelope.to,
        type: "0x8",
        cumulativeGasUsed: toHex(entry.envelope.gas),
        gasUsed: toHex(entry.envelope.gas),
        effectiveGasPrice: "0x2",
        status: entry.failureReason ? "0x0" : "0x1",
        contractAddress: null,
        logs: [],
        logsBloom: bloom,
        decryptionStatus: entry.status,
        ...(entry.failureReason ? { failureReason: entry.failureReason } : {}),
      };
    },
    include(
      hash: Hex,
      executionFailure?: "executionValidationFailed" | "reverted" | "outOfGas",
    ) {
      const entry = entries.get(hash);
      if (!entry || entry.block !== undefined)
        throw new Error("Expected a pending transaction");
      if (!mock.available || entry.envelope.epoch !== mock.epoch) {
        entries.delete(hash);
        mock.dropped.set(hash, "expiredEpoch");
        return;
      }
      const decrypted = mock.key.decrypt(
        hexToBytes(entry.envelope.ciphertext),
        hexToBytes(entry.ad),
      );
      if (decrypted === null) {
        entry.status = "failed";
        entry.failureReason = "decryptionFailed";
      } else {
        try {
          entry.payload = decodePayload(
            bytesToHex(decrypted.plaintext),
            entry.envelope,
          );
          entry.status = "succeeded";
          entry.failureReason = executionFailure;
        } catch {
          entry.status = "failed";
          entry.failureReason = "malformedPayload";
        }
      }
      entry.block = ++height;
      nonces.set(entry.sender.toLowerCase(), entry.envelope.nonce + 1n);
    },
    raw(hash: Hex) {
      return entries.get(hash)?.raw;
    },
    snapshot() {
      const saved = {
        entries: structuredClone(entries),
        nonces: new Map(nonces),
        height,
        key: mock.key,
        epoch: mock.epoch,
        available: mock.available,
        dropped: new Map(mock.dropped),
      };
      return () => {
        entries = structuredClone(saved.entries);
        nonces = new Map(saved.nonces);
        height = saved.height;
        mock.key = saved.key;
        mock.epoch = saved.epoch;
        mock.available = saved.available;
        mock.dropped = new Map(saved.dropped);
      };
    },
  };
  return Object.assign(mock, { transport: custom(mock, { retryCount: 0 }) });
}
