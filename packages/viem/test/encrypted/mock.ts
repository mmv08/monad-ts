import { admitCiphertext } from "@monad-crypto/btx";
import { createTestKey } from "@monad-crypto/btx/testing";
import {
  type AccessList,
  type Address,
  bytesToHex,
  custom,
  defineChain,
  fromRlp,
  type Hex,
  hexToBigInt,
  hexToBytes,
  keccak256,
  pad,
  recoverAddress,
  type Signature,
  size,
  toHex,
} from "viem";
import {
  associatedData,
  type Envelope,
  type Payload,
  selectedFields,
  serializeEnvelope,
} from "../../src/encrypted/codec.js";
import { encryptedFormatters } from "../../src/encrypted/index.js";

export const chain = defineChain({
  id: 1337,
  name: "ETX mock (no EVM execution)",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: ["http://127.0.0.1:8545"] } },
  formatters: encryptedFormatters,
  supportsTransactionReplacementDetection: false,
});

// TODO(spec): the PDF leaves the total transaction limit to chain policy.
// This is the mock's own limit, not a Monad claim.
const MAX_TRANSACTION_BYTES = 128 * 1024;
const zeroHash = `0x${"00".repeat(32)}` as const;
const bloom = `0x${"00".repeat(256)}` as const;
type Entry = {
  envelope: Envelope;
  signature: Signature;
  sender: Address;
  ad: Hex;
  status: "pending" | "succeeded" | "failed";
  payload?: Payload;
  block?: bigint;
  failureReason?: string;
};

/** A rejection in the ETX RPC's shape: -32000 with a machine-readable reason. */
export function rpcError(reason: string) {
  return Object.assign(new Error("ETX rejected"), {
    code: -32000,
    data: { reason },
  });
}

// Received-byte decoding belongs to this test backend, not the sender library.
// Like viem's parseTransaction, it trusts the RLP shape; admission checks the rest.
const quantity = (value: Hex) => (value === "0x" ? 0n : hexToBigInt(value));
const recipient = (value: Hex) => (value === "0x" ? null : value);
const accessList = (value: unknown): AccessList =>
  (value as [Address, Hex[]][]).map(([address, storageKeys]) => ({
    address,
    storageKeys,
  }));

async function parseEnvelope(raw: Hex) {
  try {
    if (!raw.startsWith("0x08") || size(raw) > MAX_TRANSACTION_BYTES)
      throw new Error("Not a type-8 envelope");
    const [
      chainId,
      nonce,
      maxPriorityFeePerGas,
      maxFeePerGas,
      gas,
      to,
      value,
      data,
      list,
      epoch,
      mask,
      ciphertext,
      yParity,
      r,
      s,
    ] = fromRlp(`0x${raw.slice(4)}`) as Hex[];
    const envelope: Envelope = {
      type: "encrypted",
      chainId: Number(quantity(chainId)),
      nonce: Number(quantity(nonce)),
      maxPriorityFeePerGas: quantity(maxPriorityFeePerGas),
      maxFeePerGas: quantity(maxFeePerGas),
      gas: quantity(gas),
      to: recipient(to),
      value: quantity(value),
      data,
      accessList: accessList(list),
      epoch: quantity(epoch),
      encryptedFields: Number(quantity(mask)),
      ciphertext,
    };
    const signature = {
      r: pad(r),
      s: pad(s),
      yParity: yParity === "0x" ? 0 : 1,
    };
    const sender = await recoverAddress({
      hash: keccak256(serializeEnvelope(envelope)),
      signature,
    });
    return { envelope, signature, sender };
  } catch {
    throw rpcError("invalidEnvelope");
  }
}

function decodePayload(plaintext: Hex, envelope: Envelope): Payload {
  const values = fromRlp(plaintext) as Hex[];
  const payload: Payload = {
    to: envelope.to,
    value: envelope.value,
    data: envelope.data,
    accessList: envelope.accessList,
  };
  selectedFields(envelope.encryptedFields).forEach((field, index) => {
    const value = values[index];
    if (field === "to") payload.to = recipient(value);
    else if (field === "value") payload.value = quantity(value);
    else if (field === "data") payload.data = value;
    else payload.accessList = accessList(value);
  });
  return payload;
}

/** Test-only, single-trapdoor backend. Receipts are scripted, never EVM execution. */
export function createMock() {
  const entries = new Map<Hex, Entry>();
  const nonces = new Map<string, number>();
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
          let nonce = nonces.get(address) ?? 0;
          if (args[1] === "pending")
            for (const entry of entries.values())
              if (
                entry.sender.toLowerCase() === address &&
                entry.status === "pending" &&
                entry.envelope.nonce >= nonce
              )
                nonce = entry.envelope.nonce + 1;
          return toHex(nonce);
        }
        case "eth_maxPriorityFeePerGas":
          return "0x1";
        case "eth_blockNumber":
          return toHex(height);
        case "eth_sendRawTransaction": {
          const raw = args[0] as Hex;
          const { envelope, signature, sender } = await parseEnvelope(raw);
          if (envelope.chainId !== chain.id) throw rpcError("chainIdMismatch");
          if (!mock.available || envelope.epoch !== mock.epoch)
            throw rpcError("expiredEpoch");
          // The binding uses the recovered sender, so another signer fails the proof.
          const ad = associatedData(envelope, sender);
          try {
            admitCiphertext(hexToBytes(envelope.ciphertext), hexToBytes(ad));
          } catch {
            throw rpcError("invalidProof");
          }
          const hash = keccak256(raw);
          if (!entries.has(hash))
            entries.set(hash, {
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
        case "eth_getBlockByNumber":
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
        // The PDF requires responses to mark ETX and name the concealed fields.
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
    /** Mines a pending entry. `failureReason` scripts an execution failure, such as "reverted". */
    include(hash: Hex, failureReason?: string) {
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
      if (decrypted) {
        entry.payload = decodePayload(
          bytesToHex(decrypted.plaintext),
          entry.envelope,
        );
        entry.status = "succeeded";
        entry.failureReason = failureReason;
      } else {
        entry.status = "failed";
        entry.failureReason = "decryptionFailed";
      }
      entry.block = ++height;
      nonces.set(entry.sender.toLowerCase(), entry.envelope.nonce + 1);
    },
  };
  return Object.assign(mock, { transport: custom(mock, { retryCount: 0 }) });
}
