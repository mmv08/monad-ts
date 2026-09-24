import {
  CIPHERTEXT_OVERHEAD,
  encrypt,
  paddedLengthFor,
  serializeCiphertext,
} from "@monad-crypto/btx";
import {
  type Account,
  BaseError,
  bytesToHex,
  type Chain,
  type Client,
  createClient,
  custom,
  hexToBytes,
  InvalidAddressError,
  isAddress,
  keccak256,
  type Transport,
} from "viem";
import {
  estimateFeesPerGas,
  getChainId,
  getTransactionCount,
  sendRawTransaction,
} from "viem/actions";
import {
  associatedData,
  conceal,
  type Envelope,
  encodePayload,
  MAX_TRANSACTION_BYTES,
  maskFor,
  type Payload,
  safeInteger,
  serializeTransaction,
} from "./codec.js";
import { parseContext } from "./context.js";
import { assertInput, EncryptedTransactionError } from "./errors.js";
import type {
  EncryptedWalletActionsOptions,
  SendEncryptedTransactionParameters,
  SendEncryptedTransactionReturnType,
} from "./types.js";

const forbidden = [
  "gasPrice",
  "blobs",
  "blobVersionedHashes",
  "maxFeePerBlobGas",
  "sidecars",
  "authorizationList",
  "type",
  "ciphertext",
  "epoch",
  "kzg",
  "from",
  "chain",
] as const;
const rejectionReasons = new Set([
  "expiredEpoch",
  "unavailable",
  "invalidEnvelope",
  "invalidCiphertext",
  "invalidProof",
  "invalidSignature",
  "chainIdMismatch",
  "publicValidationFailed",
  "nonceTooLow",
  "insufficientReserve",
  "replacementUnderpriced",
  "poolFull",
]);

/**
 * Encrypts and signs locally, then submits one type-8 transaction.
 * Requires gas; never estimates or sends plaintext to the RPC.
 * @returns The original signed transaction hash.
 */
export async function sendEncryptedTransaction<
  transport extends Transport,
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<transport, chain, account>,
  parameters: SendEncryptedTransactionParameters<account>,
  options: EncryptedWalletActionsOptions = {},
): Promise<SendEncryptedTransactionReturnType> {
  const signer = parameters.account ?? client.account;
  if (!signer || signer.type !== "local")
    throw new EncryptedTransactionError(
      "unsupportedSigner",
      "A local secp256k1 account is required.",
    );
  if (client.transport.type === "fallback")
    throw new EncryptedTransactionError(
      "unsupportedTransport",
      "Use a single-attempt wallet transport for encrypted submission.",
    );
  for (const field of forbidden)
    assertInput(
      parameters[field] === undefined,
      "Unsupported transaction field.",
    );
  // Required gas is a privacy boundary: never substitute remote estimation.
  assertInput(
    typeof parameters.gas === "bigint",
    "An explicit gas limit is required.",
  );
  assertInput(
    parameters.to !== null || parameters.data !== undefined,
    "Contract creation requires initcode.",
  );
  if (parameters.to !== null && !isAddress(parameters.to))
    throw new InvalidAddressError({ address: parameters.to });
  const payload: Payload = {
    to: parameters.to,
    value: parameters.value ?? 0n,
    data: parameters.data ?? "0x",
    accessList: parameters.accessList ?? [],
  };
  payload.accessList = payload.accessList.map(({ address, storageKeys }) => ({
    address,
    storageKeys: [...storageKeys],
  }));
  const encryptedFields = maskFor(parameters.encryptedFields);
  const plaintext = hexToBytes(encodePayload(payload, encryptedFields));
  const paddedLength =
    parameters.paddedLength ?? paddedLengthFor(plaintext.length);
  assertInput(
    paddedLength + CIPHERTEXT_OVERHEAD + 4 <= MAX_TRANSACTION_BYTES,
    "Padding exceeds the reference size limit.",
  );
  // Snapshot caller-owned options before awaiting any reads.
  const request = { ...parameters };
  const contextProvider = options.contextProvider;
  // Viem actions share this request function. One request layer owns the read retry budget.
  const reader = createClient({
    chain: client.chain,
    transport: custom(
      {
        request: (args) =>
          client.request<{ Parameters: unknown; ReturnType: unknown }>(args, {
            retryCount: 0,
          }),
      },
      { retryCount: 2 },
    ),
  });
  const chainId = await getChainId(reader);
  assertInput(
    chainId > 0 &&
      (client.chain === undefined || client.chain.id === chainId) &&
      (request.chainId === undefined || request.chainId === chainId),
    "Chain ID mismatch.",
  );
  // Viem 2.56.8 forwards request to its fee estimator, although the public action's
  // parameter type only exposes type/chain. Keep this request public-field-only.
  const feeParameters = {
    type: "eip1559" as const,
    chain: client.chain,
    request: {
      chainId,
      gas: request.gas,
      maxFeePerGas: request.maxFeePerGas,
      maxPriorityFeePerGas: request.maxPriorityFeePerGas,
    },
  };
  const fees =
    request.maxFeePerGas !== undefined &&
    request.maxPriorityFeePerGas !== undefined
      ? {
          maxFeePerGas: request.maxFeePerGas,
          maxPriorityFeePerGas: request.maxPriorityFeePerGas,
        }
      : await estimateFeesPerGas(reader, feeParameters);
  const maxFeePerGas = request.maxFeePerGas ?? fees.maxFeePerGas;
  const maxPriorityFeePerGas =
    request.maxPriorityFeePerGas ?? fees.maxPriorityFeePerGas;
  assertInput(
    maxPriorityFeePerGas <= maxFeePerGas,
    "Priority fee exceeds fee cap.",
  );
  // Resolve context before reserving a managed nonce, so unavailable keys do not consume one.
  const context = parseContext(
    contextProvider
      ? await contextProvider({ chainId, account: signer.address })
      : await reader.request<{
          Method: "monad_getEncryptionContext";
          Parameters: [];
          ReturnType: unknown;
        }>({ method: "monad_getEncryptionContext", params: [] }),
  );
  if (!context.available)
    throw new EncryptedTransactionError(
      "unavailable",
      "Encryption is unavailable for the active epoch.",
    );
  const nonce =
    request.nonce ??
    (signer.nonceManager
      ? await signer.nonceManager.consume({
          address: signer.address,
          chainId,
          client: reader,
        })
      : await getTransactionCount(reader, {
          address: signer.address,
          blockTag: "pending",
        }));
  safeInteger(nonce);
  const envelope: Envelope = {
    type: "encrypted",
    chainId: BigInt(chainId),
    nonce: BigInt(nonce),
    gas: request.gas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    ...conceal(payload, encryptedFields),
    epoch: context.epoch,
    encryptedFields,
    ciphertext: "0x",
  };
  const ad = associatedData(envelope, signer.address);
  envelope.ciphertext = bytesToHex(
    serializeCiphertext(
      encrypt({
        plaintext,
        encryptionKey: hexToBytes(context.encryptionKey),
        associatedData: hexToBytes(ad),
        paddedLength,
      }),
    ),
  );
  const serializedTransaction = await signer.signTransaction(envelope, {
    serializer: serializeTransaction,
  });
  // As in viem, a configured local signer is trusted to honor the serializer.
  assertInput(
    serializedTransaction.length / 2 - 1 <= MAX_TRANSACTION_BYTES,
    "Transaction exceeds the reference size limit.",
  );
  const hash = keccak256(serializedTransaction);
  let returnedHash: unknown;
  try {
    returnedHash = await sendRawTransaction(client, { serializedTransaction });
  } catch (cause) {
    // Only a structured backend rejection establishes rejection. Generic RPC errors may follow acceptance.
    let reason: unknown;
    const findReason = (error: unknown) => {
      if (
        error &&
        typeof error === "object" &&
        "data" in error &&
        error.data &&
        typeof error.data === "object" &&
        "reason" in error.data
      ) {
        reason = error.data.reason;
        return true;
      }
      return false;
    };
    if (cause instanceof BaseError) cause.walk(findReason);
    else findReason(cause);
    const code =
      typeof reason === "string" && rejectionReasons.has(reason)
        ? reason === "expiredEpoch"
          ? "expiredEpoch"
          : "rejected"
        : "unknownOutcome";
    throw new EncryptedTransactionError(
      code,
      code === "unknownOutcome"
        ? "Submission outcome is unknown; look up the original hash before taking further action."
        : "The backend rejected the encrypted transaction.",
      { hash, cause: cause instanceof Error ? cause : undefined },
    );
  }
  if (typeof returnedHash !== "string" || returnedHash.toLowerCase() !== hash)
    throw new EncryptedTransactionError(
      "unknownOutcome",
      "RPC returned a different transaction hash.",
      { hash },
    );
  return hash;
}
